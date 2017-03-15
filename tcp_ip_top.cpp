//tcp_ip_top function

#include "ap_int.h"
#include "hls_stream.h"

typedef struct axis_word_t {
  ap_uint<32>   data;
  ap_uint<4>    keep;
  ap_uint<1>    last;
  axis_word_t() {}
  axis_word_t(ap_uint<32> data, ap_uint<4> keep, ap_uint<1> last)
            :data(data), keep(keep), last(last) {}
}

const ap_uint<48> local_mac_addr        = 0x0a0b01020304;
const ap_uint<48> broadcast_mac_addr    = 0xffffffffffff;
const ap_uint<32> broadcast_ip_addr     = 0xffffffff;

void tcp_ip_top(stream<axis_word_t> rx_data, stream<axis_word_t> tx_data) {
#pragma HLS interface ap_ctrl_none port=return
#pragma HLS data_pack
#pragma HLS interface axis port=rx_data
#pragma HLS interface axis port=tx_data

    rx_mac_decode(rx_data, rx_arp_data, rx_ip_data);
    rx_ip_decode(rx_ip_data, rx_icmp_data, rx_expired_data, rx_udp_data, dchp_ip_addr);
    arp_server(rx_arp_data, ip_query, ip_query_resp, tx_arp_data, dchp_ip_addr);
    icmp_handle(rx_icmp_data, rx_expired_data, rx_udp_unreachable, tx_icmp_data);
    udp_rx_handle(rx_udp_data, open_port, open_port_resp, release_port, rx_socket, rx_udp_data, rx_udp_unreachable);
    tx_ip_encode(tx_socket, tx_udp_data, tx_udp_len, tx_icmp_data, tx_ip_data, tx_ip_checksum, dchp_ip_addr);
    tx_mac_encode(tx_ip_data, tx_ip_checksum, tx_arp_data, ip_query, ip_query_resp, tx_data);
    udp_msg_mux(open_port, open_port_resp, release_port, rx_socket, rx_udp_data, tx_socket, tx_udp_data, tx_udp_len, 
                dchp_open_port, dchp_open_port_resp, dchp_release_port, dchp_rx_socket, dchp_rx_udp_data, dchp_tx_socket, dchp_tx_udp_data, dchp_tx_udp_len,
                ulb_open_port, ulb_open_port_resp, ulb_release_port, ulb_rx_socket, ulb_rx_udp_data, ulb_tx_socket, ulb_tx_udp_data, ulb_tx_udp_len);
    dchp_server(dchp_ip_addr, 
                dchp_open_port, dchp_open_port_resp, dchp_release_port, dchp_rx_socket, dchp_rx_udp_data, dchp_tx_socket, dchp_tx_udp_data, dchp_tx_udp_len);
    udp_loopback(ulb_open_port, ulb_open_port_resp, ulb_release_port, ulb_rx_socket, ulb_rx_udp_data, ulb_tx_socket, ulb_tx_udp_data, ulb_tx_udp_len, dchp_ip_addr);
    global_timer(tick_100ms);
}


void rx_mac_decode(stream<axis_word_t> rx_data, stream<axis_word_t> rx_arp_data, stream<axis_word_t> rx_ip_data) {
#pragma HLS inline off
#pragma HLS pipeline II=1 enable_flush

    static enum rmd_state_e {RMD_IDLE = 0, RMD_R1, RMD_R2, RMD_R3, RMD_R4, RMD_STREAM, RMD_RESIDUE} rmd_state = 0;
    static axis_word_t curr_word;
    static axis_word_t perv_word;
    static axis_word_t out_word = axis_word_t(0, 0xf, 0);

    switch(rmd_state) {
        case RMD_IDLE:
            if(!rx_data.empty()) {
                curr_word = rx_data.read();
                dst_mac_addr(47, 16) = byte_swap32(rx_data.data);
                rmd_state ++;
            }
            break;
        case RMD_R1:
            if(!rx_data.empty()) {
                curr_word = rx_data.read();
                dst_mac_addr(15, 0) = byte_swap16(rx_data.data(15, 0));
                rmd_state ++;
            }
            break;
        case RMD_R2:
            if(!rx_data.empty()) {
                curr_word = rx_data.read();
                rmd_state ++;
            }
            break;
        case RMD_R3:
            if(!rx_data.empty()) {
                curr_word = rx_data.read();
                prev_word = curr_word;
                eth_type = byte_swap16(curr_word.data(15, 0));
                rmd_state ++;
            }
            break;
        case RMD_R4:
            if(!rx_data.empty()) {
                curr_word = rx_data.read();
                out_word.data(15, 0) = prev_word.data(31, 16);
                out_word.data(31, 16) = curr_word.data(15, 0);
                if(dst_mac_addr == local_mac_addr || dst_mac_addr == broadcast_mac_addr) {
                    if(eth_type == ETH_TYPE_ARP)
                        rx_arp_data.write(out_word);
                    else if(eth_type == ETH_TYPE_IP)
                        rx_ip_data.write(out_word);
                }
                prev_word = curr_word;
                rmd_state ++;
            }
            break;
        case RMD_STREAM:
            if(!rx_data.empty()) {
                curr_word = rx_data.read();
                out_word.data(15, 0) = prev_word.data(31, 16);
                out_word.data(31, 16) = curr_word.data(15, 0);
                if(keep_count(curr_word.keep) < 3 && curr_word.last == 1) {
                    out_word.keep(3, 2) = curr_word.keep(1, 0);
                    out_word.last = 1;
                    rdm_state = RMD_IDLE;
                } else if(curr_word.last == 1) {
                    rdm_state ++;
                }
                if(eth_type == ETH_TYPE_ARP) 
                    rx_arp_data.write(out_word);
                else if(eth_type == ETH_TYPE_IP)
                    rx_ip_data.write(out_word);
                prev_word = curr_word;
            }
            break;
        case RMD_RESIDUE:
            out_word.data(15, 0) = prev_word.data(31, 16);
            out_word.data(31, 16) = 0;
            out_word.keep(1, 0) = prev_word.keep(3, 2);
            out_word.keep(3, 2) = 0;
            out_word.last = 1;
            rdm_state = RMD_IDLE;
            if(eth_type == ETH_TYPE_ARP)
                rx_arp_data.write(out_word);
            else if(eth_type == ETH_TYPE_IP) 
                rx_ip_data.write(out_word);
            break;
    }
}



void rx_ip_decode(stream<axis_word_t> rx_ip_data, stream<axis_word_t> rx_icmp_data, stream<axis_word_t> rx_expired_data, stream<axis_word_t> rx_udp_data, ap_uint<32> dchp_ip_addr) {
#pragma HLS inline off
#pragma HLS interface ap_stable port=dchp_ip_addr
#pragma HLS pipeline II=1 enable_flush
    static enum rid_state_e {RID_IDLE = 0, RID_R1, RID_R2, RID_R3, RID_R4, RID_SKIP, RID_STREAM, RID_KEEP, RID_RESIDUE} rid_state = 0;
    static ap_uint<4> ihl;
    static ap_uint<4> version;
    static ap_uint<16> total_length;
    static ap_uint<17> calc_checksum;
    static ap_uint<3> flags;
    static ap_uint<13> offset;
    static ap_uint<8> ttl;
    static ap_uint<8> protocol;
    static ap_uint<16> ip_checksum;
    static ap_uint<32> dst_ip_addr;
    static axis_word_t curr_word;
    static axis_word_t prev_word;

    switch(rid_state) {
        case RID_IDLE:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                ihl = curr_word.data(3, 0);
                version = curr_word.data(7, 4);
                total_length = byte_swap16(curr_word.data(31, 16));
                calc_checksum = curr_word.data(31, 16) + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                ihl --;
                rid_state ++;
            }
            break;
        case RID_R1:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                flags = curr_word.data(23, 21);
                offset(12, 8) = curr_word.data(20, 16);
                offset(7, 0) = curr_word.data(31, 24);
                calc_checksum = curr_word.data(31, 16) + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                ihl --;
                rid_state ++;
            }
            break;
        case RID_R2:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                ttl = curr_word.data(7, 0);
                protocol = curr_word.data(15, 8);
                ip_checksum = byte_swap16(curr_word.data(31, 16));
                calc_checksum = curr_word.data(31, 16) + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                ihl --;
                rid_state ++;
            }
            break;
        case RID_R3:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                rx_udp_data.write(curr_word.data);
                calc_checksum = curr_word.data(31, 16) + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                ihl --;
                rid_state ++;
            }
            break;
        case RID_R4:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                dst_ip_addr = byte_swap32(curr_word.data);
                rx_udp_data.write(curr_word.data);
                calc_checksum = curr_word.data(31, 16) + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                ihl --;
                if(ihl == 0) {
                    total_length = total_length - ihl*4;
                    rid_state = RID_STREAM;
                }
                else 
                    rid_state = RID_SKIP;
            }
            break;
        case RID_SKIP:
            if(!rx_ip_data.empty()) {
                rx_ip_data.read();
                calc_checksum = curr_word.data(31, 16) + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                calc_checksum = ~calc_checksum;
                ihl --;
                if(ihl == 0) {
                    total_length = total_length - ihl*4;
                    rid_state = RID_STREAM;
                }
            }
            break;
        case RID_STREAM:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                axis_word_t temp = axis_word_t(0, 0xf, 0);
                temp.data(15, 8) = protocol;
                temp.data(15, 8) = total_length(7, 0);
                temp.data(7, 0) = total_length(15, 8);
                rx_udp_data.write(temp);
                no_drop = version == 4 && !flags && !offset && (dst_ip_addr == dchp_ip_addr || dst_ip_addr == broadcast_ip_addr) && calc_checksum == 0;
                if(!no_drop)
                    rid_state = RID_DROP;
                else if(total_length < 5)
                    rid_state = RID_RESIDUE;
                else 
                    rid_state = RID_KEEP;
                prev_word = curr_word;
                prev_word.last = 0;
            }
            break;
        case RID_DROP:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                if(curr_word.last)
                    rid_state = RID_IDLE;
            }
            break;
        case RID_KEEP:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                total_length = total_length - 4;
                if(total_length < 5)
                    rid_state = RID_RESIDUE;
                if(protocol == IP_TYPE_ICMP)
                    rx_icmp_data.write(prev_word);
                else if(ttl == 1)
                    rx_expired_data.write(prev_word);
                else if(protocol == IP_TYPE_UDP)
                    rx_udp_data.write(prev_word);
                prev_word = curr_word;
                prev_word.last = 0;
            }
            break;
        case RID_RESIDUE:
                prev_word.keep = ~(1 << (total_length - 1)) + (1 << (total_length - 1));
                prev_word.last = 1;
                if(protocol == IP_TYPE_ICMP)
                    rx_icmp_data.write(prev_word);
                else if(ttl == 1)
                    rx_expired_data.write(prev_word);
                else if(protocol == IP_TYPE_UDP)
                    rx_udp_data.write(prev_word);
                rid_state = RID_IDLE;
            }
            break;
    }
}

arp_server(rx_arp_data, ip_query, ip_query_resp, tx_arp_data, dchp_ip_addr);
void arp_server(stream<axis_word_t > rx_arp_data, stream<ap_uint<32> > ip_query, stream<query_resp_t> ip_query_resp, stream<axis_word_t> tx_arp_data, ap_uint<32> dchp_ip_addr) {
#pragma HLS inline off
#pragma HLS pipeline II=1 enable_flush

}
