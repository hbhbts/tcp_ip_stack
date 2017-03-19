//tcp_ip_top function


#include "ap_int.h"
#include "hls_stream.h"

#define ARP_CACHE_SIZE 6
#define ARP_CACHE_NUM (2**(ARP_CACHE_SIZE))

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
    rx_ip_decode(rx_ip_data, rx_icmp_data, rx_expired_data, rx_udp_valid, rx_udp_pseudo, rx_udp_data, dchp_ip_addr);
    arp_server(rx_arp_data, ip_query, ip_query_rsp, tx_arp_data, dchp_ip_addr);
    icmp_handle(rx_icmp_data, rx_expired_data, rx_udp_unreachable, tx_icmp_data);
    udp_rx_handle(rx_udp_valid, rx_udp_pseudo, rx_udp_data, open_port, open_port_rsp, release_port, in_udp_socket, in_udp_data, rx_udp_unreachable);
    tx_ip_encode(out_socket, out_udp_data, out_udp_len, tx_icmp_data, tx_ip_data, tx_ip_checksum, dchp_ip_addr);
    tx_mac_encode(tx_ip_data, tx_ip_checksum, tx_arp_data, ip_query, ip_query_rsp, tx_data);
    udp_msg_mux(open_port, open_port_rsp, release_port, in_socket, in_udp_data, out_socket, out_udp_data, out_udp_len, 
                dchp_open_port, dchp_open_port_rsp, dchp_release_port, dchp_in_socket, dchp_in_udp_data, dchp_out_socket, dchp_out_udp_data, dchp_out_udp_len,
                ulb_open_port, ulb_open_port_rsp, ulb_release_port, ulb_in_socket, ulb_in_udp_data, ulb_out_socket, ulb_out_udp_data, ulb_out_udp_len);
    dchp_server(dchp_ip_addr, 
                dchp_open_port, dchp_open_port_rsp, dchp_release_port, dchp_in_socket, dchp_in_udp_data, dchp_out_socket, dchp_out_udp_data, dchp_out_udp_len);
    udp_loopback(ulb_open_port, ulb_open_port_rsp, ulb_release_port, ulb_in_socket, ulb_in_udp_data, ulb_out_socket, ulb_out_udp_data, ulb_out_udp_len, dchp_ip_addr);
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



void rx_ip_decode(stream<axis_word_t> rx_ip_data, stream<axis_word_t> rx_icmp_data, stream<axis_word_t> rx_expired_data,
                    stream<ap_uint<1> > rx_udp_valid, stream<udp_psd_t > rx_udp_pseudo, stream<axis_word_t> rx_udp_data,
                    ap_uint<32> dchp_ip_addr) {
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
    static ap_uint<17> pseudo_checksum;
    static ap_uint<32> src_ip_addr;
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
                calc_checksum = calc_checksum + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                calc_checksum = calc_checksum + curr_word.data(31, 16);
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
                calc_checksum = calc_checksum + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                calc_checksum = calc_checksum + curr_word.data(31, 16);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                ihl --;
                rid_state ++;
            }
            break;
        case RID_R3:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                src_ip_addr = byte_swap32(curr_word.data);
                pseudo_checksum = curr_word.data(15, 0) + curr_word.data(31, 16);
                pseudo_checksum = pseudo_checksum(15, 0) + pseudo_checksum.bit(16);
                calc_checksum = calc_checksum + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                calc_checksum = calc_checksum + curr_word.data(31, 16);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                ihl --;
                rid_state ++;
            }
            break;
        case RID_R4:
            if(!rx_ip_data.empty()) {
                curr_word = rx_ip_data.read();
                dst_ip_addr = byte_swap32(curr_word.data);
                pseudo_checksum = pseudo_checksum + curr_word.data(15, 0);
                pseudo_checksum = pseudo_checksum(15, 0) + pseudo_checksum.bit(16);
                pseudo_checksum = pseudo_checksum + curr_word.data(31, 16);
                pseudo_checksum = pseudo_checksum(15, 0) + pseudo_checksum.bit(16);
                calc_checksum = calc_checksum + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                calc_checksum = calc_checksum + curr_word.data(31, 16);
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
                calc_checksum = calc_checksum + curr_word.data(15, 0);
                calc_checksum = calc_checksum(15, 0) + calc_checksum.bit(16);
                calc_checksum = calc_checksum + curr_word.data(31, 16);
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
                axis_word_t temp = axis_word_t(0, 0xf, 1);
                temp.data(15, 8) = protocol;
                temp.data(15, 8) = total_length(7, 0);
                temp.data(7, 0) = total_length(15, 8);
                pseudo_checksum = pseudo_checksum + temp.data(15, 0);
                pseudo_checksum = pseudo_checksum(15, 0) + pseudo_checksum.bit(16);
                pseudo_checksum = pseudo_checksum + temp.data(31, 16);
                pseudo_checksum = pseudo_checksum(15, 0) + pseudo_checksum.bit(16);
                udp_pst_t pst_tmp;
                pst_tmp.ip = src_ip_addr;
                pst_tmp.checksum = pseudo_checksum;
                rx_udp_pseudo.write(pst_tmp);
                no_drop = version == 4 && !flags && !offset && (dst_ip_addr == dchp_ip_addr || dst_ip_addr == broadcast_ip_addr) && calc_checksum == 0;
                if(!no_drop)
                    rid_state = RID_DROP;
                else if(total_length < 5)
                    rid_state = RID_RESIDUE;
                else 
                    rid_state = RID_KEEP;
                prev_word = curr_word;
                prev_word.last = 0;
                if(no_drop && protocol ==IP_TYPE_UDP) 
                    rx_udp_valid.write(1);
                else 
                    rx_udp_valid.write(0);
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


void rx_arp_handle(stream<axis_word_t> rx_arp_data, stream<arp_cache_t> update_arp_cache, stream<arp_cache_t> send_arp_reply, ap_uint<32> dchp_ip_addr) {
#pragma HLS inline off
#pragma HLS pipeline II=1 enable_flush

    static int rah_state = 0;
    static axis_word_t curr_word;
    static ap_uint<16> htype;
    static ap_uint<16> ptype;
    static ap_uint<16> op;
    static ap_uint<48> sha;
    static ap_uint<32> spa;
    static ap_uint<48> tha;
    static ap_uint<32> tpa;

    if(!rx_arp_data.empty()) {
        curr_word = rx_arp_data.read();
        switch(rah_state) {
            case 0:
                htype = byte_swap16(curr_word.data(15, 0));
                ptype = byte_swap16(curr_word.data(31, 16));
                break;
            case 1:
                op = byte_swap16(curr_word.data(31, 16));
                break;
            case 2:
                sha(47, 16) = byte_swap32(curr_word.data);
                break;
            case 3:
                sha(15, 0) = byte_swap16(curr_word.data(15, 0));
                spa(31, 16) = byte_swap16(curr_word.data(31, 16));
                break;
            case 4:
                spa(15, 0) = byte_swap16(curr_word.data(15, 0));
                tha(47, 32) = byte_swap16(curr_word.data(31, 16));
                break;
            case 5:
                tha(31, 0) = byte_swap16(curr_word.data);
                break;
            case 6:
                tpa = byte_swap16(curr_word.data);
                if(hype == 0x001 && ptype == 0x0800 && tpa == dchp_ip_addr && (op == 1 || op == 2)) {
                    arp_cache_t arp_cache_temp;
                    arp_cache_temp.mac = sha;
                    arp_cache_temp.ip = spa;
                    update_arp_cache.write(arp_cache_temp);
                    if(op == 1) //request
                        send_arp_reply.write(arp_cache_temp);
                }
                break;
        }
        rah_state ++;
        if(curr_word.last)
            rah_state = 0;
    }
}

void arp_cache(stream<arp_cache_t> update_arp_cache, stream<ap_uint<32> > ip_query, stream<query_rsp_t> ip_query_rsp, stream<arp_cache_t> send_arp_request) {
#pragma HLS inline off
#pragma HLS pipeline II=1 enable_flush
    ap_uint<48+32-ARP_CACHE_SIZE> cache [ARP_CACHE_NUM];
    arp_cache_t cache_temp;
    ap_uint<ARP_CACHE_SIZE> index;
    ap_uint<48+32-ARP_CACHE_SIZE> entry;
    ap_uint<32> ip;

    if(!update_arp_cache.empty()) {
        cache_temp = update_arp_cache.read();
        index = cache_temp.ip(ARP_CACHE_SIZE-1, 0);
        entry(31-ARP_CACHE_SIZE, 0) = cache_temp.ip(31, ARP_CACHE_SIZE);
        entry(48+31-ARP_CACHE_SIZE, 32-ARP_CACHE_SIZE) = cache_temp.mac;
        cache[index] = entry;        
    }
    else if(!ip_query.empty()) {
        query_rsp_t rsp = query_rsp_t(0, 0); 
        ip = ip_query.read();
        index = ip(ARP_CACHE_SIZE-1, 0);
        entry = cache[index];
        if(entry(31-ARP_CACHE_SIZE, 0) == ip(31, ARP_CACHE_SIZE)) {
            rsp.hit = 1;
            rsp.mac = entry(48+31-ARP_CACHE_SIZE, 32-ARP_CACHE_SIZE);
        }
        ip_query_rsp.write(rsp);
        if(!rsp.hit) {
            cache_temp.mac = broadcast_mac_addr;
            cache_temp.ip = ip;
            send_arp_request.write(cache_temp);
        }
    }
}

void arp_mux(stream<arp_cache_t> send_arp_reply, stream<arp_cache_t> send_arp_request, ap_uint<32> dchp_ip_addr, stream<axis_word_t> tx_arp_data) {
#pragma HLS inline off
#pragma HLS pipeline II=1 enable_flush 

    static int am_state = 0;
    static arp_cache_t req;
    static ap_uint<1> is_reply;
    static axis_word_t temp;

    switch(am_state) {
        case 0:
            if(!send_arp_reply.empty() || !send_arp_request.empty()) {
                if(!send_arp_reply.empty()) {
                    req = send_arp_reply.read();
                    is_reply = 1;
                }
                else {
                    req = send_arp_request.read();
                    is_reply = 0;
                }
                am_state ++;
            }
            break;
        case 1:
            temp.data(15, 0) = byte_swap16(0x0001);
            temp.data(31, 16) = byte_swap16(0x0800);
            tx_arp_data.write(temp);
            am_state ++;
            break;
        case 2:
            temp.data(7, 0) = 6;
            temp.data(15, 8) = 4;
            if(is_reply)
                temp.data(31, 16) = 2;
            else
                temp.data(31, 16) = 1;
            tx_arp_data.write(temp);
            am_state ++;
            break;
        case 3:
            temp.data = byte_swap32(local_mac_addr(47, 16);
            tx_arp_data.write(temp);
            am_state ++;
            break;
        case 4:
            temp.data(15, 0) = byte_swap16(local_mac_addr(15, 0));
            temp.data(31, 16) = byte_swap16(dchp_ip_addr(31, 16));
            tx_arp_data.write(temp);
            am_state ++;
            break;
        case 5:
            temp.data(15, 0) = byte_swap16(dchp_ip_addr(15, 0));
            temp.data(31, 16) = byte_swap16(req.mac(47, 32));
            tx_arp_data.write(temp);
            am_state ++;
            break;
        case 6:
            temp.data = byte_swap32(req.mac(31, 0));
            tx_arp_data.write(temp);
            am_state ++;
            break;
        case 7:
            temp.data = byte_swap32(req.ip);
            temp.last = 1;
            tx_arp_data.write(temp);
            am_state = 0;
            break;
    }
}

void arp_server(stream<axis_word_t> rx_arp_data, stream<ap_uint<32> > ip_query, stream<query_rsp_t> ip_query_rsp, stream<axis_word_t> tx_arp_data, ap_uint<32> dchp_ip_addr) {
#pragma HLS inline

    rx_arp_handle(rx_arp_data, update_arp_cache, send_arp_reply, dchp_ip_addr);
    arp_cache(update_arp_cache, ip_query, ip_query_rsp, send_arp_request);
    arp_mux(send_arp_reply, send_arp_request, dchp_ip_addr, tx_arp_data);

}

void rx_udp_verify(stream<ap_uint<1> > rx_udp_valid, stream<udp_pst_t > rx_udp_pseudo, stream<axis_word_t> rx_udp_data,
        stream<ap_uint<17> > calc_checksum, stream<connection_t> rx_udp_cnn, sream<axis_word_t> verify_stream, ap_uint<32> dhcp_ip_addr) {
#pragma HLS inline off
#pragma HLS pipeline enable_flush
    static enum ruv_state_e {IDLE=0, DROP_PSEUDO, READ_PSEUDO, UDP_HEADER, UDP_HEAFER2, DROP_UDP, UDP_DATA} ruv_state = 0;
    static udp_pst_t pst_tmp;
    static ap_uint<17> pseudo_checksum;
    static axis_word_t temp;
    static ap_uint<16> src_port;
    static ap_uint<16> dst_port;
    static ap_uint<16> length;
    static ap_uint<16> checksum;
    
    
    switch(ruv_state) {
        case IDLE:
            if(!rx_udp_valid.empty()) {
                if(rx_udp_valid.data == 0)
                    ruv_state = DROP_PSEUDO;
                else
                    ruv_state = READ_PSEUDO;
            }
            break;
        case DROP_PSEUDO:
            rx_udp_pseudo.read();
            ruv_state = IDLE;
            break;
        case READ_PSEUDO:
            if(!rx_udp_pseudo.empty()) {
                pst_tmp = rx_udp_pseudo.read();
                pseudo_checksum = pst_tmp.checksum;
                ruv_state = UDP_HEADER;
            }
            break;
        case UDP_HEADER:
            if(!rx_udp_data.empty()) {
                temp = rx_udp_data.read();
                src_port = byte_swap16(temp.data(15, 0));
                dst_port = byte_swap16(temp.data(31, 16));
                pseudo_checksum = pseudo_checksum + temp.data(15, 0);
                pseudo_checksum = pseudo_checksum(15, 0) + pseudo_checksum.bit(16);
                pseudo_checksum = pseudo_checksum + temp.data(31, 16);
                pseudo_checksum = pseudo_checksum(15, 0) + pseudo_checksum.bit(16);
                ruv_state = UDP_HEAFER2;
            }
            break;
        case UDP_HEADER2:
            if(!rx_udp_data.empty()) {
                temp = rx_udp_data.read();
                length = temp.data(15, 0);
                checksum = temp.data(31, 16);
                pseudo_checksum = pseudo_checksum + temp.data(15, 0);
                pseudo_checksum = pseudo_checksum(15, 0) + pseudo_checksum.bit(16);
                pseudo_checksum = pseudo_checksum + temp.data(31, 16);
                pseudo_checksum = pseudo_checksum(15, 0) + pseudo_checksum.bit(16);
                pseudo_checksum = ~pseudo_checksum;
                calc_checksum.write(pseudo_checksum);
                connection_t cnn_tmp;
                cnn_tmp.src_ip = pst_tmp.ip;
                cnn_tmp.src_port = src_port;
                cnn_tmp.dst_ip = dhcp_ip_addr;
                cnn_tmp.dst_port = dst_port;
                rx_udp_cnn.write(cnn_tmp);
                if(temp.last)
                    ruv_state = IDLE;
                else
                    ruv_state = UDP_DATA;
            }
            break;
        case UDP_DATA:
            if(!rx_udp_data.empty()) {
                temp = rx_udp_data.read();
                verify_stream.write(temp);
                if(temp.last)
                    ruv_state = IDLE;
            }
            break;
    }
}

void udp_port_mng(stream<ap_uint<16> > port_status_req, stream<ap_uint<1> > port_status_rsp, stream<ap_uint<16> > open_port,
                    stream<ap_uint<1> > open_port_rsp, stream<ap_uint<16> > release_port) {
    
}

void udp_rx_handle(stream<ap_uint<1> > rx_udp_valid, stream<axis_word_t> rx_udp_pseudo, stream<axis_word_t> rx_udp_data, stream<ap_uint<16> > open_port, stream<ap_uint<1> > open_port_rsp,
        stream<ap_uint<16> > release_port, stream<connection_t> in_udp_cnn, stream<axis_word_t> in_udp_data, stream<axis_word_t> rx_udp_unreachable) {
#pragma HLS inline

    rx_udp_verify(rx_udp_valid, rx_udp_pseudo, rx_udp_data, calc_checksum, connection, verify_stream);
    udp_decode(calc_checksum, connection, verify_stream, port_status_req, port_status_rsp, rx_udp_unreachable, in_udp_cnn, in_udp_data);
    udp_port_mng(port_status_req, port_status_rsp, open_port, open_port_rsp, release_port);
}

