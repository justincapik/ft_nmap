#include "ft_nmap.h"

// Question: on function fer scan type ?
// - different packet types (TCP, UDP)
// - different TCP flags (SYN, NULL, ACK, FIN, XMAS(all))

// What are we doing in a sending function ?
// - called by thread pool after getting paquet_queue
// - open socket (need to say packet type)
// - create packet/set flags
// - sendto
// - wait for response and resend if none after TIME
//     ^- Call pcap_parsing here ?
// 

// https://nmap.org/book/scan-methods-null-fin-xmas-scan.html
// FIN, NULL, and XMAS are very similar, servers respond differently


// first to do is SYN just to get idea of things

// typedef struct packet_opts_s {
//     u_char              protocol;
//     struct sockaddr_in  *endpoint;
//     uint8_t             flags; // only relevant for TCP ?
//     opt_t               *opts;
// } pack_opts_t;



uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    unsigned int sum = 0;
    uint16_t result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// set_up_socket_for_scan_type() ?



void    *packet_sending_manager(void *void_psm_opts)
{
    int                 sockfd;
    psm_opts_t          *psm_opts = (psm_opts_t*)void_psm_opts;
    struct sockaddr_in  *target = psm_opts->endpoint;
    uint16_t            *port = psm_opts->port;
    opt_t               *opts = psm_opts->opts;

    // Create a raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0) {
        v_err(VBS_NONE, "Socket creation failed");
        return NULL;
    }

    // Set the IP_HDRINCL socket option
    int one = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        v_err(VBS_NONE, "Error setting IP_HDRINCL");
        return NULL;
    }

    for (size_t i = 0; i < psm_opts->nb_endpoint; ++i)
    {
        for (size_t j = 0; j < psm_opts->nb_port; ++j)
        {
            // Buffer for the packet
            char packet[4096];
            memset(packet, 0, 4096);

            struct iphdr ip_header = {
                .ihl = 5,
                .version = 4,
                .tos = 0,
                .tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr),
                .id = htons(54321), // tmp ?
                .frag_off = 0,
                .ttl = 255,
                .protocol = IPPROTO_TCP,
                .check = 0,
                .saddr = inet_addr(opts->self_ip),
                .daddr = target[i].sin_addr.s_addr
            }; 

            target[i].sin_port = htons(port[j]);
            struct tcphdr tcp_header = {
                .th_sport = htons(12345),
                .th_dport = target[i].sin_port,
                .th_seq = htonl(0),
                .th_ack = 0,
                .th_off = 5,            
                .th_flags = psm_opts->flags,
                .th_win = htons(65535),
                .th_sum = 0,              
                .th_urp = 0         
            };

            // for tcp checksum
            struct pseudohdr pseudo_header = {
                .src_addr = ip_header.saddr,
                .dest_addr = ip_header.daddr,
                .placeholder = 0,
                .protocol = IPPROTO_TCP,
                .tcp_length = htons(sizeof(struct tcphdr))
            };
            memcpy(packet, &pseudo_header, sizeof(struct pseudohdr));
            memcpy(packet + sizeof(struct pseudohdr),
                &tcp_header, sizeof(struct tcphdr));
            tcp_header.th_sum = checksum((void*)packet,
                sizeof(struct tcphdr) + sizeof(struct pseudohdr));

            // 
            memset(packet, 0, 4096);
            memcpy(packet, &ip_header, sizeof(struct iphdr));
            memcpy(packet + sizeof(struct iphdr),
                &tcp_header, sizeof(struct tcphdr));

            if (sendto(sockfd, packet, ip_header.tot_len, 0,
                    (struct sockaddr *)&(target[i]), sizeof(struct sockaddr_in)) < 0) {
                printf("sendto failed: %s\n", strerror(errno));
            } else {
                printf("Packet sent!\n");
            }
        }
    }




    return NULL;
}