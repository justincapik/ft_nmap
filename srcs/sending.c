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

// https://nmap.org/book/synscan.html
// SYN

// https://nmap.org/book/scan-methods-udp-scan.html
// UDP

// https://nmap.org/book/scan-methods-null-fin-xmas-scan.html
// FIN, NULL, and XMAS are parsed similarily, servers respond differently

// https://nmap.org/book/scan-methods-ack-scan.html
// ACK

// List of packets to listen for:
// - ICMP error (type 3, codes 1, 2, **+-3**, 9, 10, 13)
// - TCP RST
// - TCP SYN/ACK
// - UDP (unusual)


// first to do is SYN just to get idea of things


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

int     create_socket(u_char protocol)
{
    // Create a raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, protocol);
    if(sockfd < 0) {
        v_err(VBS_NONE, "Socket creation failed");
        return sockfd;
    }

    return sockfd;
}

void    send_icmp(int sockfd, struct sockaddr_in *target)
{
    char    packet[4096]; // Buffer for the packet
    memset(packet, 0, 4096);

    icmphdr_t hdr = {
        .type = ICMP_ECHO,
        .code = 0,
        .id = 12345,
        .sequence = 1,
        .cksum = 0
    };
    hdr.cksum = checksum((void*)&hdr, sizeof(icmphdr_t));

    memcpy(packet, &hdr, sizeof(icmphdr_t));

    if (sendto(sockfd, packet, sizeof(icmphdr_t), 0,
            (struct sockaddr *)target, sizeof(struct sockaddr_in)) < 0) {
        v_err(VBS_NONE, "sendto failed: %s\n", strerror(errno));
    }
    else
    {
        v_info(VBS_LIGHT, "Packet ICMP sent!\n");
    }
}

void    send_tlp_packet(int sockfd, void *tlp_header,
    char *self_ip, struct sockaddr_in *target, u_char protocol)
{
    size_t  packet_size;
    char    packet[4096]; // Buffer for the packet
    memset(packet, 0, 4096);
    
    packet_size = (protocol == IPPROTO_TCP) ?
        sizeof(struct tcphdr) : sizeof(struct udphdr);

    struct iphdr ip_header = {
        .ihl = 5,
        .version = 4,
        .tos = 0,
        .tot_len = sizeof(struct iphdr) + packet_size,
        .id = htons(54321), // tmp ?
        .frag_off = 0,
        .ttl = 255,
        .protocol = protocol,
        .check = 0,
        .saddr = inet_addr(self_ip),
        .daddr = target->sin_addr.s_addr
    }; 

    // set up pseudo header buffer for checksum
    struct pseudohdr pseudo_header = {
        .src_addr = ip_header.saddr,
        .dest_addr = ip_header.daddr,
        .placeholder = 0,
        .protocol = protocol,
        .pack_length = htons(packet_size)
    };
    memcpy(packet, &pseudo_header, sizeof(struct pseudohdr));
    memcpy(packet + sizeof(struct pseudohdr),
        tlp_header, packet_size);
    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr *tmp = (struct tcphdr*)tlp_header;
        tmp->th_sum = checksum((void*)packet,
            packet_size + sizeof(struct pseudohdr));
    }
    else /* IPPROTO_UDP */
    {
        struct udphdr *tmp = (struct udphdr*)tlp_header;
        tmp->uh_sum = checksum((void*)packet,
            packet_size + sizeof(struct pseudohdr));
    }

    // construct packet to send 
    memset(packet, 0, 4096);
    memcpy(packet, &ip_header, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr),
        tlp_header, packet_size);

    if (sendto(sockfd, packet, ip_header.tot_len, 0,
            (struct sockaddr *)target, sizeof(struct sockaddr_in)) < 0) {
        v_err(VBS_NONE, "sendto failed: %s\n", strerror(errno));
    } else {
        v_info(VBS_LIGHT, "Packet TLP sent!\n");
    }
}

void    send_packet(psm_opts_t *psm_opts, int sockfd, u_char protocol,
    struct sockaddr_in *target, uint16_t port)
{
    int ipheader_bool;

    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
    {

        // Set the IP_HDRINCL socket option
        ipheader_bool = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,
                &ipheader_bool, sizeof(ipheader_bool)) < 0)
            v_err(VBS_NONE, "Error setting IP_HDRINCL");

        if (protocol == IPPROTO_TCP)
        {
            // create tcp header and send
            target->sin_port = htons(port);
            struct tcphdr tcp_header = {
                .th_sport = htons(12345),
                .th_dport = target->sin_port,
                .th_seq = htonl(0),
                .th_ack = 0,
                .th_off = 5,            
                .th_flags = psm_opts->flags,
                .th_win = htons(65535),
                .th_sum = 0,              
                .th_urp = 0         
            };
            send_tlp_packet(sockfd, (void*)&tcp_header, psm_opts->self_ip,
                target, IPPROTO_TCP);
        }
        else /* IPPROTO_UDP */
        {
            // create udp header and send
            struct udphdr udp_header = {
                .uh_sport = htons(12345),
                .uh_dport = target->sin_port,
                .uh_ulen = htons(sizeof(struct udphdr)), // TODO: CHANGE IF ADDING DATA
                .uh_sum = 0
            };
            send_tlp_packet(sockfd, (void*)&udp_header, psm_opts->self_ip,
                target, IPPROTO_UDP);
        }
    }
    else if (protocol == IPPROTO_ICMP)
    {
        ipheader_bool = 0;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,
                &ipheader_bool, sizeof(ipheader_bool)) < 0)
            v_err(VBS_NONE, "Error unsetting IP_HDRINCL");
        send_icmp(sockfd, target);
    }
}

void    *packet_sending_manager(void *void_info)
{
    int                 udp_sock;
    int                 tcp_sock;
    int                 icmp_sock;
    psm_thread_vars_t   *psm_info = (psm_thread_vars_t *)void_info;

    // create socket for each packet type
    // TODO: only create socket if it doesn't exist
    if ((tcp_sock = create_socket(IPPROTO_TCP)) < 0)
        return NULL;
    if ((udp_sock = create_socket(IPPROTO_UDP)) < 0)
    {
        close(tcp_sock);
        return NULL;
    }
    if ((icmp_sock = create_socket(IPPROTO_ICMP)) < 0)
    {
        close(tcp_sock);
        close(udp_sock);
        return NULL;
    }

    while (1)
    {
        // lock queue ressource on psm_opts
        pthread_mutex_lock(&(psm_info->mutex));
        {
            if (shared_packet_data[psm_info->shared_index].state == FINISHED)
            {
                pthread_mutex_unlock(&(psm_info->mutex));
                break;
            }
            else if (shared_packet_data[psm_info->shared_index].state == DATA_FULL)
            {
                //TODO: optimize with copy and then process
                psm_opts_t *psm_opts = &(shared_packet_data[psm_info->shared_index]);
                switch (psm_opts->protocol) {
                    case IPPROTO_TCP:
                        send_packet(psm_opts, tcp_sock, IPPROTO_TCP,
                            psm_opts->target, psm_opts->port);
                        break;
                    case IPPROTO_UDP:
                        send_packet(psm_opts, udp_sock, IPPROTO_UDP,
                            psm_opts->target, psm_opts->port);
                        break;
                    case IPPROTO_ICMP:
                        send_packet(psm_opts, icmp_sock, IPPROTO_ICMP,
                            psm_opts->target, psm_opts->port);
                        break;
                    default:
                        break;
                }
                shared_packet_data[psm_info->shared_index].state = DATA_PROCESSED;
            }
            // unlock queue ressource on psm_opts
        }
        pthread_mutex_unlock(&(psm_info->mutex));
    }

    close(tcp_sock);
    close(udp_sock);
    close(icmp_sock);

    v_info(VBS_LIGHT, "end of thread\n");

    return NULL;
}