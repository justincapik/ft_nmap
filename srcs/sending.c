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

void    send_icmp(int sockfd, struct sockaddr_in *target, char *payload)
{
    char    packet[4096]; // Buffer for the packet
    memset(packet, 0, 4096);

    icmphdr_t hdr = {
        .type = ICMP_ECHO,
        .code = 0,
        .id = htons(DEFAULT_ID),
        .sequence = 1,
        .cksum = 0
    };
    memcpy(packet, &hdr, sizeof(icmphdr_t));
    memcpy(packet + sizeof(icmphdr_t), payload, PAYLOAD_SIZE);
    
    hdr.cksum = checksum((void*)packet, sizeof(icmphdr_t) + PAYLOAD_SIZE);
    memcpy(packet, &hdr, sizeof(icmphdr_t));
    
    if (sendto(sockfd, packet, sizeof(icmphdr_t) + PAYLOAD_SIZE, 0,
            (struct sockaddr *)target, sizeof(struct sockaddr_in)) < 0)
        v_err(VBS_NONE, "sendto failed: %s\n", strerror(errno));
    else
        v_info(VBS_LIGHT, "Packet ICMP sent!\n");
}

void send_tlp_packet(int sockfd, void *tlp_header, char *self_ip,
    struct sockaddr_in *target, u_char protocol, char *payload)
{
    char packet[4096]; // Buffer for the packet
    memset(packet, 0, sizeof(packet));

    size_t header_size = (protocol == IPPROTO_TCP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
    size_t packet_size = header_size + PAYLOAD_SIZE;

    struct iphdr ip_header;
    ip_header.ihl = 5;
    ip_header.version = 4;
    ip_header.tos = 0;
    ip_header.tot_len = htons(sizeof(struct iphdr) + packet_size);
    ip_header.id = htons(DEFAULT_ID);
    ip_header.frag_off = 0;
    ip_header.ttl = 255;
    ip_header.protocol = protocol;
    ip_header.check = 0;
    ip_header.saddr = inet_addr(self_ip);
    ip_header.daddr = target->sin_addr.s_addr;

    // Construct pseudo-header for checksum calculation
    struct pseudohdr pseudo_header;
    pseudo_header.src_addr = ip_header.saddr;
    pseudo_header.dest_addr = ip_header.daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = protocol;
    pseudo_header.pack_length = htons(packet_size);

    char checksum_buffer[4096];
    memset(checksum_buffer, 0, sizeof(checksum_buffer));
    memcpy(checksum_buffer, &pseudo_header, sizeof(struct pseudohdr));
    memcpy(checksum_buffer + sizeof(struct pseudohdr), tlp_header,
        header_size);
    memcpy(checksum_buffer + sizeof(struct pseudohdr) + header_size,
        payload, PAYLOAD_SIZE);

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (struct tcphdr*)tlp_header;
        tcp_hdr->th_sum = checksum((void*)checksum_buffer,
            sizeof(struct pseudohdr) + packet_size);
    } else { // IPPROTO_UDP
        struct udphdr *udp_hdr = (struct udphdr*)tlp_header;
        udp_hdr->uh_sum = checksum((void*)checksum_buffer,
            sizeof(struct pseudohdr) + packet_size);
    }

    // Construct final packet to send
    memset(packet, 0, sizeof(packet));
    memcpy(packet, &ip_header, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), tlp_header, header_size);
    memcpy(packet + sizeof(struct iphdr) + header_size, payload, PAYLOAD_SIZE);

    if (sendto(sockfd, packet, ntohs(ip_header.tot_len), 0,
               (struct sockaddr *)target, sizeof(struct sockaddr_in)) < 0)
    {        
        v_err(VBS_NONE, "sendto failed: %s\n", strerror(errno));
    } else {
        v_info(VBS_LIGHT, "Packet TLP sent!\n");
    }
}


void    send_packet(psm_opts_t *psm_opts, int sockfd, u_char protocol,
    struct sockaddr_in *target)
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
            target->sin_port = htons(psm_opts->port);
            struct tcphdr tcp_header = {
                .th_sport = htons(psm_opts->sport),
                .th_dport = htons(psm_opts->port),
                .th_seq = htonl(0),
                .th_ack = 0,
                .th_off = 5,            
                .th_flags = psm_opts->flags,
                .th_win = htons(65535),
                .th_sum = 0,              
                .th_urp = 0         
            };
            send_tlp_packet(sockfd, (void*)&tcp_header, psm_opts->self_ip,
                target, IPPROTO_TCP, psm_opts->payload);
        }
        else /* IPPROTO_UDP */
        {
            // create udp header and send
            struct udphdr udp_header = {
                .uh_sport = htons(psm_opts->sport),
                .uh_dport = htons(psm_opts->port),
                .uh_ulen = htons(sizeof(struct udphdr) + PAYLOAD_SIZE),
                .uh_sum = 0
            };
            send_tlp_packet(sockfd, (void*)&udp_header, psm_opts->self_ip,
                target, IPPROTO_UDP, psm_opts->payload);
        }
    }
    else if (protocol == IPPROTO_ICMP)
    {
        ipheader_bool = 0;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,
                &ipheader_bool, sizeof(ipheader_bool)) < 0)
            v_err(VBS_NONE, "Error unsetting IP_HDRINCL");
        send_icmp(sockfd, target, psm_opts->payload);
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
                            psm_opts->target);
                        break;
                    case IPPROTO_UDP:
                        send_packet(psm_opts, udp_sock, IPPROTO_UDP,
                            psm_opts->target);
                        break;
                    case IPPROTO_ICMP:
                        send_packet(psm_opts, icmp_sock, IPPROTO_ICMP,
                            psm_opts->target);
                        break;
                    default:
                        break;
                }
                shared_packet_data[psm_info->shared_index].state = DATA_EMPTY;
            }
        }
        // unlock queue ressource on psm_opts
        pthread_mutex_unlock(&(psm_info->mutex));
    }

    close(tcp_sock);
    close(udp_sock);
    close(icmp_sock);

    v_info(VBS_DEBUG, "end of thread\n");

    return NULL;
}