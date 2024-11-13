#include "ft_nmap.h"

// actually no i need the source port (local) to CONFIRM
// source port (local) CONFIRMS -> validity
//                              -> scan type (iterate thourgh ip * port)
// and i need destinaiton to find in the table

void            parse_icmp(struct addrinfo **targets, unsigned long s_addr,
                    void *pack, size_t pack_size)
{
    struct sockaddr_in  *tmp;
    icmphdr_t           *icmp;
    uint16_t            sport;
    uint16_t            dport;
    int                 response_type;

    icmp = (icmphdr_t *)pack;

    if (icmp->id == htons(DEFAULT_ID))
    {
        for (size_t i = 0; targets[i] != NULL; ++i)
        {
            tmp = (struct sockaddr_in*)(targets[i]->ai_addr);
            if (tmp->sin_addr.s_addr == s_addr)
            {
                response_type = parse_icmp_answer((void*)icmp, pack_size,
                    &sport, &dport);

                if (response_type == R_ICMP_CLEAN)
                    results_add_icmp(i);
                else if (response_type == R_ICMP_ERR_OTH
                    ||response_type == R_ICMP_ERR_3)
                    results_add_info(i, sport, dport, response_type);
                else
                    printf("irrelevent icmp packet\n");
                // ignore '0' response, irrelevant packet
            }
        }
    }
}

void            parse_tcp(struct addrinfo **targets, unsigned long s_addr,
                    void *pack, size_t pack_size)
{
    struct sockaddr_in  *tmp;
    struct tcphdr       *tcp;
    uint16_t            sport;
    uint16_t            dport;
    int                 response_type;

    tcp = (struct tcphdr *)pack;

    for (size_t i = 0; targets[i] != NULL; ++i)
    {
        tmp = (struct sockaddr_in*)(targets[i]->ai_addr);
        if (tmp->sin_addr.s_addr == s_addr)
        {
            response_type = parse_tcp_answer((void*)tcp, pack_size,
                &sport, &dport);
            if (response_type != 0)
                results_add_info(i, sport, dport, response_type);
        }
    }
}

void            parse_udp(struct addrinfo **targets, unsigned long s_addr,
                    void *pack, size_t pack_size)
{
    struct sockaddr_in  *tmp;
    struct udphdr       *udp;
    uint16_t            sport;
    uint16_t            dport;
    int                 response_type;

    udp = (struct udphdr *)pack;
    
    for (size_t i = 0; targets[i] != NULL; ++i)
    {
        tmp = (struct sockaddr_in*)(targets[i]->ai_addr);
        if (tmp->sin_addr.s_addr == s_addr)
        {
            response_type = parse_udp_answer((void*)udp, pack_size,
                &sport, &dport);
            if (response_type != 0)
                results_add_info(i, sport, dport, response_type);
        }
    }
    
    char *payload = ((char*)pack) + sizeof(struct iphdr) + sizeof(struct udphdr);
    for (int i = 0; i < PAYLOAD_SIZE; ++i)
        printf("%hhx", payload[i]);
    printf("\n");

    (void)pack_size;
}

void            parse_packets(u_char *char_opts, const struct pcap_pkthdr *h,
    const u_char *raw_data)
{
    struct iphdr        *hdr;
    struct ether_header *eth = (struct ether_header *)raw_data;
    int                 ether_size = ETH_HLEN;
    uint16_t            ether_type = ntohs(eth->ether_type);
    opt_t               *opts = (opt_t *)char_opts;

    if (ether_type != ETHERTYPE_IP)
        v_info(VBS_DEBUG, "NON IP PACKET: 0x%04x\n", ether_type);

    if (ether_type == ETHERTYPE_IP)
    {
        hdr = (struct iphdr*)(raw_data+ether_size);
        
        int ip_size = IP_HL(hdr)*4;
        if (ip_size < 20)
        {
            v_err(VBS_NONE, "Invalid IP header length: %u bytes\n", ip_size);
            return;
        }

        switch (hdr->protocol) {
            case IPPROTO_ICMP:
                v_info(VBS_DEBUG, "Got ICMP packet\n");
                parse_icmp(opts->targets, hdr->saddr,
                    (void*)(raw_data + ether_size + ip_size),
                    (size_t)(h->len - ether_size - ip_size));
                break;
            case IPPROTO_TCP:
                v_info(VBS_DEBUG, "Got TCP packet\n");
                parse_tcp(opts->targets, hdr->saddr,
                    (void*)(raw_data + ether_size + ip_size),
                    (size_t)(h->len - ether_size - ip_size));
                break;
            case IPPROTO_UDP:
                v_info(VBS_DEBUG, "Got UDP packet\n");
                parse_udp(opts->targets, hdr->saddr,
                    (void*)(raw_data + ether_size + ip_size),
                    (size_t)(h->len - ether_size - ip_size));
                break;
            default:
                v_info(VBS_DEBUG, "OTHER packet\n");
                break;
        }
        
        struct in_addr src_addr;
        src_addr.s_addr = hdr->saddr;
        char src_ip[INET_ADDRSTRLEN];
        strncpy(src_ip, inet_ntoa(src_addr), INET_ADDRSTRLEN);

        v_info(VBS_DEBUG, "src  = %s\n", src_ip);
        v_info(VBS_DEBUG, "\n");
    }

    (void)h;
}