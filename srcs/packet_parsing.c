#include "ft_nmap.h"

void            parse_icmp(struct addrinfo **targets, unsigned long s_addr,
                    void *pack)
{
    struct sockaddr_in  *tmp;
    struct iphdr        *ip;
    icmphdr_t           *icmp;

    // TODO: extra security, check icmp payload for validation
    // char *payload = ((char*)pack) + sizeof(struct iphdr) + sizeof(icmphdr_t);
    // for (int i = 0; i < PAYLOAD_SIZE; ++i)
    //     printf("%hhx", payload[i]);
    // printf("\n");

    ip = (struct iphdr*)pack;
    icmp = (icmphdr_t *) (((char*)pack) + sizeof(struct iphdr));

    (void)ip;

    if (icmp->id == htons(DEFAULT_ID))
    {
        for (size_t i = 0; targets[i] != NULL; ++i)
        {
            tmp = (struct sockaddr_in*)(targets[i]->ai_addr);
            if (tmp->sin_addr.s_addr == s_addr)
                results_add_icmp(i);
        }
    }

}

void            parse_tcp(struct addrinfo **targets, unsigned long s_addr,
                    void *pack)
{
    struct sockaddr_in *tmp;
    // struct iphdr        *ip;
    struct tcphdr       *tcp;

    // ip = (struct iphdr*)pack;
    tcp = (struct tcphdr *) (((char*)pack) + sizeof(struct iphdr));

    if ((uint16_t)ntohs(tcp->th_dport) == DEFAULT_SOURCE_PORT)
    {
        for (size_t i = 0; targets[i] != NULL; ++i)
        {
            tmp = (struct sockaddr_in*)(targets[i]->ai_addr);
            if (tmp->sin_addr.s_addr == s_addr)
                results_add_tcp(i);
        }
    }
    else
        printf("ports don't match\n");
}

void            parse_udp(struct addrinfo **targets, unsigned long s_addr,
                    void *pack)
{
    struct sockaddr_in *tmp;

    for (size_t i = 0; targets[i] != NULL; ++i)
    {
        tmp = (struct sockaddr_in*)(targets[i]->ai_addr);
        if (tmp->sin_addr.s_addr == s_addr)
            results_add_udp(i);
    }
    
    char *payload = ((char*)pack) + sizeof(struct iphdr) + sizeof(struct udphdr);
    for (int i = 0; i < PAYLOAD_SIZE; ++i)
        printf("%hhx", payload[i]);
    printf("\n");
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
                v_info(VBS_DEBUG, "ICMP packet\n");
                parse_icmp(opts->targets, hdr->saddr,
                    (void*)(raw_data + ether_size));
                break;
            case IPPROTO_TCP:
                v_info(VBS_DEBUG, "TCP packet\n");
                parse_tcp(opts->targets, hdr->saddr,
                    (void*)(raw_data + ether_size));
                break;
            case IPPROTO_UDP:
                v_info(VBS_DEBUG, "UDP packet\n");
                parse_udp(opts->targets, hdr->saddr,
                    (void*)(raw_data + ether_size));
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