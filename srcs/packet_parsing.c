#include "ft_nmap.h"

// void        parse_iphdr(const u_char *raw_data)
void            parse_packets(u_char *opts, const struct pcap_pkthdr *h,
    const u_char *raw_data)
{
    struct iphdr *hdr;
    struct ether_header *eth = (struct ether_header *)raw_data;
    int ether_size = ETH_HLEN;
    uint16_t ether_type = ntohs(eth->ether_type);

    if (ether_type != ETHERTYPE_IP)
        v_info(VBS_DEBUG, "NON IP PACKET: 0x%04x\n", ether_type);

    if (ether_type == ETHERTYPE_IP)
    {
        hdr = (struct iphdr*)(raw_data+ether_size);
        
        int size_ip = IP_HL(hdr)*4;
        if (size_ip < 20)
        {
            v_err(VBS_NONE, "Invalid IP header length: %u bytes\n", size_ip);
            return;
        }

        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = hdr->saddr;
        dst_addr.s_addr = hdr->daddr;
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        strncpy(src_ip, inet_ntoa(src_addr), INET_ADDRSTRLEN);
        strncpy(dst_ip, inet_ntoa(dst_addr), INET_ADDRSTRLEN);

        switch (hdr->protocol) {
            case IPPROTO_ICMP:
                v_info(VBS_DEBUG, "ICMP packet\n");
                break;
            case IPPROTO_TCP:
                v_info(VBS_DEBUG, "TCP packet\n");
                break;
            case IPPROTO_UDP:
                v_info(VBS_DEBUG, "UDP packet\n");
                break;
            default:
                v_info(VBS_DEBUG, "OTHER packet\n");
                break;
        }
        
        // v_info(VBS_DEBUG, "hl = %x - v = %x\n", hdr->ihl, hdr->version);
        // v_info(VBS_DEBUG, "type of service = %d\n", hdr->tos);
        // v_info(VBS_DEBUG, "time to live = %d\n", hdr->ttl);
        v_info(VBS_DEBUG, "src  = %s\n", src_ip);
        v_info(VBS_DEBUG, "dst  = %s\n", dst_ip);
        v_info(VBS_DEBUG, "\n");
    }

    (void)h;
    (void)opts;
}