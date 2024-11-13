#include "ft_nmap.h"

// access through results

// all functions return target server port
// and store return type in r_type

//TODO:
uint8_t   no_response_logic(uint8_t scan_type)
{
    switch (scan_type)
    {
        case SYN_SCAN:
            return FILTERED;
        case ACK_SCAN:
            return FILTERED;
        case NULL_SCAN:
        case FIN_SCAN:
        case XMAS_SCAN:
            return OPEN_FILTERED;
        case UDP_SCAN:
            return OPEN_FILTERED;
        default:
            printf("something went very wrong\n");
            return 0;
    }
}

uint8_t     scan_logic(uint8_t scan_type, uint8_t answer)
{
    switch (scan_type)
    {
        case SYN_SCAN:
            switch (answer)
            {
                case R_TCP_SYN_ACK:
                    return OPEN;
                case R_TCP_RST:
                    return CLOSED;
                case R_ICMP_ERR_3:
                case R_ICMP_ERR_OTH:
                    return FILTERED;
                default:
                    printf("Something's gone terriblye wrong (1)\n");
                    return 0;
            }
        case ACK_SCAN: 
            switch (answer)
            {
                case R_TCP_RST:
                    return UNFILTERED;
                case R_ICMP_ERR_3:
                case R_ICMP_ERR_OTH:
                    return FILTERED;
                default:
                    printf("Something's gone terriblye wrong (2)\n");
                    return 0;
            }
        case NULL_SCAN:
        case XMAS_SCAN:
        case FIN_SCAN:
            switch (answer)
            {
                case R_TCP_RST:
                    return CLOSED;
                case R_ICMP_ERR_3:
                case R_ICMP_ERR_OTH:
                    return FILTERED;
                default:
                    printf("Something's gone terriblye wrong (3)\n");
                    return 0;
            }
        case UDP_SCAN:
            switch (answer)
            {
                case R_UDP_ANY:
                    return OPEN;
                case R_ICMP_ERR_3:
                    return CLOSED;
                case R_ICMP_ERR_OTH:
                    return FILTERED;
                default:
                    printf("Something's gone terriblye wrong (4)\n");
                    return 0;
            }
        default:
            printf("Something's gone terriblye wrong (5)\n");
            return 0;
    }
}

uint8_t     parse_tcp_answer(void *pack, size_t pack_size, uint16_t *sport,
				uint16_t *dport)
{
    struct tcphdr   *tcp = (struct tcphdr *)pack;
    char            *payload = (char*)((char*)pack + sizeof(struct tcphdr));
    
    (void)pack_size;
    (void)payload;

    *dport = ntohs(tcp->th_dport);
    *sport = ntohs(tcp->th_sport);

    if ((tcp->th_flags & TCP_RST) > 0)
        return R_TCP_RST;
    else if ((tcp->th_flags & (TCP_SYN | TCP_ACK)) > 0)
        return R_TCP_SYN_ACK;
    else
        return 0;
}

uint8_t     parse_icmp_answer(void *pack, size_t pack_size, uint16_t *sport,
				uint16_t *dport)
{
    struct iphdr    *og_ip;
    struct tcphdr   *og_tcp;
    struct udphdr   *og_udp;
    icmphdr_t   *icmp = (icmphdr_t *)pack;
    char        *payload = (char*)((char*)pack + sizeof(icmphdr_t));

    (void)pack_size;

    if (icmp->type == 0 && icmp->code == 0)
        return R_ICMP_CLEAN;
    else if (icmp->type == ICMP_DEST_UNREACH)
    {
        og_ip = (struct iphdr *)payload;

        switch (og_ip->protocol)
        {
            case IPPROTO_TCP:
                og_tcp = (struct tcphdr *)(payload + IP_HL(og_ip));
                *dport = ntohs(og_tcp->th_dport);
                *sport = ntohs(og_tcp->th_sport);
                break;
            case IPPROTO_UDP:
                og_udp = (struct udphdr *)(payload + IP_HL(og_ip));
                *dport = ntohs(og_udp->uh_dport);
                *sport = ntohs(og_udp->uh_sport);
                break;
            default:
                return 0;
        }

        switch (icmp->code)
        {
            case 3:
                return R_ICMP_ERR_3;
            case 1:
            case 2:
            case 9:
            case 10:
            case 13:
                return R_ICMP_ERR_OTH;
            default:
                return 0;
        }
    }
    else
        return 0;
}

uint8_t     parse_udp_answer(void *pack, size_t pack_size, uint16_t *sport,
				uint16_t *dport)
{
    struct udphdr   *udp = (struct udphdr *)pack;
    char            *payload = (char*)((char*)pack + sizeof(struct udphdr));

    *dport = ntohs(udp->uh_dport);
    *sport = ntohs(udp->uh_sport);

    (void)pack_size;
    (void)payload; 

    return R_UDP_ANY;
}