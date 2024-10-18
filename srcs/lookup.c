#include "ft_nmap.h"

struct addrinfo   *dns_lookup(char *canonname, opt_t *opts)
{
    // check direction of lookup ?
    struct addrinfo hint;
    ft_memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_INET;   // IPv4 
    hint.ai_socktype = SOCK_RAW; // configure sent packet header
    hint.ai_flags = AI_CANONNAME | AI_V4MAPPED | AI_ADDRCONFIG;
    hint.ai_protocol = IPPROTO_ICMP; // ICMP packet  TODO: change ?  
    hint.ai_canonname = NULL;
    hint.ai_addr = NULL;
    hint.ai_next = NULL;
    
    struct addrinfo add_res;
    struct addrinfo* res = &add_res;
    int s = getaddrinfo(canonname, 0, &hint, &res);
    if (s != 0) {
        fprintf(stderr, "%s: %s\n", canonname, gai_strerror(s));
        return NULL;
    }
    (void)opts;
    
    return (res);
}

// get hostname and dns from ip
int    hostname_lookup(unsigned int ip, char *revhostname)
{
    struct sockaddr_in endpoint;
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = ip;

    ft_bzero(revhostname, 256);
    int ret = getnameinfo((struct sockaddr*)&endpoint, (socklen_t)sizeof(struct sockaddr),
                    revhostname, 1000, 0, 0, NI_NOFQDN);
    // if (ret != 0)
    //     printf("%d: %s\n", ip, gai_strerror(ret));
    return ret;
}