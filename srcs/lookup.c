#include "ft_nmap.h"

struct addrinfo   *dns_lookup(char *canonname)
{
    // check direction of lookup ?
    struct addrinfo hint;
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_INET;   // IPv4 
    hint.ai_socktype = SOCK_RAW; // configure sent packet header
    hint.ai_flags = AI_CANONNAME | AI_V4MAPPED | AI_ADDRCONFIG;
    hint.ai_protocol = 0; 
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
    
    return (res);
}

opt_t   *get_local_ip(opt_t *opts)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    // Get the list of network interfaces
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // Loop through each interface
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                continue;
            }

            // ignore recursive local network and only get first network
            if (strncmp("lo", ifa->ifa_name, 2) != 0
                && opts->self_ip == NULL)
            {
                if (opts->interface == NULL)
                {
                    opts->interface = (char*)malloc(strlen(ifa->ifa_name) + 1);
                    memcpy(opts->interface, ifa->ifa_name, strlen(ifa->ifa_name) + 1);
                }
                opts->self_ip = (char*)malloc(strlen(host) + 1);
                memcpy(opts->self_ip, host, strlen(host) + 1);
            }
        }
    }

    freeifaddrs(ifaddr);
    printf("Selected Interface: %s\n", opts->interface);
    return (opts); 
}

// get hostname and dns from ip
int    hostname_lookup(unsigned int ip, char *revhostname)
{
    struct sockaddr_in endpoint;
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = ip;

    bzero(revhostname, 256);
    int ret = getnameinfo((struct sockaddr*)&endpoint, (socklen_t)sizeof(struct sockaddr),
                    revhostname, 1000, 0, 0, NI_NOFQDN);
    // if (ret != 0)
    //     printf("%d: %s\n", ip, gai_strerror(ret));
    return ret;
}

