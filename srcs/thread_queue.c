#include "ft_nmap.h"

// create_queue ()

// execute_queue ()
//      send out queue packets to threads
//      TODO way later throddle sending based on rec values

// exec_thread ()
//  doesn't close until end of program
//  while (packets not all sent)
//      asks for packet to send
//      for (max_retries or pack received)
//          send packet
//          while (check rec queue every n msec)
//              ;
//  exit when no more packets to sen 

// reading_?thread? ()
//

void    scan_port(uint16_t port, struct sockaddr_in *targets, scan_type_e type)
{
    u_char  protocol;
    uint8_t flags;

    if (type == ICMP_SCAN)
        protocol = IPPROTO_ICMP;
    else if (type == UDP_SCAN)
        protocol = IPPROTO_UDP;
    else /* TCP scan of some type, see flags*/
    {
        protocol = IPPROTO_TCP;
        if (type == SYN_SCAN)
            flags = TCP_SYN;
        else if (type == NULL_SCAN) 
            flags = 0;
        else if (type == ACK_SCAN) 
            flags = TCP_ACK;
        else if (type == FIN_SCAN)
            flags = TCP_FIN;
        else if (type == XMAS_SCAN)
            flags = TCP_FIN | TCP_PUSH | TCP_URG;
    }
    
    psm_opts_t psm_opt = {
        .targets = targets,
        .port = port,
        .protocol = protocol,
        .flags = flags,
        .opts = opts,
    };

    // somehow send psm_opt to thread

}

struct sockaddr_in *resolve_ips(char **ips)
{
    struct addrinfo *info;
    struct sockaddr_in *targets;
    int ips_count;

    for (ips_count = 0; ips[ips_count] != NULL; ++ips_count) ;

    targets = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in) * (ips_count + 1));
    int count = 0;
    for (int i = 0; ips[i] != NULL; ++i)
    {
        info = dns_lookup(ips[i]);
        if (info != NULL)
            targets[count++] = (struct sockaddr_in *)(info->ai_addr);
        else
            v_err(VBS_NONE, "unable to resolve IP %s\n", ips[i]);
    }
    targets[count] = NULL;

    return targets;
}

void    *provider(void *void_opts)
{
    opt_t   *opts = (opt_t *)void_opts;

    struct addrinfo *info;
    struct sockaddr_in *targets;

    // lookup for ip
    targets = resolve_ips(opts->ips);

    // create thread
    // malloc thread table
    for
    pthread_t psm_thread;
    pthread_create(&psm_thread, NULL, packet_sending_manager, (void*)&tp_mutex[i]);

    // host check if they're up

    // scan
    // scan type
    for (int i = 0; i < )
    {
        // port number
        for (int j = 0; opts->port[j] != -1 && j < 1024; ++j)
        {
            // ip addr
            for (int k = 0; targets[i] != NULL; ++k)
            {
                scan_port(smtg scan type, port, )
            }
            // also read results table to dermine what needs to be resent
            // from the sent timestamps
            // resend all those that need to be resent
            // do this in anotehr thread ? probably not 
        }

    }

    // give queue ressource to thread


    pthread_join(psm_thread, NULL);

    free(targets);

    return NULL;
}