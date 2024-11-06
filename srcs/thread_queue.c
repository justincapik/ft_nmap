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

void    *provider(void *void_opts)
{
    opt_t   *opts = (opt_t *)void_opts;

    struct addrinfo *info;
    struct sockaddr_in *target;
    
    info = dns_lookup(opts->ips[0]);
    if (info == NULL)
        return NULL;
    memset(&target, 0, sizeof(target));
    target = (struct sockaddr_in *)(info->ai_addr);  
    target->sin_family = AF_INET;

    uint16_t port = 80;
    psm_opts_t psm_opt = {
        .target = target,
        .port = port,
        .protocol = IPPROTO_TCP,
        .flags = TCP_SYN,
        .opts = opts,
        .self_ip = opts->self_ip
    };

    // create thread pool TODO:
    pthread_t psm_thread;
    pthread_create(&psm_thread, NULL, packet_sending_manager,
        (void*)&psm_opt /* TODO: */);

    // give queue ressource to thread


    pthread_join(psm_thread, NULL);
    
    psm_opts_t psm_opt2 = {
        .target = target,
        .port = port,
        .protocol = IPPROTO_UDP,
        .flags = TCP_SYN,
        .opts = opts,
        .self_ip = opts->self_ip
    };
    pthread_create(&psm_thread, NULL, packet_sending_manager,
        (void*)&psm_opt2 /* TODO: */);
    pthread_join(psm_thread, NULL);

    return NULL;
}