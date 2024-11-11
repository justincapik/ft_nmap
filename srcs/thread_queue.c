#include "ft_nmap.h"

void    send_probe(uint16_t port, struct sockaddr_in *target,
    uint8_t type, char *self_ip, psm_thread_vars_t *psm_info)
{
    u_char          protocol;
    uint8_t         flags;

    if (type == ICMP_SCAN)
        protocol = IPPROTO_ICMP;
    else if (type == UDP_SCAN)
        protocol = IPPROTO_UDP;
    else /* TCP scan of some type, see flags */
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
        .target = target,
        .port = port,
        // .payload = "\xef\xbe\xad\xde\xef\xbe\xad\xde" "\0",
        .payload = "\xde\xad\xbe\xef\xde\xad\xbe\xef" "\0",
        .protocol = protocol,
        .flags = flags,
        .self_ip = self_ip,
        .state = DATA_FULL
    };

    // end condition
    if (target == NULL && port == 0 && self_ip == 0)
    {
        fprintf(stderr, "finishing\n");
        psm_opt.state = FINISHED;
    }
    while (1)
    {
        if (shared_packet_data[psm_info->shared_index].state != DATA_FULL)
        {
            // somehow send psm_opt to thread
            pthread_mutex_lock(&(psm_info->mutex));
            memcpy((void*)&(shared_packet_data[psm_info->shared_index]),
                &psm_opt, sizeof(psm_opt));
            pthread_mutex_unlock(&(psm_info->mutex));
            break;
        }
    }
}

psm_thread_vars_t *init_thread_vars(uint8_t nb_threads)
{
    // create thread
    // malloc thread table
    psm_thread_vars_t *psm_info;
    psm_info = (psm_thread_vars_t *)malloc(sizeof(psm_thread_vars_t) * (nb_threads + 1));
    
    // global
    shared_packet_data = (psm_opts_t *)malloc(sizeof(psm_opts_t) * nb_threads);
    bzero(shared_packet_data, sizeof(psm_opts_t) * nb_threads);

    for (int i = 0; i < nb_threads; ++i)
    {
        pthread_mutex_init(&(psm_info[i].mutex), NULL);
        pthread_create(&(psm_info[i].thread), NULL,
            packet_sending_manager, (void*)&(psm_info[i]));
        psm_info[i].shared_index = 0;
    }

    return psm_info;
}

uint8_t *make_scan_list(int flag)
{
    int     count;
    uint8_t *lst;

    count = 0;
    for (int i = 0; i < NB_SCAN_TYPES; ++i)
        count += ((SCAN_TYPES[i] & flag) > 0);
    lst = (uint8_t *)malloc(sizeof(uint8_t) * (count + 1));
    for (int i = 0; i < NB_SCAN_TYPES; ++i)
        if ((flag & SCAN_TYPES[i]) > 0)
            lst[i] = SCAN_TYPES[i];
    lst[count] = 0;
    return (lst);
}

void    *provider(void *void_opts)
{
    struct addrinfo     **targets; //pointer list
    psm_thread_vars_t   *psm_info;
    opt_t               *opts = (opt_t *)void_opts;
    uint8_t             *scan_types;
    uint8_t             thread_id;

    // lookup for ip
    targets = opts->targets;

    // create thread pool
    psm_info = init_thread_vars(opts->nb_threads);

    thread_id = 0;
    
    // host check if they're up
    // results are added to results table
    for (int i = 0; targets[i] != NULL; ++i)
    {
        send_probe(0, (struct sockaddr_in*)targets[i]->ai_addr,
            ICMP_SCAN, opts->self_ip, &(psm_info[thread_id]));
        thread_id = (thread_id + 1) % opts->nb_threads;
    } 


    // TODO: check scan types are valid
    scan_types = make_scan_list(opts->scan_types);
    
    // scan
    // port number
    for (int j = 0; opts->ports[j] != -1 && j < 1024; ++j)
    {
        // scan type
        for (int i = 0; scan_types[i] != 0; ++i)
        {
            // ip addr
            for (int k = 0; targets[k] != NULL; ++k)
            {
                // printf("probe: p=%d st=%d t=%s\n",
                //     opts->ports[j], scan_types[i], opts->ips[k]);
                send_probe(opts->ports[j], (struct sockaddr_in*)targets[k]->ai_addr,
                    scan_types[i], opts->self_ip, &(psm_info[thread_id]));
                thread_id = (thread_id + 1) % opts->nb_threads;
            
                // results_timestamp_packet(k, i, j);
            }
            // also read results table to dermine what needs to be resent
            // from the sent timestamps
            // resend all those that need to be resent
            // do this in anotehr thread ? probably not 
        }
    }

    // I'm a despicable genius
    sleep(1);
    pcap_breakloop(opts->pvars->source_handle);

    // kill threads
    for (int i = 0; i < opts->nb_threads; ++i)
        send_probe(0, NULL, 0, NULL, &(psm_info[i]));

    v_info(VBS_LIGHT, "left provider\n");

    for (int i = 0; i < opts->nb_threads; ++i)
    {
        pthread_join(psm_info[i].thread, NULL);
        pthread_mutex_destroy(&(psm_info[i].mutex));
    }
    free(psm_info);
    free(scan_types);

    return NULL;
}