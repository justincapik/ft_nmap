#include "ft_nmap.h"

void    send_probe(uint16_t port, struct sockaddr_in *target,
    uint8_t type, char *self_ip, psm_thread_vars_t *psm_info, uint16_t sport)
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
        .payload = DEFAULT_PAYLOAD "\0",
        .sport = sport,
        .protocol = protocol,
        .flags = flags,
        .self_ip = self_ip,
        .state = DATA_FULL
    };

    // end condition
    if (target == NULL && port == 0 && self_ip == 0)
        psm_opt.state = FINISHED;
    
    // Wait until the buffer is empty
    sem_wait(&(psm_info->sem_empty));

    pthread_mutex_lock(&(psm_info->mutex));
    memcpy((void*)&(shared_packet_data[psm_info->shared_index]),
        &psm_opt, sizeof(psm_opt));
    pthread_mutex_unlock(&(psm_info->mutex));

    // Signal that the buffer is full
    sem_post(&(psm_info->sem_full));
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
        sem_init(&(psm_info[i].sem_empty), 0, 1); 
        sem_init(&(psm_info[i].sem_full), 0, 0); 
        pthread_create(&(psm_info[i].thread), NULL,
            packet_sending_manager, (void*)&(psm_info[i]));
        psm_info[i].shared_index = i;
    }

    return psm_info;
}

static uint8_t *make_scan_list(int flag)
{
    int     count;
    uint8_t *lst;
    int     lst_i;

    count = 0;
    for (int i = 0; i < NB_SCAN_TYPES; ++i)
        count += ((SCAN_TYPES[i] & flag) > 0);
    lst = (uint8_t *)malloc(sizeof(uint8_t) * (count + 1));
    lst_i = 0;
    for (int i = 0; i < NB_SCAN_TYPES; ++i)
        if ((flag & SCAN_TYPES[i]) > 0)
            lst[lst_i++] = SCAN_TYPES[i];
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
            ICMP_SCAN, opts->self_ip, &(psm_info[thread_id]), 0);
        thread_id = (thread_id + 1) % opts->nb_threads;
    } 

    scan_types = make_scan_list(opts->scan_types);

    srand((uint16_t) time(NULL));
    // scan
    // port number
    for (int j = 0; opts->ports[j] != -1 && j < MAX_PORT_AMOUNT; ++j)
    {
        // scan type
        for (int i = 0; scan_types[i] != 0; ++i)
        {
            // ip addr
            for (int k = 0; targets[k] != NULL; ++k)
            {
                uint16_t sport = (uint16_t) (rand() & 0xFFFF);

                results_prepare(k, i, j, sport, opts->ports[j]);

                send_probe(opts->ports[j], (struct sockaddr_in*)targets[k]->ai_addr,
                    scan_types[i], opts->self_ip, &(psm_info[thread_id]), sport);
                v_info(VBS_DEBUG, "sent probe to thread %d\n", thread_id);
                thread_id = (thread_id + 1) % opts->nb_threads;
                if (opts->politness > 0)
                    usleep(1000 * opts->politness + 1);
            }
        }
    }

    v_info(VBS_LIGHT, "Finished sending packets\n");

    // I'm a despicable genius
    sleep(1 * (opts->politness + 1));
    pcap_breakloop(opts->pvars->source_handle);

    // kill threads
    for (int i = 0; i < opts->nb_threads; ++i)
        send_probe(0, NULL, 0, NULL, &(psm_info[i]), 0);

    v_info(VBS_DEBUG, "Left provider\n");

    for (int i = 0; i < opts->nb_threads; ++i)
    {
        pthread_join(psm_info[i].thread, NULL);
        pthread_mutex_destroy(&(psm_info[i].mutex));
        sem_destroy(&(psm_info[i].sem_empty));
        sem_destroy(&(psm_info[i].sem_full));
    }
    free(psm_info);
    free(scan_types);
    free(shared_packet_data);

    return NULL;
}