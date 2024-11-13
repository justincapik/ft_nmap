#include "ft_nmap.h"

// for scan names binary mask
static int co_sh(uint8_t n) {
    int count = 0;
    while (n > 1) {
        n >>= 1;
        count++;
    }
    return count; 
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

void    print_opts(opt_t *opts)
{
    char    *scan_names[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};
    uint8_t *scan_lst = make_scan_list(opts->scan_types);

    fprintf(stderr, "scanning ips:\n");
    for (int i = 0; opts->ips[i] != NULL; ++i)
        fprintf(stderr, "\t[%s]\n", opts->ips[i]);
    int i = 0;
    for (i = 0; opts->ports[i] != -1 && i < MAX_PORT_AMOUNT; ++i);
    fprintf(stderr, "port amount: %d\n", i);

    fprintf(stderr, "speedup: %d\n", opts->nb_threads);

    fprintf(stderr, "scan: ");
    for (int i = 0; scan_lst[i] != 0; ++i)
        fprintf(stderr, "%s ", scan_names[co_sh(scan_lst[i])]);
    fprintf(stderr, "\n");
    
    free(scan_lst);
}

int main(int ac, char **av) {
    opt_t       *opts;
    struct      timeval start, end;
    double      elapsed_time;
    pthread_t   sniffer_thread;
    pthread_t   provider_thread;

    gettimeofday(&start, NULL);

    if ((opts = parse_opt(ac, av)) == NULL)
        return 1; 

    if (opts->targets == NULL || opts->targets[0] == NULL)
    {
        v_err(VBS_NONE, "Err: No valid ips to scan\n");
        free_opts(opts);
        return 1;
    }
    if (opts->scan_types == 0)
    {
        v_err(VBS_NONE, "Err: No valid scan type\n");
        free_opts(opts);
        return 1;
    }

    verbose_set(opts->verbose);

    print_opts(opts);

    if ((opts = get_local_ip(opts)) == NULL)
    {
        free_opts(opts);
        return 1;
    }
    create_results(opts);
    
    v_info(VBS_NONE, "Scanning...\n");

    pthread_create(&sniffer_thread, NULL, super_simple_sniffer, (void*)opts);

    usleep(1000 * 100);

    pthread_create(&provider_thread, NULL, provider, (void*)opts);

    pthread_join(provider_thread, NULL);
    pthread_join(sniffer_thread, NULL);

    results_no_answers();
    crude_print_results(opts);

    free_results();
    free_opts(opts);

    gettimeofday(&end, NULL);
    elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("Time taken: %.2f seconds\n", elapsed_time);

    return 0;
}