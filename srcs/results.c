#include "ft_nmap.h"

static size_t       scan_count;
static size_t       port_count;
static size_t       ip_count;
static char         **ips;

// list of struct, ordered by ips (opts->targets), then port, then scan type
// ends with ip scan results
// see define to get index
// state=0 means packets hasn't been received, can make a link list or smtg TODO:? 
static results_t        *scan_res;
static pthread_mutex_t  results_mutex;

int             count_scan_nb(int flag)
{
    int     count;

    count = 0;
    for (int i = 0; i < NB_SCAN_TYPES; ++i)
        count += ((SCAN_TYPES[i] & flag) > 0);
    return (count);
}

void            create_results(opt_t *opts)
{
    scan_count = count_scan_nb(opts->scan_types);
    for(ip_count = 0; opts->targets[ip_count] != NULL; ++ip_count) ;
    for(port_count = 0; opts->ports[port_count] != -1 && port_count < 1024; ++port_count) ;

    size_t size = ip_count * port_count * scan_count + ip_count;
    scan_res = (results_t *)malloc(sizeof(results_t) * size);
    bzero(scan_res, sizeof(results_t) * size);

    ips = opts->ips;

    // pthread_mutex_init(&results_mutex);

    fprintf(stderr, "ipcount = %ld, scan_count = %ld, port_count = %ld\n",
        ip_count, scan_count, port_count);
}

void            crude_print_results(void)
{
    //print icmp answers
    for (size_t idx = RSIZE; idx - RSIZE < ip_count; idx++)
    {
        if (scan_res[idx].state == OPEN)
            v_info(VBS_NONE, "%s online (icmp check)\n", ips[idx - RSIZE]);
        else
            v_info(VBS_NONE, "%s offline (icmp check)\n", ips[idx - RSIZE]);
    }

}

void            free_results(void)
{
    free(scan_res);
    pthread_mutex_destroy(&results_mutex);
}

void            results_add_icmp(size_t ip_index)
{
    pthread_mutex_lock(&results_mutex);
    
    scan_res[RSIZE + ip_index].state = OPEN;

    // v_info(VBS_LIGHT, "added found icmp probe (%d)\n", ip_index);

    crude_print_results();
    
    pthread_mutex_unlock(&results_mutex);
}

void            results_add_tcp(size_t ip_index)
{
    v_info(VBS_LIGHT, "found tcp probe (%d)\n", ip_index);
}

void            results_add_udp(size_t ip_index)
{
    v_info(VBS_LIGHT, "found udp probe (%d)\n", ip_index);
}

// void            results_timestamp_packet(size_t ip_idx, size_t scan_idx, size_t port_idx)
// {
//     pthread_mutex_lock(&results_mutex);

    

//     pthread_mutex_unlock(&results_mutex);
// }