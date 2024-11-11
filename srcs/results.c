#include "ft_nmap.h"

// https://nmap.org/book/scan-methods-null-fin-xmas-scan.html
// FIN, NULL, and XMAS are very similar, servers respond differently

// https://nmap.org/book/synscan.html
// SYN

// https://nmap.org/book/scan-methods-udp-scan.html
// UDP

// https://nmap.org/book/scan-methods-null-fin-xmas-scan.html
// FIN, NULL, and XMAS are parsed similarily, servers respond differently

// https://nmap.org/book/scan-methods-ack-scan.html
// ACK

// List of packets to listen for:
// - ICMP error (type 3, codes 1, 2, **+-3**, 9, 10, 13)
// - TCP RST
// - TCP SYN/ACK
// - UDP (unusual)

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

    printf("size = %ld\n", size);
    scan_res = (results_t *)malloc(sizeof(results_t) * size);
    bzero(scan_res, sizeof(results_t) * size);

    ips = opts->ips;

    pthread_mutex_init(&results_mutex, NULL);

    fprintf(stderr, "ipcount = %ld, scan_count = %ld, port_count = %ld\n",
        ip_count, scan_count, port_count);
}

// for scan binary mask
int co_sh(uint8_t n) {
    int count = 0;
    while (n > 1) {
        n >>= 1;
        count++;
    }
    return count; 
}

void            crude_print_results(opt_t *opts)
{
    char    *scan_names[] = { "SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};
    uint8_t *scan_lst;

    scan_lst = make_scan_list(opts->scan_types);

    // iterate through ips
    for (size_t ip_idx = 0; ip_idx < ip_count; ip_idx++)
    {
        v_info(VBS_NONE, "\n");
        if (scan_res[ip_idx + RSIZE].state == OPEN)
            v_info(VBS_NONE, "%s - online (icmp check)\n", ips[ip_idx],  "");
        else
            v_info(VBS_NONE, "%s - offline (icmp check)\n", ips[ip_idx],  "");
        v_info(VBS_NONE, "------------------------------------------\n");
        v_info(VBS_NONE, "PORT          SERVICE         STATE\n");
        v_info(VBS_NONE, "------------------------------------------\n");

        for (size_t port_idx = 0; port_idx < port_count; port_idx++)
        {
            for (size_t scan_idx = 0; scan_lst[scan_idx] != 0; scan_idx++)
            {
                v_info(VBS_NONE, "% 5hd % 13s % 10s(%hd)\n",
                    opts->ports[port_idx],
                    scan_res[RIDX(ip_idx, port_idx, scan_idx)].service,
                    scan_names[co_sh(scan_lst[scan_idx])],
                    scan_res[RIDX(ip_idx, port_idx, scan_idx)].state);
            }
        }
    }

    free(scan_lst);
}

void            free_results(void)
{
    for (size_t ip_idx = 0; ip_idx < ip_count; ip_idx++)
        for (size_t port_idx = 0; port_idx < port_count; port_idx++)
            for (size_t scan_idx = 0; scan_idx < scan_count; scan_idx++)
                free(scan_res[RIDX(ip_idx, port_idx, scan_idx)].service);

    free(scan_res);
    pthread_mutex_destroy(&results_mutex);
}

void            results_add_icmp(size_t ip_index)
{
    pthread_mutex_lock(&results_mutex);
    
    scan_res[RSIZE + ip_index].state = OPEN;
    
    v_info(VBS_DEBUG, "found tcp probe (%d)\n", ip_index);
    
    pthread_mutex_unlock(&results_mutex);
}

void            results_add_tcp(size_t ip_index)
{
    pthread_mutex_lock(&results_mutex);
    
    // scan_res[RIDX(ip_index, )]

    v_info(VBS_DEBUG, "found tcp probe (%d)\n", ip_index);
    
    pthread_mutex_unlock(&results_mutex);
}

void            results_add_udp(size_t ip_index)
{
    pthread_mutex_lock(&results_mutex);
    
    v_info(VBS_DEBUG, "found udp probe (%d)\n", ip_index);
    
    pthread_mutex_unlock(&results_mutex);
}

void            results_prepare(size_t ip_idx, size_t scan_idx, size_t port_idx,
                    uint16_t sport, uint16_t dport)
{
    pthread_mutex_lock(&results_mutex);
    
    struct servent *service;
    service = getservbyport(htons(dport), NULL);

    scan_res[RIDX(ip_idx, port_idx, scan_idx)].state = 0;
    if (service)
        scan_res[RIDX(ip_idx, port_idx, scan_idx)].service = strdup(service->s_name);
    else
        scan_res[RIDX(ip_idx, port_idx, scan_idx)].service = strdup("unknown");
    scan_res[RIDX(ip_idx, port_idx, scan_idx)].sport = sport;

    pthread_mutex_unlock(&results_mutex);
}