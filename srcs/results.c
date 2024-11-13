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

// if you're looking to hire me pease don't look at these variables
// this file, along with answer_logic and packet_parsing were written in the span of two days
// and a sleepless night
static size_t       scan_count;
static size_t       port_count;
static size_t       ip_count;
static char         **ips;
static uint16_t     ports[MAX_PORT_AMOUNT];
static uint8_t      scan_lst[NB_SCAN_TYPES];

// list of struct, ordered by ips (opts->targets), then port, then scan type
// ends with ip scan results
// see define to get index
static results_t        *scan_res;
static pthread_mutex_t  results_mutex;

void        make_scan_list(int flag)
{
    int     count;
    int     lst_i;

    count = 0;
    for (int i = 0; i < NB_SCAN_TYPES; ++i)
        count += ((SCAN_TYPES[i] & flag) > 0);
    lst_i = 0;
    for (int i = 0; i < NB_SCAN_TYPES; ++i)
        if ((flag & SCAN_TYPES[i]) > 0)
            scan_lst[lst_i++] = SCAN_TYPES[i];
    if (count < NB_SCAN_TYPES)
        scan_lst[count] = 0;
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
    for(port_count = 0; opts->ports[port_count] != -1 && port_count < MAX_PORT_AMOUNT; ++port_count)
        ports[port_count] = opts->ports[port_count];
    if (port_count < MAX_PORT_AMOUNT)
        ports[port_count] = -1;

    size_t size = ip_count * port_count * scan_count + ip_count;

    scan_res = (results_t *)malloc(sizeof(results_t) * size);
    bzero(scan_res, sizeof(results_t) * size);

    make_scan_list(opts->scan_types);

    ips = opts->ips;

    pthread_mutex_init(&results_mutex, NULL);

    // fprintf(stderr, "ipcount = %ld, scan_count = %ld, port_count = %ld\n",
    //     ip_count, scan_count, port_count);
}

// for scan names binary mask
static int co_sh(uint8_t n) {
    int count = 0;
    while (n > 1) {
        n >>= 1;
        count++;
    }
    return count; 
}

void            crude_print_results(opt_t *opts)
{
    char    *scan_names[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};
    char    *port_states[] = {"NULL", "filtered", "open|filtered",
                                "unfiltered", "closed", "open"};

    for (size_t ip_idx = 0; ip_idx < ip_count; ip_idx++)
    {
        v_info(VBS_NONE, "\n");
        if (scan_res[ip_idx + RSIZE].state == OPEN)
            v_info(VBS_NONE, "%s - online (icmp check)\n", ips[ip_idx],  "");
        else
            v_info(VBS_NONE, "%s - offline (icmp check)\n", ips[ip_idx],  "");
        v_info(VBS_NONE, "------------------------------------------");
        for (size_t scan_idx = 0; scan_idx < NB_SCAN_TYPES && scan_lst[scan_idx] != 0; scan_idx++)
            v_info(VBS_NONE, "------------");
        v_info(VBS_NONE, "\n");
        v_info(VBS_NONE, "PORT          SERVICE         STATE\n");
        v_info(VBS_NONE, "------------------------------------------");
        for (size_t scan_idx = 0; scan_idx < NB_SCAN_TYPES && scan_lst[scan_idx] != 0; scan_idx++)
            v_info(VBS_NONE, "------------");
        v_info(VBS_NONE, "\n");

        for (size_t port_idx = 0; port_idx < port_count; port_idx++)
        {
            bool has_open_or_unfiltered = false; 

            for (size_t scan_idx = 0; scan_idx < NB_SCAN_TYPES && scan_lst[scan_idx] != 0; scan_idx++)
            {
                if (scan_res[RIDX(ip_idx, port_idx, scan_idx)].state != CLOSED 
                    && scan_res[RIDX(ip_idx, port_idx, scan_idx)].state != OPEN_FILTERED 
                    && scan_res[RIDX(ip_idx, port_idx, scan_idx)].state != FILTERED 
                    && scan_res[RIDX(ip_idx, port_idx, scan_idx)].state != UNFILTERED)
                {
                    has_open_or_unfiltered = true;
                    break;
                }
            }

            if (!opts->show_all_res && !has_open_or_unfiltered)
                continue; 

            v_info(VBS_NONE, "% 5hd % 15s % 6s",
                opts->ports[port_idx],
                scan_res[RIDX(ip_idx, port_idx, 0)].service,
                "");

            for (size_t scan_idx = 0; scan_idx < NB_SCAN_TYPES && scan_lst[scan_idx] != 0; scan_idx++)
            {
                if (opts->show_all_res || 
                    (scan_res[RIDX(ip_idx, port_idx, scan_idx)].state != CLOSED
                    && scan_res[RIDX(ip_idx, port_idx, scan_idx)].state != OPEN_FILTERED
                    && scan_res[RIDX(ip_idx, port_idx, scan_idx)].state != FILTERED
                    && scan_res[RIDX(ip_idx, port_idx, scan_idx)].state != UNFILTERED))
                {
                    v_info(VBS_NONE, "%s(%s) ", scan_names[co_sh(scan_lst[scan_idx])],
                        port_states[scan_res[RIDX(ip_idx, port_idx, scan_idx)].state]);
                }
            }

            v_info(VBS_NONE, "\n");
        }

    }

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
    
    v_info(VBS_DEBUG, "found icmp probe (%d)\n", ip_index);
    
    pthread_mutex_unlock(&results_mutex);
}

void            results_add_info(size_t ip_index, uint16_t sport, uint16_t dport,
                    uint8_t answer)
{
    pthread_mutex_lock(&results_mutex);

    uint16_t port_idx;

    for (port_idx = 0; ports[port_idx] != sport && port_idx < MAX_PORT_AMOUNT; ++port_idx)
        ;
    if (port_idx >= MAX_PORT_AMOUNT)
    {

        printf("Something went horribly wrong, port version\n");
        printf("sport = %d, dport = %d\n", sport, dport);
    }
    for (uint8_t scan_idx = 0; scan_idx < scan_count; scan_idx++)
        if (scan_res[RIDX(ip_index, port_idx, scan_idx)].sport == dport)
            scan_res[RIDX(ip_index, port_idx, scan_idx)].state = scan_logic(scan_lst[scan_idx], answer);
    v_info(VBS_DEBUG, "found answer probe (%d)\n", ip_index);
    
    pthread_mutex_unlock(&results_mutex);
}

// TODO: final pass on results for unanswered packets
void            results_no_answers(void)
{
    for (size_t ip_idx = 0; ip_idx < ip_count; ip_idx++)
        for (size_t port_idx = 0; port_idx < port_count; port_idx++)
            for (size_t scan_idx = 0; scan_idx < scan_count; scan_idx++)
                if (scan_res[RIDX(ip_idx, port_idx, scan_idx)].state == 0)
                    scan_res[RIDX(ip_idx, port_idx, scan_idx)].state = no_response_logic(scan_lst[scan_idx]);
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