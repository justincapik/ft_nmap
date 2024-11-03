#include "ft_nmap.h"

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

void        free_pcap(pcap_v_t *pvars)
{
    if (pvars->alldevsp != NULL)
        pcap_freealldevs(pvars->alldevsp);
    pcap_freecode(&(pvars->fp));
    pcap_close(pvars->source_handle);
    free(pvars);
}

static int8_t          set_filter(pcap_v_t *pvars, opt_t *opts)
{
    char host_str[] = "host ";
    char *filter_str;  // Filter expression

    // TODO: change for multiple IPs
    filter_str = calloc(strlen(host_str) + strlen(opts->ips[0]) + 1, sizeof(char));
    strcpy(filter_str, host_str);
    strcat(filter_str, opts->ips[0]);

    v_info(VBS_DEBUG, "pcap filter string: %s\n", filter_str);

    if (pcap_compile(pvars->source_handle, &(pvars->fp),
            filter_str, 1, pvars->net) < 0) {
        v_err(VBS_NONE, "Couldn't compile filter %s: %s\n",
            filter_str, pcap_geterr(pvars->source_handle));
        free(filter_str);
        return ERROR;
    }

    if (pcap_setfilter(pvars->source_handle, &(pvars->fp)) < 0) {
        v_err(VBS_NONE, "Couldn't set filter %s: %s\n",
            filter_str, pcap_geterr(pvars->source_handle));
        free(filter_str);
        return ERROR;
    }

    free(filter_str);

    return SUCCESS;
}

static pcap_v_t      *get_source_handle(opt_t *opts)
{
    char    errbuf[PCAP_ERRBUF_SIZE];
    int                 dl_type;
    pcap_v_t            *pvars;

    pvars = (pcap_v_t*)malloc(sizeof(pcap_v_t));
    bzero(pvars, sizeof(pcap_v_t));

    if (opts->interface == NULL)
    {
        if (pcap_findalldevs(&(pvars->alldevsp), errbuf) < 0)
        {      
            v_err(VBS_NONE, "pcap_findalldevs failed: %s\n", errbuf);
            return NULL;
        }
        if (pvars->alldevsp == NULL) {
            v_err(VBS_NONE, "No devices found\n");
            pcap_freealldevs(pvars->alldevsp);
            return NULL;
        }
        opts->interface = strdup(pvars->alldevsp->name);
        pcap_freealldevs(pvars->alldevsp); // Free the device list
        pvars->alldevsp = NULL;
    }
    v_info(VBS_LIGHT, "interface: [%s]\n", opts->interface);

    if (pcap_lookupnet(opts->interface, &(pvars->net),
            &(pvars->mask), errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            opts->interface, errbuf);
        pvars->net = PCAP_NETMASK_UNKNOWN;
    }

    pvars->source_handle = pcap_create(opts->interface, errbuf);
    if (pvars->source_handle == NULL) {
        v_err(VBS_NONE, "pcap_create failed: %s\n", errbuf);
        return NULL;
    }

    if (pcap_set_snaplen(pvars->source_handle, BUFSIZ) != 0 ||
        pcap_set_promisc(pvars->source_handle, 1) != 0 ||
        pcap_set_timeout(pvars->source_handle, 0) != 0 ||
        pcap_set_immediate_mode(pvars->source_handle, 1) != 0) {
        v_err(VBS_NONE, "Error setting pcap options: %s\n", pcap_geterr(pvars->source_handle));
        pcap_close(pvars->source_handle);
        return NULL;
    }

    int status = pcap_activate(pvars->source_handle);
    if (status < 0) {
        v_err(VBS_NONE, "pcap_activate failed: %s\n", pcap_geterr(pvars->source_handle));
        free_pcap(pvars);
        return NULL;
    } else if (status > 0) {
        // Warning occurred during activation
        v_info(VBS_NONE, "pcap_activate warning: %s\n", pcap_statustostr(status));
    }

    dl_type = pcap_datalink(pvars->source_handle);
    if (dl_type != 1)
    {
        free_pcap(pvars);
        v_err(VBS_NONE, "datalink = %d, parsing not implemented\n", dl_type);
        return NULL;
    }

    if (set_filter(pvars, opts) < 0)
        return NULL;

    return pvars;
}

void        super_simple_sniffer(opt_t *opts)
{
    pcap_v_t            *pvars;

    if ((pvars = get_source_handle(opts)) == NULL)
        return ;

    pcap_loop(pvars->source_handle, 0, parse_packets, (u_char *)opts);

    free_pcap(pvars);

    // int lim = 10;
    // for (int i = 0; i < lim; ++i)
    // {
    //     pkg_info = NULL; // silence compiler
    //     int ret;
    //     if ((ret = pcap_next_ex(pvars->source_handle, &pkg_info, &raw_data)) != 1)
    //     {
    //         if (ret == -1) {
    //             v_err(VBS_NONE, "pcap_next_ex error: %s\n", pcap_geterr(pvars->source_handle));
    //             break; // Stop capturing on error
    //         } else if (ret == -2) {
    //             v_err(VBS_NONE, "pcap_next_ex reached EOF\n");
    //             break;
    //         } else if (ret == 0) {
    //             v_info(VBS_NONE, "pcap_next_ex timeout occurred\n");
    //             continue;
    //         } else {
    //             v_err(VBS_NONE, "pcap_next_ex unexpected return value (%d): %s\n", ret, pcap_geterr(pvars->source_handle));
    //             continue;
    //         }
    //     }

    //     parse_iphdr(raw_data);
    // }

    // pcap_set_immediate_mode() ?
    // might be a little slow on cpu 
    // but ensures packets arrive right awya and don't
    // build up in buffer

    // TODO: ^ might actually use buffer to avoid thread locking too much 
}
