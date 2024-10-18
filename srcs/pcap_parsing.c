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

void        super_simple_sniffer(void)
{
    char    errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    pcap_t *source_handle;
    struct pcap_pkthdr *pkg_info;

    // To open a handle for a live capture, given the name of the network
    // or other interface on which the capture should be done,
    // call pcap_create(), set the appropriate options on the handle,
    // and then activate it with pcap_activate()

    // pcap_create() returns a pcap_t 
    // which is the handle used for reading packets from the capture stream

    // pcap_lookupdev() will return the first device
    // on that list that is not a ``loopback`` network interface.

    if (pcap_findalldevs(&alldevsp, errbuf) < 0)
    {      
        pcap_freealldevs(alldevsp);
        fprintf(stderr, "pcap_findalldevs failed\n");
    }
    fprintf(stderr, "interface: [%s]\n", alldevsp->name);

    source_handle = pcap_create(alldevsp->name, errbuf);

    pcap_set_immediate_mode(source_handle, 1);

    if (pcap_activate(source_handle) != 0)
    {      
        pcap_freealldevs(alldevsp);
        pcap_close(source_handle);
        fprintf(stderr, "pcap_activate failed\n");
    }

    for (int i = 0; i < 10; ++i)
    {
        // int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
        //      const u_char **pkt_data);

        //const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);

        pkg_info = NULL; // silence compiler
        const u_char *raw_data;
        // crashed here, try putting filters ?
        if (pcap_next_ex(source_handle, &pkg_info, &raw_data) != 1)
            fprintf(stderr, "there's been a terrible mistake\n");
        else
        {
            write(2, raw_data, pkg_info->len);
            write(2, "\n", 1);
        }
    }

    pcap_freealldevs(alldevsp);
    pcap_close(source_handle);


    // pcap_set_immediate_mode() ?
    // might be a little slow on cpu 
    // but ensures packets arrive right awya and don't
    // build up in buffer



    // pcap_close() at the end
}