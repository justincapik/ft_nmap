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

void        super_simple_sniffer(opt_t *opts)
{
    char    errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t           *alldevsp;
    pcap_t              *source_handle;
    struct pcap_pkthdr  *pkg_info;
    int                 dl_type;

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

    dl_type = pcap_datalink(source_handle);
    fprintf(stderr, "datalink = %d\n", dl_type);

    int lim = 10;
    for (int i = 0; i < lim; ++i)
    {
        pkg_info = NULL; // silence compiler
        const u_char *raw_data;
        // crashed here, try putting filters ?
        if (pcap_next_ex(source_handle, &pkg_info, &raw_data) != 1)
        {
            fprintf(stderr, "there's been a terrible mistake\n");
            continue;
        }
        // write(2, raw_data, pkg_info->len);
        // write(2, "\n", 1);

        struct ether_header *eth = (struct ether_header *)raw_data;
        int header_size = ETH_HLEN;
        uint16_t ether_type = ntohs(eth->ether_type);

        if (ether_type == 0x8100) { // VLAN-tagged frame (add 4 bytes)
            fprintf(stderr, "VLAN TAGGED FRAME\n");
            header_size += 4;
        } else if (ether_type == 0x88a8 || ether_type == 0x9100) {
            // Q-in-Q or double VLAN-tagged frame (add 8 bytes)
            fprintf(stderr, "Q in Q or DOUBLE VLAN-TAGGED\n");
            header_size += 8;
        }

        // struct ip *ip_head = (struct ip*)(raw_data+j);

        // char *src_ip = inet_ntoa(ip_head->ip_src);
        // char *dst_ip = inet_ntoa(ip_head->ip_dst);
        // fprintf(stderr, "j = %d - src = %s\n", j, src_ip);
        // fprintf(stderr, "         dst = %s\n", dst_ip);
        // fprintf(stderr, "       hl = %x - v = %x\n", ip_head->ip_hl, ip_head->ip_v);
        
        // ip_head = (struct ip*)(raw_data+j);

        // char *src_ip = inet_ntoa(ip_head->ip_src);
        // char *dst_ip = inet_ntoa(ip_head->ip_dst);
        // char *test_ip = inet_ntoa(*(&(ip_head->ip_dst)+sizeof(struct in_addr)*4));
        // fprintf(stderr, "hl = %x - v = %x\n", ip_head->ip_hl, ip_head->ip_v);
        // fprintf(stderr, "data length = %d\n", ip_head->ip_len);
        // fprintf(stderr, "type of service = %d\n", ip_head->ip_tos);
        // fprintf(stderr, "time to live = %d\n", ip_head->ip_ttl);
        // fprintf(stderr, "fragment offset = %d\n", ip_head->ip_off);
        // fprintf(stderr, "src  = %s\n", src_ip);
        // fprintf(stderr, "dst  = %s\n", dst_ip);
        // fprintf(stderr, "test = %s\n", test_ip);

        // fprintf(stderr, "\n");
    
        struct iphdr *hdr = (struct iphdr*)(raw_data+header_size);
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = hdr->saddr;
        dst_addr.s_addr = hdr->daddr;
        // Allocate separate buffers for source and destination IPs
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        // Copy the IP addresses into the buffers to prevent overwriting
        strncpy(src_ip, inet_ntoa(src_addr), INET_ADDRSTRLEN);
        strncpy(dst_ip, inet_ntoa(dst_addr), INET_ADDRSTRLEN);
        
        fprintf(stderr, "hl = %x - v = %x\n", hdr->ihl, hdr->version);
        fprintf(stderr, "data length = %d\n", hdr->tot_len);
        fprintf(stderr, "type of service = %d\n", hdr->tos);
        fprintf(stderr, "time to live = %d\n", hdr->ttl);
        fprintf(stderr, "fragment offset = %d\n", hdr->frag_off);
        fprintf(stderr, "src  = %s\n", src_ip);
        fprintf(stderr, "dst  = %s\n", dst_ip);
        fprintf(stderr, "\n");
    }

    pcap_freealldevs(alldevsp);
    pcap_close(source_handle);


    // pcap_set_immediate_mode() ?
    // might be a little slow on cpu 
    // but ensures packets arrive right awya and don't
    // build up in buffer

    // TODO: ^ might actually use buffer to avoid thread locking too much 



    // pcap_close() at the end

    (void)opts;
}
