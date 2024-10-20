
#include "ft_nmap.h"

int main(int ac, char **av) {
    // char *device;
    // char ip[13];
    // char subnet_mask[13];
    // bpf_u_int32 ip_raw; /* IP address as integer */
    // bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
    // int lookup_return_code;
    // char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    // struct in_addr address; /* Used for both ip & subnet */

    opt_t   *opts;

    opts = parse_opt(ac, av); 

    fprintf(stderr, "scanned ips:\n");
    for (int i = 0; opts->ips[i] != NULL; ++i)
        fprintf(stderr, "\t[%s]\n", opts->ips[i]);
    fprintf(stderr, "nb threads = %d\n", opts->nb_threads);
    fprintf(stderr, "Scan type: ");
    for (int i = 0; i < NB_SCAN_TYPES; ++i)
        if ((opts->scan_types & SCAN_TYPES[i]) > 0)
            fprintf(stderr, " 0x%x", SCAN_TYPES[i]);
    fprintf(stderr, "\n");


    super_simple_sniffer();



    free_opts(opts);

    /* Find a device */
    // device = pcap_lookupdev(error_buffer);
    // if (device == NULL) {
    //     printf("%s\n", error_buffer);
    //     return 1;
    // }
    
    // /* Get device info */
    // lookup_return_code = pcap_lookupnet(
    //     device,
    //     &ip_raw,
    //     &subnet_mask_raw,
    //     error_buffer
    // );
    // if (lookup_return_code == -1) {
    //     printf("%s\n", error_buffer);
    //     return 1;
    // }

    // /*
    // If you call inet_ntoa() more than once
    // you will overwrite the buffer. If we only stored
    // the pointer to the string returned by inet_ntoa(),
    // and then we call it again later for the subnet mask,
    // our first pointer (ip address) will actually have
    // the contents of the subnet mask. That is why we are
    // using a string copy to grab the contents while it is fresh.
    // The pointer returned by inet_ntoa() is always the same.

    // This is from the man:
    // The inet_ntoa() function converts the Internet host address in,
    // given in network byte order, to a string in IPv4 dotted-decimal
    // notation. The string is returned in a statically allocated
    // buffer, which subsequent calls will overwrite. 
    // */

    // /* Get ip in human readable form */
    // address.s_addr = ip_raw;
    // strcpy(ip, inet_ntoa(address));
    // if (ip == NULL) {
    //     perror("inet_ntoa"); /* print error */
    //     return 1;
    // }
    
    // /* Get subnet mask in human readable form */
    // address.s_addr = subnet_mask_raw;
    // strcpy(subnet_mask, inet_ntoa(address));
    // if (subnet_mask == NULL) {
    //     perror("inet_ntoa");
    //     return 1;
    // }

    // printf("Device: %s\n", device);
    // printf("IP address: %s\n", ip);
    // printf("Subnet mask: %s\n", subnet_mask);

    return 0;
}