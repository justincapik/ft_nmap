
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
	
    verbose_set(opts->verbose);

    fprintf(stderr, "scanning ips:\n");
    for (int i = 0; opts->ips[i] != NULL; ++i)
        fprintf(stderr, "\t[%s]\n", opts->ips[i]);
    fprintf(stderr, "ports: ");
    for (int i = 0; opts->ports[i] != -1 && i < MAX_PORT_AMOUNT; ++i)
        fprintf(stderr, "%d ", opts->ports[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "nb threads = %d\n", opts->nb_threads);
    fprintf(stderr, "\n");

    opts = get_local_ip(opts);
    create_results(opts);

    pthread_t sniffer_thread;
    pthread_create(&sniffer_thread, NULL, super_simple_sniffer, (void*)opts);

    usleep(1000 * 100);

    pthread_t provider_thread;
    pthread_create(&provider_thread, NULL, provider, (void*)opts);

    pthread_join(provider_thread, NULL);
    pthread_join(sniffer_thread, NULL);

    results_no_answers();
    crude_print_results(opts);

    free_results();
    free_opts(opts);

    return 0;
}