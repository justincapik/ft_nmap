#include "ft_nmap.h"

//void				

opt_t		*parse_opt(int ac, char **av)
{
	opt_t	*opts;
	// char	*ports_str;
	// char	*scan_str;
	// char	*ip_str;
	// char	*thread_nb;

	opts = (opt_t*)malloc(sizeof(opt_t));

	// printf("init_result: %d\n", init_lib("./config/nmap.ntmlp"));
	// set_string_ptr(&ports_str, "-p");
	// set_string_ptr(&scan_str, "-s");
	// set_string_ptr(&ip_str, "--ip");
	// set_string_ptr(&thread_nb, "--speedup");

	// // set_bool_ptr_mask(&mtu, sizeof(char), 0x10, "--mtu");
	// printf("parse_result: %d\n", parse(ac, av));
	// printf("ports = %s\n", ports_str);
	// printf("scans = %s\n", scan_str);
	// printf("ip = %s\n", ip_str);
	// printf("nb threads = %s\n", thread_nb);
	// close_lib();

	// free(opts);

	(void)ac;
	(void)av;

	opts->scan_types = SYN_SCAN;
	opts->nb_threads = 1;
	memset(opts->ports, -1, sizeof(int16_t) * MAX_PORT_AMOUNT);
	opts->ports[0] = 22;
	opts->verbose = TRUE;
	
	char ip[] = "google.com";
	opts->ips = (char**)malloc(sizeof(char*) * 2);
	opts->ips[0] = (char*)malloc(sizeof(char) * (strlen(ip) + 1));
	opts->ips[1] = NULL;
	memcpy(opts->ips[0], ip, strlen(ip) + 1);

    return (opts);
}

void	free_opts(opt_t *opts)
{
	for (int i = 0; opts->ips[i] != NULL; ++i)
		free(opts->ips[i]);
	free(opts->ips);
	free(opts);
}