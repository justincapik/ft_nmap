#include "ft_nmap.h"

//void				

opt_t		*parse_opt(int ac, char **av)
{
	opt_t	*opts;
	char	*ports_str;
	char	*scan_str;
	char	*ip_str;

	opts = (opt_t*)malloc(sizeof(opt_t));

	printf("init_result: %d\n", init_lib("./config/sample.ntmlp"));
	set_ptr(&ports_str, "-p");
	set_ptr(&scan_str, "-s");
	set_ptr(&ip_str, "--ip");
	set_ptr(&(opts->nb_threads), "--speedup");

	// set_bool_ptr_mask(&mtu, sizeof(char), 0x10, "--mtu");
	printf("parse_result: %d\n", parse(ac, av));
	printf("ports = %s\n", ports_str);
	printf("scans = %s\n", scan_str);
	printf("ip = %s\n", ip_str);
	printf("nb threads = %hhu\n", opts->nb_threads);
	close_lib();



	free(opts);
    return (NULL);
}