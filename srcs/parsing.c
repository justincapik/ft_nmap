#include "ft_nmap.h"

//void				

opt_t		*parse_opt(int ac, char **av)
{
	opt_t	*opts;

	opts = (opt_t*)malloc(sizeof(opt_t));
	bzero(opts, sizeof(opt_t));

	
	opts->verbose = VBS_DEBUG;

	opts->scan_types = SYN_SCAN;
	opts->nb_threads = 1;
	memset(opts->ports, -1, sizeof(int16_t) * MAX_PORT_AMOUNT);
	opts->ports[0] = 22;
	opts->interface = NULL;
	opts->self_ip = NULL;
	
	char ip[] = "google.com";
	opts->ips = (char**)malloc(sizeof(char*) * 2);
	opts->ips[0] = (char*)malloc(sizeof(char) * (strlen(ip) + 1));
	opts->ips[1] = NULL;
	memcpy(opts->ips[0], ip, strlen(ip) + 1);
	

    return (opts);
}

void	free_opts(opt_t *opts)
{
	if (opts->ips != NULL)
	{
		for (int i = 0; opts->ips[i] != NULL; ++i)
			free(opts->ips[i]);
		free(opts->ips);
	}
	if (opts->interface != NULL)
		free(opts->interface);
	if (opts->self_ip != NULL)
		free(opts->self_ip);
	free(opts);
}