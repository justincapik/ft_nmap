#include "ft_nmap.h"

//void				

struct addrinfo **resolve_ips(char **ips)
{
    struct addrinfo *info;
    struct addrinfo **targets;
    int ips_count;

    for (ips_count = 0; ips[ips_count] != NULL; ++ips_count) ;

    targets = (struct addrinfo**)malloc(sizeof(struct addrinfo *) * (ips_count + 1));
    int count = 0;
    for (int i = 0; ips[i] != NULL; ++i)
    {
        printf("ips[%d] = %s\n", i, ips[i]);
        info = dns_lookup(ips[i]);
        if (info != NULL)
            targets[count++] = info;
        else
            v_err(VBS_NONE, "unable to resolve IP %s\n", ips[i]);
    }
    targets[count] = NULL;

    return targets;
}

opt_t		*parse_opt(int ac, char **av)
{
	opt_t	*opts;

	opts = (opt_t*)malloc(sizeof(opt_t));
	bzero(opts, sizeof(opt_t));

	(void)ac;
	(void)av;

	opts->verbose = VBS_DEBUG;

	opts->scan_types = SYN_SCAN | UDP_SCAN;
	opts->nb_threads = 4; // count, MUST BE MIN 1
	memset(opts->ports, -1, sizeof(int16_t) * MAX_PORT_AMOUNT);
	opts->ports[0] = 80;
	opts->ports[1] = 433;
	opts->ports[2] = 512;
	opts->ports[3] = 1024;
	opts->interface = NULL;
	opts->self_ip = NULL;
	
	char ip[] = "google.com";
	char ip2[] = "facebook.com";
	char ip3[] = "facebook.fr";
	opts->ips = (char**)malloc(sizeof(char*) * 4);
	opts->ips[0] = (char*)malloc(sizeof(char) * (strlen(ip) + 1));
	opts->ips[1] = (char*)malloc(sizeof(char) * (strlen(ip2) + 1));
	opts->ips[2] = (char*)malloc(sizeof(char) * (strlen(ip3) + 1));
	opts->ips[3] = NULL;
	memcpy(opts->ips[0], ip, strlen(ip) + 1);
	memcpy(opts->ips[1], ip2, strlen(ip2) + 1);
	memcpy(opts->ips[2], ip3, strlen(ip3) + 1);
	
    opts->targets = resolve_ips(opts->ips);

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
    for (int i = 0; opts->targets[i] != NULL; ++i)
        freeaddrinfo(opts->targets[i]);
    free(opts->targets);
	
	free(opts);
}