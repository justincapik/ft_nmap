#include "ft_nmap.h"

//void				

struct addrinfo **resolve_ips(char **ips)
{
    struct addrinfo *info;
    struct addrinfo **targets;
    int ips_count;

	if (ips == NULL)
		return NULL;

    for (ips_count = 0; ips[ips_count] != NULL; ips_count++)
		;

    targets = (struct addrinfo**)malloc(sizeof(struct addrinfo *) * (ips_count + 1));
    int count = 0;
    for (int i = 0; ips[i] != NULL; ++i)
    {
        info = dns_lookup(ips[i]);
        if (info != NULL)
            targets[count++] = info;
        else
            v_err(VBS_NONE, "unable to resolve IP %s\n", ips[i]);
    }
    targets[count] = NULL;

    return targets;
}

opt_t		*err(char *msg, opt_t *opts)
{
	v_err(VBS_NONE, msg);
	free_opts(opts);
	return NULL;
}

int is_valid_port(char *str) {
    char *endptr;
    long val = strtol(str, &endptr, 10);
    
	if (*endptr != '\0' || val < 0 || val > SHRT_MAX) {
        return 0;
    }
    return 1;
}

bool parse_ports(char *arg, opt_t *opts) {
	char		*hyphen;
	char		*start_str;
	char		*end_str;
	char		*token = strtok(arg, ",");
	uint16_t	port_idx = 0; 

    while (token)
	{
		// split first by comma
        hyphen = strchr(token, '-');
        if (hyphen) {
            // split on the hyphen
            *hyphen = '\0';
            start_str = token;
            end_str = hyphen + 1;

            if (!is_valid_port(start_str) || !is_valid_port(end_str))
			{
                fprintf(stderr, "Invalid port range: %s-%s\n", start_str, end_str);
                return false;
            }

            int start_port = atoi(start_str);
            int end_port = atoi(end_str);
            if (start_port > end_port)
			{
                fprintf(stderr, "Invalid range (start > end): %d-%d\n", start_port, end_port);
                return false;
            }

            for (int i = start_port; i <= end_port; i++)
			{
				opts->ports[port_idx++] = i;
				if (port_idx >= MAX_PORT_AMOUNT)
				{
					v_info(VBS_NONE, "Warning: cutting off port range.\n");
					return true;
				}         
			}
        }
		else
		{
            if (!is_valid_port(token))
			{
                fprintf(stderr, "Invalid port: %s\n", token);
                return false;
            }
			opts->ports[port_idx++] = atoi(token);
			if (port_idx >= MAX_PORT_AMOUNT)
			{
				v_info(VBS_NONE, "Warning: cutting off port range.\n");
				return true;
			}         
        }
        token = strtok(NULL, ",");
    }

	return true;
}

opt_t		*parse_opt(int ac, char **av)
{
	opt_t	*opts;
	char usage[] =
"Usage\n\
    ft_nmap  [--help] [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER]] [--scan [TYPE]]\n\n\
Options:\n\
  --ip           specify single target ip\n\
  --scan         specify scan type(s)\n\
  --speedup      specify number of threads for optimization\n\
  --ports        specify ports: either seperated by comma (,) for iteration or tilde (-) for a range\n\
  --file         specify file namewith list of target ips\n\
  --polite       specify politness, from 0 to 10\n\
  --show_all     show full scan results\n\
  --help         show this menu\n";


	opts = (opt_t*)malloc(sizeof(opt_t));
	bzero(opts, sizeof(opt_t));

	opts->verbose = VBS_NONE;

	opts->scan_types = 0;
	opts->nb_threads = 250; // count, MUST BE MIN 1
	opts->ips = NULL;
	memset(opts->ports, -1, sizeof(int16_t) * MAX_PORT_AMOUNT);
	opts->politness = 1;
	opts->interface = NULL;
	opts->self_ip = NULL;
	opts->show_all_res = false;

	for (int i = 1; i < ac; ++i)
	{
		if ((strcmp(av[i], "-s") == 0 || strcmp(av[i], "--speedup") == 0) && i + 1 < ac)
		{
			int tmp = atoi(av[i + 1]);
			if (tmp < 0 || tmp > 250)
				return err("Speedup value should be between 0 and 250\n", opts);
			if (tmp == 0)
				++tmp;
			opts->nb_threads = tmp;
			++i;
		}
		else if (strcmp(av[i], "--ip") == 0 && i + 1 < ac)
		{
			if (opts->ips != NULL)
				return err("Only one ip definition allowed, use file for multiple definition\n", opts);
			opts->ips = (char**)malloc(sizeof(char*) * 2);
			opts->ips[0] = strdup(av[i + 1]);
			opts->ips[1] = NULL;
			++i;
		}
		else if (strcmp(av[i], "--scan") == 0 && i + 1 < ac)
		{
			if (strcmp(av[i + 1], "SYN") == 0)
				opts->scan_types |= SYN_SCAN; 
			else if (strcmp(av[i + 1], "NULL") == 0)
				opts->scan_types |= NULL_SCAN; 
			else if (strcmp(av[i + 1], "ACK") == 0)
				opts->scan_types |= ACK_SCAN; 
			else if (strcmp(av[i + 1], "FIN") == 0)
				opts->scan_types |= FIN_SCAN; 
			else if (strcmp(av[i + 1], "XMAS") == 0)
				opts->scan_types |= XMAS_SCAN; 
			else if (strcmp(av[i + 1], "UDP") == 0)
				opts->scan_types |= UDP_SCAN;
			else
				return err("Invalid scan type\n", opts); 
			++i;
		}
		else if ((strcmp(av[i], "--file") == 0) && i + 1 < ac)
		{
			opts->ips = get_file(av[i+1]);
			int j = 0;
			while (opts->ips != NULL && opts->ips[j] != NULL) {
				printf("%s\n", opts->ips[j]);
				j++;
			}
			++i;
			printf("===========================FIN===========================\n");
		}
		else if ((strcmp(av[i], "-p") == 0 || strcmp(av[i], "--port") == 0) && i + 1 < ac)
		{
			++i;
			if (parse_ports(av[i], opts) == false)
				return err("", opts);
		}
		else if ((strcmp(av[i], "--polite") == 0) && i + 1 < ac)
		{
			int tmp = atoi(av[i + 1]);
			if (tmp < 0 || tmp > 10)
				return err("Politness value should be between 0 and 10\n", opts);
			if (tmp == 0)
				++tmp;
			opts->politness = tmp;
			++i;
		}
		else if (strcmp(av[i], "--show_all") == 0)
			opts->show_all_res = true;
		else if (strcmp(av[i], "--help") == 0 || strcmp(av[i], "-h") == 0)
		{
			v_info(VBS_NONE, usage);
			free_opts(opts);
			return NULL;
		}
		else
			return err("Invalide argument\n", opts);
	}

	// default values
	if (opts->scan_types == 0)
		opts->scan_types = SYN_SCAN | NULL_SCAN | ACK_SCAN | FIN_SCAN | XMAS_SCAN | UDP_SCAN;
	if (opts->ports[0] == -1)
		for (int i = 0; i < MAX_PORT_AMOUNT; ++i)
			opts->ports[i] = i;

	// for ease of use later in code, define only valid ips with dns registry
	if ((opts->targets = resolve_ips(opts->ips)) == NULL)
		return err("No ip given\n", opts);

    return (opts);
}

void free_opts(opt_t *opts) {
    if (opts == NULL)
        return;

    if (opts->ips != NULL) {
        for (int i = 0; opts->ips[i] != NULL; ++i)
            free(opts->ips[i]);
        free(opts->ips);
    }
    if (opts->interface != NULL)
        free(opts->interface);
    if (opts->self_ip != NULL)
        free(opts->self_ip);
    if (opts->targets != NULL) {
        for (int i = 0; opts->targets[i] != NULL; ++i)
            freeaddrinfo(opts->targets[i]);
        free(opts->targets);
    }
    free(opts);
}
