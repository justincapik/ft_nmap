#ifndef __FT_NMAP__
# define __FT_NMAP__

# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <pcap.h>
# include <arpa/inet.h>
# include <string.h>

# include "lib_arg_parsing.h"
# include "lib_arg_parsing_internal.h"
# include "lib_arg_parsing_structs.h"

# define SYN_SCAN  0x1
# define NULL_SCAN 0x2
# define ACK_SCAN  0x4
# define FIN_SCAN  0x8
# define XMAS_SCAN 0x10
# define UDP_SCAN  0x20

# define MAX_PORT_AMOUNT 1024

typedef struct pack_queue_s pack_queue_t;
struct pack_queue_s {

    // network info ...
    uint16_t    port;
    // could do blocks for each ip but would make code very complex
    char        *ip;

    // single scan type
    uint8_t    scan_type; // mask 

    pack_queue_t *next;
};

typedef struct options_s {
    // starts with ports to scan, negative means stop there
    int32_t     ports[MAX_PORT_AMOUNT]; // simple et efficace
    uint8_t     scan_types; // mask
    uint8_t     nb_threads;
    char        **ips;
} opt_t;

// first functions to write
opt_t           *parse_opt(int ac, char **av);
pack_queue_t    *create_queue(opt_t opts);
int8_t          send_packet(char *ip, uint16_t port, uint8_t scan_type);

// figure out rest after those
// ...
// read_packets

#endif