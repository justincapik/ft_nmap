#ifndef __FT_NMAP__
# define __FT_NMAP__

# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <pcap.h>
# include <arpa/inet.h>
# include <string.h>
# include <stdint.h>

# include "lib_arg_parsing.h"
# include "lib_arg_parsing_internal.h"
# include "lib_arg_parsing_structs.h"

# define MAX_PORT_AMOUNT 1024

# define NB_SCAN_TYPES 6

enum scan_type_e {
    SYN_SCAN    = 0x1,
    NULL_SCAN   = 0x2,
    ACK_SCAN    = 0x4,
    FIN_SCAN    = 0x8,
    XMAS_SCAN   = 0x10,
    UDP_SCAN    = 0x20
};

enum error_e { // make errors explicit
    SUCCESS
}

enum port_status_e {
    OPEN        = 0x1,
    CLOSED      = 0x2,
    FILTERED    = 0x4
}

extern const uint8_t SCAN_TYPES[NB_SCAN_TYPES];

typedef struct pack_queue_s pack_queue_t;
struct pack_queue_s {

    // network info ...
    uint16_t        port;
    // could do blocks for each ip but would make code very complex
    struct addrinfo *hostinfo;

    // single scan type
    uint8_t         scan_type; // mask 

    // whatever info is needed for printing results
    uint16_t        send_count;


    pack_queue_t *next;
};

typedef struct options_s {
    // starts with ports to scan, negative means stop there
    int16_t     ports[MAX_PORT_AMOUNT]; // simple et efficace
    uint8_t     scan_types; // mask
    uint8_t     nb_threads;
    char        **ips;

//   hostgroups: min 1, max 100000
//   rtt-timeouts: init 1000, min 100, max 10000
//   max-scan-delay: TCP 1000, UDP 1000, SCTP 1000
//   parallelism: min 0, max 0
//   max-retries: 10, host-timeout: 0
//   min-rate: 0, max-rate: 0


} opt_t;

// first functions to write
opt_t           *parse_opt(int ac, char **av);
void            free_opts(opt_t *opts);
pack_queue_t    *create_queue(opt_t opts);
int16_t          send_packet(struct addrinfo *hostinfo,
                    uint16_t port, uint8_t scan_type);

struct addrinfo *dns_lookup(char *canoname, opt_t opts);

// figure out rest after those
// ...
// read_packets

#endif