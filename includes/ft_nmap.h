#ifndef __FT_NMAP__
# define __FT_NMAP__

// standard
# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <string.h>
# include <stdint.h>
# include <stdbool.h>


// network
# include <pcap.h>
# include <pcap/pcap.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <net/ethernet.h>

// internal parsing library
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

enum port_status_e {
    OPEN        = 0x1,
    CLOSED      = 0x2,
    FILTERED    = 0x4,
    UNFILTERED  = 0x8
};

extern const uint8_t SCAN_TYPES[NB_SCAN_TYPES];

typedef struct queue_pack_info_s queue_pack_info_t;
struct queue_pack_info_s {

    // network info ...
    uint16_t        port;
    // could do blocks for each ip but would make code very complex
    struct addrinfo *hostinfo;

    // single scan type
    uint8_t         scan_type; // mask 

    // whatever info is needed for printing results
    uint16_t        send_count;


    queue_pack_info_t *next;
};

typedef struct options_s {
    // starts with ports to scan, negative means stop there
    int16_t     ports[MAX_PORT_AMOUNT]; // simple et efficace
    uint8_t     scan_types; // mask
    uint8_t     nb_threads;
    char        **ips;
    char        *interface;

    // options (bonus)
    uint16_t    max_retries;
    uint32_t    host_timeout;

//   max-retries: 10, host-timeout: 0
//   hostgroups: min 1, max 100000
//   rtt-timeouts: init 1000, min 100, max 10000
//   max-scan-delay: TCP 1000, UDP 1000, SCTP 1000
//   parallelism: min 0, max 0
//   min-rate: 0, max-rate: 0

    // other
    bool        verbose;
} opt_t;

// first functions to write
opt_t               *parse_opt(int ac, char **av);
void                free_opts(opt_t *opts);
queue_pack_info_t   *create_queue(opt_t opts);
int16_t             send_packet(struct addrinfo *hostinfo,
                    uint16_t port, uint8_t scan_type);

struct addrinfo     *dns_lookup(char *canoname, opt_t opts);

void            super_simple_sniffer(opt_t *opts);

// figure out rest after those
// ...
// read_packets

#endif