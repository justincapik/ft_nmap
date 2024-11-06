#ifndef __FT_NMAP__
# define __FT_NMAP__

// standard
# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <string.h>
# include <stdint.h>
# include <stdbool.h>
# include <stdarg.h>
# include <errno.h>

// network
# include <pcap.h>
# include <pcap/pcap.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
# include <net/ethernet.h>
# include <ifaddrs.h>

// threads
# include <pthread.h> 

// internal parsing library
// # include "lib_arg_parsing.h"
// # include "lib_arg_parsing_structs.h"

# define MAX_PORT_AMOUNT 1024

# define NB_SCAN_TYPES 6

enum return_values_e {
    SUCCESS = 0,
    FAIL = -1,
    ERROR = -2,
};

enum scan_type_e {
    SYN_SCAN    = 0x1,
    NULL_SCAN   = 0x2,
    ACK_SCAN    = 0x4,
    FIN_SCAN    = 0x8,
    XMAS_SCAN   = 0x10,
    UDP_SCAN    = 0x20,
    ICMP_SCAN   = 0x40
};

enum port_status_e {
    OPEN        = 0x1,
    CLOSED      = 0x2,
    FILTERED    = 0x4,
    UNFILTERED  = 0x8
};

enum tcp_flag_e {
    TCP_FIN     = 0x01,
    TCP_SYN     = 0x02,
    TCP_RST     = 0x04,
    TCP_PUSH    = 0x08,
    TCP_ACK     = 0x10,
    TCP_URG     = 0x20
};

extern const uint8_t SCAN_TYPES[NB_SCAN_TYPES];

#define IP_HL(ip)		(((ip)->ihl) & 0x0f)
#define IP_V(ip)		(((ip)->ihl) >> 4)

// TODO: service discovery, can also copy nmap-services file for more complete
//  ---->> struct servent *getservbyport(int port, const char *proto);



// in a nb(ip_nb) * nb(ports) * nb(scan types) table
typedef struct results_s {
    // timestamp TODO:
    uint8_t retries;
    // deduction (open, closed...)
} results_t;
// TODO: 

typedef struct options_s {
    // starts with ports to scan, negative means stop there
    int16_t     ports[MAX_PORT_AMOUNT]; // simple et efficace
    uint8_t     scan_types; // mask
    uint8_t     nb_threads;
    char        **ips;
    char        *interface;
    char        *self_ip;

    // options (bonus)
    uint16_t    max_retries;
    uint32_t    host_timeout;
    uint8_t     verbose;

//   max-retries: 10, host-timeout: 0
//   hostgroups: min 1, max 100000
//   rtt-timeouts: init 1000, min 100, max 10000
//   max-scan-delay: TCP 1000, UDP 1000, SCTP 1000
//   parallelism: min 0, max 0
//   min-rate: 0, max-rate: 0

} opt_t;

// Packet Sending Manager
typedef struct psm_opts_s {
    // sending info
    struct sockaddr_in  *target; 
    uint16_t            port;      

    // packer info
    u_char              protocol;
    uint8_t             flags; // only relevant for TCP ?

    opt_t               *opts; // contains self ip
} psm_opts_t;

typedef struct pcap_vars_s{
    pcap_if_t           *alldevsp;
    pcap_t              *source_handle;
    struct bpf_program  fp;
    bpf_u_int32         net;		/* Our IP */
    bpf_u_int32         mask;		/* Our netmask */
} pcap_v_t;

// first functions to write
opt_t               *parse_opt(int ac, char **av);
void                free_opts(opt_t *opts);
void                parse_packets(u_char *opts, const struct pcap_pkthdr *h,
                        const u_char *raw_data);

struct addrinfo     *dns_lookup(char *canoname);
opt_t               *get_local_ip(opt_t *opts);

void                *super_simple_sniffer(void *void_opts);
void                *packet_sending_manager(void *psm_opts);

void                *provider(void *void_opts);

// verbose system
enum verbose_options {
    VBS_NONE    = 0,
    VBS_LIGHT   = 1,
    VBS_DEBUG   = 2,
};

void    verbose_set(uint8_t level);
void    v_info(uint8_t level, char *msg, ...); 
void    v_err(uint8_t level, char *msg, ...); 

// figure out rest after those
// ...
// read_packets

/*
struct tcphdr
  {
    u_int16_t th_sport;                 source port 
    u_int16_t th_dport;                 destination port 
    tcp_seq th_seq;                 sequence number 
    tcp_seq th_ack;                 acknowledgement number 
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;                 (unused) 
    u_int8_t th_off:4;                 data offset 
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;                 data offset 
    u_int8_t th_x2:4;                 (unused) 
#  endif
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH        0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;                 window 
    u_int16_t th_sum;                 checksum 
    u_int16_t th_urp;                 urgent pointer 
};

struct udphdr
{
  u_int16_t uh_sport;                 source port 
  u_int16_t uh_dport;                 destination port 
  u_int16_t uh_ulen;                 udp length 
  u_int16_t uh_sum;                 udp checksum 
};


struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error        "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    // The options start here.
  };


*/

typedef struct custom_icmphdr_s
{
    uint8_t    type;                /* message type */
    uint8_t    code;                /* type sub-code */
    uint16_t   cksum;
    uint16_t   id;
    uint16_t   sequence;
} icmphdr_t;

struct pseudohdr {
    uint32_t src_addr; 
    uint32_t dest_addr;  
    uint8_t placeholder;  
    uint8_t protocol;       
    uint16_t pack_length;   
};

#endif