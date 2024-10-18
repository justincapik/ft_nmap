#include "ft_nmap.h"

// https://nmap.org/book/synscan.html
// SYN

// https://nmap.org/book/scan-methods-udp-scan.html
// UDP

// https://nmap.org/book/scan-methods-null-fin-xmas-scan.html
// FIN, NULL, and XMAS are parsed similarily, servers respond differently

// List of packets to listen for:
// - ICMP error (type 3, codes 1, 2, **+-3**, 9, 10, 13)
// - TCP RST