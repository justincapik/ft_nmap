#include "ft_nmap.h"

// Question: on function fer scan type ?
// - different packet types (TCP, UDP)
// - different TCP flags (SYN, NULL, ACK, FIN, XMAS(all))

// What are we doing in a sending function ?
// - called by thread pool after getting paquet_queue
// - open socket (need to say packet type)
// - create packet/set flags
// - sendto
// - wait for response and resend if none after TIME
//     ^- Call pcap_parsing here ?
// 

// https://nmap.org/book/scan-methods-null-fin-xmas-scan.html
// FIN, NULL, and XMAS are very similar, servers respond differently


// first to do is SYN just to get idea of things

int16_t send_packet(void *args)
{
    // send TCP SYN to port
    // TCP SYN/ACK          -> open
    // TCP RST              -> closed
    // Nothing              -> filtered (packet dropped)
    // ICMP err (type 3, code 1, 2, 3, 9, 10, or 13) -> filtered
}