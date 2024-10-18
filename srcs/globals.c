#include "ft_nmap.h"

const uint8_t SCAN_TYPES[NB_SCAN_TYPES] = {
    SYN_SCAN,
    NULL_SCAN,
    ACK_SCAN,
    FIN_SCAN,
    XMAS_SCAN,
    UDP_SCAN
};