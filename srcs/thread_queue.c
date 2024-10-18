#include "ft_nmap.h"

// create_queue ()

// execute_queue ()
//      send out queue packets to threads
//      TODO way later throddle sending based on rec values

// exec_thread ()
//  doesn't close until end of program
//  while (packets not all sent)
//      asks for packet to send
//      for (max_retries or pack received)
//          send packet
//          while (check rec queue every n msec)
//              ;
//  exit when no more packets to sen 

// reading_?thread? ()
// 