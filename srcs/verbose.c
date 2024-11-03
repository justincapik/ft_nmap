#include "ft_nmap.h"

// printf family is already thread safe, no need for mutex
// Make a buffer if printing is too slow
// -> but probably don't <-

static uint8_t verbose_level = VBS_NONE;

void    verbose_set(uint8_t level)
{
    verbose_level = level;
}

void    v_info(uint8_t level, char *msg, ...)
{
    if (verbose_level >= level)
    {
        va_list args;
        
        va_start(args, msg);
        vfprintf(stdout, msg, args);
        va_end(args);
    }
}

void    v_err(uint8_t level, char *msg, ...)
{
    if (verbose_level >= level)
    {
        va_list args;
        
        va_start(args, msg);
        vfprintf(stderr, msg, args);
        va_end(args);
    }
}