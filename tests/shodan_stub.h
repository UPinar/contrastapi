#ifndef SHODAN_STUB_H
#define SHODAN_STUB_H

#include <stddef.h>

#include "external/shodan.h"

extern ShodanStatus_t g_stub_SHODAN_check_status;
extern ShodanStatus_t g_stub_SHODAN_lookup_status;
extern unsigned int   g_stub_SHODAN_retry_after_seconds;
extern ShodanHost_t   g_stub_SHODAN_host;

extern int    g_stub_SHODAN_check_count;
extern int    g_stub_SHODAN_lookup_count;
extern size_t g_stub_SHODAN_last_key_len;
extern char   g_stub_SHODAN_last_ip[64];
extern int    g_stub_SHODAN_free_count;
extern int    g_stub_SHODAN_free_unknown_host_count;

#endif
