#ifndef ABUSEIPDB_STUB_H
#define ABUSEIPDB_STUB_H

#include <stddef.h>

#include "external/abuseipdb.h"

extern AbuseIpDbStatus_t g_stub_ABUSEIPDB_status;
extern AbuseIpDbReport_t g_stub_ABUSEIPDB_report;
extern unsigned int      g_stub_ABUSEIPDB_retry_after_seconds;

extern int    g_stub_ABUSEIPDB_check_count;
extern size_t g_stub_ABUSEIPDB_last_key_len;
extern char   g_stub_ABUSEIPDB_last_ip[64];

#endif
