#ifndef CVESERVICES_STUB_H
#define CVESERVICES_STUB_H

#include <stdint.h>

#include "external/cveservices.h"
#include "cve.h"

extern CveServicesStatus_t     g_stub_CVESERVICES_status;
extern CveServicesCveIdState_t g_stub_CVESERVICES_state;
extern unsigned int            g_stub_CVESERVICES_retry_after_seconds;

extern int     g_stub_CVESERVICES_call_count;
extern char    g_stub_CVESERVICES_last_cve_id[CVELOOKUP_ID_MAX_LEN + 1];
extern int64_t g_stub_CVESERVICES_last_deadline_ms;

extern void (*g_stub_CVESERVICES_on_call)(void);

#endif
