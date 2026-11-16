#ifndef CVESERVICES_H
#define CVESERVICES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CVESERVICES_ASK_DEADLINE_MS 3000

#define CVESERVICES_MAX_BODY_BYTE_COUNT 4096

typedef enum {
  CVESERVICES_CVE_ID_STATE_NOT_CHECKED = 0,
  CVESERVICES_CVE_ID_STATE_PUBLISHED,
  CVESERVICES_CVE_ID_STATE_RESERVED,
  CVESERVICES_CVE_ID_STATE_REJECTED,
  CVESERVICES_CVE_ID_STATE_UNKNOWN_ID,
} CveServicesCveIdState_t;

typedef enum {
  CVESERVICES_OK = 0,
  CVESERVICES_RATE_LIMITED,
  CVESERVICES_UPSTREAM_ERROR,
  CVESERVICES_INVALID_ID,
} CveServicesStatus_t;

bool                cveservices_tryReadCveIdState  (const char* body, size_t body_len, CveServicesCveIdState_t* state_out);
bool                cveservices_isUnknownCveIdBody (const char* body, size_t body_len);
CveServicesStatus_t cveservices_askCveIdState      (const char* cve_id, int64_t deadline_ms, CveServicesCveIdState_t* state_out, unsigned int* retry_after_seconds_out);
const char*         cveservices_cveIdStateName     (CveServicesCveIdState_t state);

#endif
