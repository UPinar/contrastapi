#ifndef ABUSEIPDB_H
#define ABUSEIPDB_H

#include <stdbool.h>

#include "keyvault.h"

#define ABUSEIPDB_TIMEOUT_MS 3000

#define ABUSEIPDB_MAX_BODY_BYTE_COUNT (16 * 1024)

#define ABUSEIPDB_KEY_MAX_LEN KEYVAULT_VENDOR_KEY_MAX_LEN

#define ABUSEIPDB_SCORE_MAX 100

#define ABUSEIPDB_LAST_REPORTED_AT_MAX_LEN 32
#define ABUSEIPDB_USAGE_TYPE_MAX_LEN       64

typedef enum {
  ABUSEIPDB_UNAVAILABLE = 0,
  ABUSEIPDB_OK,
  ABUSEIPDB_KEY_REJECTED,
  ABUSEIPDB_RATE_LIMITED,
} AbuseIpDbStatus_t;

typedef enum {
  ABUSEIPDB_WHITELIST_UNKNOWN = 0,
  ABUSEIPDB_WHITELIST_NO,
  ABUSEIPDB_WHITELIST_YES,
} AbuseIpDbWhitelist_t;

typedef struct {
  int                   m_abuseConfidenceScore;
  int                   m_reportCount;
  int                   m_distinctReporterCount;
  char                  ma_lastReportedAt[ABUSEIPDB_LAST_REPORTED_AT_MAX_LEN + 1];
  AbuseIpDbWhitelist_t  m_whitelist;
  char                  ma_usageType[ABUSEIPDB_USAGE_TYPE_MAX_LEN + 1];
} AbuseIpDbReport_t;

bool              abuseipdb_isKeyAccepted(const char* vendor_key);
AbuseIpDbStatus_t abuseipdb_checkAddress (const char* vendor_key, const char* ip_text, AbuseIpDbReport_t* report_out, unsigned int* retry_after_seconds_out);

#endif
