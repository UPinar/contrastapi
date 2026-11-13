#ifndef SHODAN_H
#define SHODAN_H

#include <stdbool.h>
#include <stddef.h>

#include "keyvault.h"

#define SHODAN_TIMEOUT_MS 3000

#define SHODAN_MAX_BODY_BYTE_COUNT (256 * 1024)

#define SHODAN_KEY_MAX_LEN KEYVAULT_VENDOR_KEY_MAX_LEN

#define SHODAN_RATE_LIMIT_RETRY_SECONDS 1u

#define SHODAN_TAG_MAX_LEN 64

#define SHODAN_LAST_UPDATE_MAX_LEN 32

#define SHODAN_PORT_MAX 65535

typedef enum {
  SHODAN_UNAVAILABLE = 0,
  SHODAN_OK,
  SHODAN_NOT_FOUND,
  SHODAN_KEY_REJECTED,
  SHODAN_RATE_LIMITED,
} ShodanStatus_t;

#define SHODAN_FACET_SIZE 1000

typedef struct {
  char**  mp_items;
  size_t  m_count;
  size_t  m_skippedCount;
} ShodanTextArray_t;

typedef struct {
  int*               mp_ports;
  size_t             m_portCount;
  size_t             m_skippedPortCount;
  ShodanTextArray_t  m_vulns;
  ShodanTextArray_t  m_hostnames;
  ShodanTextArray_t  m_tags;
  char               ma_lastUpdate[SHODAN_LAST_UPDATE_MAX_LEN + 1];
  bool               m_isFromFacets;
  bool               m_isVulnListCut;
} ShodanHost_t;

bool           shodan_isKeyAccepted (const char* vendor_key);
ShodanStatus_t shodan_lookupHost    (const char* vendor_key, const char* ip_text, ShodanHost_t* host_out, unsigned int* retry_after_seconds_out);
ShodanStatus_t shodan_checkKey      (const char* vendor_key, unsigned int* retry_after_seconds_out);
void           shodan_freeHost      (ShodanHost_t* host);

#endif
