#ifndef IP_H
#define IP_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "dns.h"
#include "jsonbuf.h"
#include "request.h"
#include "external/shodan.h"
#include "external/abuseipdb.h"

#define IPLOOKUP_LISTED_ON_MAX_LEN  JSONBUF_DEFAULT_CEILING

#define IPLOOKUP_ASN_NAME_MAX_LEN        256
#define IPLOOKUP_COUNTRY_CODE_LEN          2
#define IPLOOKUP_CLOUD_PROVIDER_MAX_LEN   10
#define IPLOOKUP_CLOUD_SERVICE_MAX_LEN    32

typedef struct {
  const RequestCreditBudget_t* mp_creditBudget;
  char                         ma_ipAddress[INET6_ADDRSTRLEN];
} IPLOOKUPParams_t;

typedef struct {
  char        ma_ipAddress[INET6_ADDRSTRLEN];
  uint32_t    m_asn;
  char        ma_asnName[IPLOOKUP_ASN_NAME_MAX_LEN + 1];
  char        ma_asnCountry[IPLOOKUP_COUNTRY_CODE_LEN + 1];
  char        ma_geoCountry[IPLOOKUP_COUNTRY_CODE_LEN + 1];
  char        ma_cloudProvider[IPLOOKUP_CLOUD_PROVIDER_MAX_LEN + 1];
  char        ma_cloudService[IPLOOKUP_CLOUD_SERVICE_MAX_LEN + 1];
  bool        m_isCdn;
  bool        m_isDatacenter;
  bool        m_isTorExit;
  char*       mp_listedOn;
  bool        m_isAsnFeedLoaded;
  bool        m_isGeoFeedLoaded;
  bool        m_isCloudFeedLoaded;
  bool        m_isTorFeedLoaded;
  bool        m_isDropListFeedLoaded;
  DnsAnswer_t m_ptrAnswer;
} IPLOOKUPRecord_t;

typedef enum {
  IPLOOKUP_SLOT_DB_ERROR = 0,
  IPLOOKUP_SLOT_PRO_KEY_REQUIRED,
  IPLOOKUP_SLOT_KEY_MISSING,
  IPLOOKUP_SLOT_KEY_REJECTED,
  IPLOOKUP_SLOT_VENDOR_UNAVAILABLE,
  IPLOOKUP_SLOT_FILLED,
} IPLOOKUPSlotState_t;

typedef struct {
  IPLOOKUPSlotState_t m_slotState;
  unsigned int        m_retryAfterSeconds;
} IPLOOKUPSlot_t;

typedef struct {
  IPLOOKUPSlot_t    m_internetExposure;
  ShodanHost_t      m_shodanHost;
  IPLOOKUPSlot_t    m_reputation;
  AbuseIpDbReport_t m_abuseIpDbReport;
} IPLOOKUPVendorSlots_t;

#define ASNLOOKUP_MAX_LIMIT  50

#define ASNLOOKUP_PREFIX_MAX_LEN  (INET6_ADDRSTRLEN - 1 + 4)

#define ASNLOOKUP_PREFIX_ARRAY_MAX_LEN  JSONBUF_DEFAULT_CEILING

typedef struct {
  char  ma_target[INET6_ADDRSTRLEN];
  int   m_limit;
  int   m_offset;
} ASNLOOKUPParams_t;

typedef struct {
  uint32_t  m_asn;
  char      ma_asnName[IPLOOKUP_ASN_NAME_MAX_LEN + 1];
  char      ma_asnCountry[IPLOOKUP_COUNTRY_CODE_LEN + 1];
  char      ma_prefix[ASNLOOKUP_PREFIX_MAX_LEN + 1];
  int       m_ipv4PrefixCount;
  int       m_ipv6PrefixCount;
  char*     mp_ipv4Prefixes;
  char*     mp_ipv6Prefixes;
} ASNLOOKUPRecord_t;

#endif
