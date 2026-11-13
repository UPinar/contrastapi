#ifndef RDAP_H
#define RDAP_H

#include <stdbool.h>
#include <stddef.h>

#include "validate.h"

#define RDAP_REGISTRAR_NAME_MAX_LEN 255

#define RDAP_DATE_MAX_LEN 63

#define RDAP_NAME_SERVER_MAX_COUNT 16

#define RDAP_STATUS_MAX_COUNT 16
#define RDAP_STATUS_MAX_LEN   63

typedef struct {
  const char*   mp_tld;
  const char*   mp_baseUrl;
} RdapServer_t;

extern const RdapServer_t rdap_servers[];
extern const int          rdap_serverCount;

typedef enum {
  RDAP_OK = 0,
  RDAP_NOT_REGISTERED,
  RDAP_RATE_LIMITED,
  RDAP_UPSTREAM_ERROR,
  RDAP_INVALID_NAME,
} RdapStatus_t;

typedef enum {
  RDAP_DELEGATION_SIGNED_UNKNOWN = 0,
  RDAP_DELEGATION_SIGNED_YES,
  RDAP_DELEGATION_SIGNED_NO,
} RdapDelegationSigned_t;

typedef struct {
  char                    ma_registrarName[RDAP_REGISTRAR_NAME_MAX_LEN + 1];
  long                    m_registrarIanaId;
  char                    ma_createdAt[RDAP_DATE_MAX_LEN + 1];
  char                    ma_updatedAt[RDAP_DATE_MAX_LEN + 1];
  char                    ma_expiresAt[RDAP_DATE_MAX_LEN + 1];
  char                    ma_statuses[RDAP_STATUS_MAX_COUNT][RDAP_STATUS_MAX_LEN + 1];
  int                     m_statusCount;
  char                    ma_nameServers[RDAP_NAME_SERVER_MAX_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  int                     m_nameServerCount;
  RdapDelegationSigned_t  m_delegationSigned;
} RdapRegistration_t;

typedef enum {
  WHOISLOOKUP_UNAVAILABLE_NONE = 0,
  WHOISLOOKUP_UNAVAILABLE_NO_REGISTRY_SERVER,
  WHOISLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED,
} WHOISLOOKUPUnavailableReason_t;

typedef struct {
  char ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} WHOISLOOKUPParams_t;

typedef struct {
  char                            ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  const char*                     mp_rdapServerBaseUrl;
  const char*                     mp_whoisServerHost;
  WHOISLOOKUPUnavailableReason_t  m_unavailableReason;
  unsigned int                    m_retryAfterSeconds;
  RdapRegistration_t              m_registration;
} WHOISLOOKUPRecord_t;

const char*  rdap_findServerBaseUrl (const char* domain_name);
bool         rdap_tryReadDomain     (const char* body, size_t body_len, RdapRegistration_t* registration_out);
RdapStatus_t rdap_lookupDomain      (const char* domain_name, const char* base_url, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out);

#endif
