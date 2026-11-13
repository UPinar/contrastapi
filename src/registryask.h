#ifndef REGISTRYASK_H
#define REGISTRYASK_H

#include <stdbool.h>
#include <libpq-fe.h>

#include "external/rdap.h"
#include "external/whois.h"
#include "quota.h"
#include "throttle.h"

typedef struct
{
  const ThrottleRule_t* mp_rdapRule;
  const ThrottleRule_t* mp_whoisRule;
} RegistryAskThrottleRules_t;

typedef struct
{
  const char*          mp_rdapServerBaseUrl;
  const WhoisServer_t* mp_whoisServer;
} RegistryAskServer_t;

typedef enum
{
  REGISTRYASK_OK = 0,
  REGISTRYASK_NOT_REGISTERED,
  REGISTRYASK_UNAVAILABLE,
  REGISTRYASK_DAILY_QUOTA_EXHAUSTED,
  REGISTRYASK_INVALID_NAME,
  REGISTRYASK_UPSTREAM_ERROR,
  REGISTRYASK_DB_ERROR,
} RegistryAskStatus_t;

extern const RegistryAskThrottleRules_t registryask_userRequestThrottleRules;
extern const RegistryAskThrottleRules_t registryask_watchlistScanThrottleRules;

bool                registryask_tryFindServer (const char* registrable_domain, RegistryAskServer_t* server_out);
RegistryAskStatus_t registryask_askDomain     (PGconn* conn, const RegistryAskThrottleRules_t* throttle_rules, const QuotaRule_t* daily_quota_rule, const RegistryAskServer_t* server, const char* registrable_domain, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out);

#endif
