#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "registryask.h"
#include "quota.h"

#define REGISTRYASK_RDAP_HOLD_NAME_PREFIX "rdap:"

#define REGISTRYASK_HTTPS_PREFIX "https://"

static bool                static_tryCopyRdapHost     (const char* base_url, char* host_out);
static RegistryAskStatus_t static_chargeServerRequest (PGconn* conn, const ThrottleRule_t* rule, const QuotaRule_t* daily_quota_rule, const char* host, unsigned int* retry_after_seconds_out);
static RegistryAskStatus_t static_reserveDailyCall    (PGconn* conn, const QuotaRule_t* daily_quota_rule);
static RegistryAskStatus_t static_askRdap             (PGconn* conn, const RegistryAskThrottleRules_t* throttle_rules, const QuotaRule_t* daily_quota_rule, const char* base_url, const char* registrable_domain, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out);
static RegistryAskStatus_t static_askWhois            (PGconn* conn, const RegistryAskThrottleRules_t* throttle_rules, const QuotaRule_t* daily_quota_rule, const WhoisServer_t* whois_server, const char* registrable_domain, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out);

bool registryask_tryFindServer(const char* registrable_domain, RegistryAskServer_t* server_out)
{
  assert(registrable_domain != NULL);
  assert(server_out         != NULL);

  *server_out = (RegistryAskServer_t){ NULL, NULL };
  server_out->mp_rdapServerBaseUrl = rdap_findServerBaseUrl(registrable_domain);
  if (server_out->mp_rdapServerBaseUrl != NULL)
    return true;

  server_out->mp_whoisServer = whois_findServer(registrable_domain);
  return server_out->mp_whoisServer != NULL;
}

RegistryAskStatus_t registryask_askDomain(PGconn* conn, const RegistryAskThrottleRules_t* throttle_rules, const QuotaRule_t* daily_quota_rule, const RegistryAskServer_t* server, const char* registrable_domain, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out)
{
  assert(throttle_rules               != NULL);
  assert(throttle_rules->mp_rdapRule  != NULL);
  assert(throttle_rules->mp_whoisRule != NULL);
  assert(server != NULL);
  assert((server->mp_rdapServerBaseUrl != NULL) != (server->mp_whoisServer != NULL));
  assert(registrable_domain      != NULL);
  assert(registration_out        != NULL);
  assert(retry_after_seconds_out != NULL);

  *retry_after_seconds_out = 0;
  if (server->mp_rdapServerBaseUrl != NULL)
    return static_askRdap(conn, throttle_rules, daily_quota_rule, server->mp_rdapServerBaseUrl, registrable_domain, registration_out, retry_after_seconds_out);
  return static_askWhois(conn, throttle_rules, daily_quota_rule, server->mp_whoisServer, registrable_domain, registration_out, retry_after_seconds_out);
}

static bool static_tryCopyRdapHost(const char* base_url, char* host_out)
{
  if (strncmp(base_url, REGISTRYASK_HTTPS_PREFIX, sizeof(REGISTRYASK_HTTPS_PREFIX) - 1) != 0)
    return false;

  const char* host = base_url + sizeof(REGISTRYASK_HTTPS_PREFIX) - 1;
  size_t host_len = strcspn(host, "/:");
  if (host_len == 0 || host_len > THROTTLE_TARGET_NAME_MAX_LEN)
    return false;

  memcpy(host_out, host, host_len);
  host_out[host_len] = '\0';
  return true;
}

static RegistryAskStatus_t static_chargeServerRequest(PGconn* conn, const ThrottleRule_t* rule, const QuotaRule_t* daily_quota_rule, const char* host, unsigned int* retry_after_seconds_out)
{
  unsigned int retry_after_seconds = 0;
  switch (throttle_dbCharge(conn, rule, host, 1, &retry_after_seconds))
  {
    case THROTTLE_CHARGED:
      return static_reserveDailyCall(conn, daily_quota_rule);
    case THROTTLE_REFUSED:
      *retry_after_seconds_out = retry_after_seconds;
      return REGISTRYASK_UNAVAILABLE;
    case THROTTLE_ERROR:
      break;
  }
  return REGISTRYASK_DB_ERROR;
}

static RegistryAskStatus_t static_reserveDailyCall(PGconn* conn, const QuotaRule_t* daily_quota_rule)
{
  if (daily_quota_rule == NULL)
    return REGISTRYASK_OK;

  switch (quota_dbReserve(conn, daily_quota_rule))
  {
    case QUOTA_GRANTED:
      return REGISTRYASK_OK;
    case QUOTA_EXHAUSTED:
      return REGISTRYASK_DAILY_QUOTA_EXHAUSTED;
    case QUOTA_ERROR:
      break;
  }
  return REGISTRYASK_DB_ERROR;
}

static RegistryAskStatus_t static_askRdap(PGconn* conn, const RegistryAskThrottleRules_t* throttle_rules, const QuotaRule_t* daily_quota_rule, const char* base_url, const char* registrable_domain, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out)
{
  char host[THROTTLE_TARGET_NAME_MAX_LEN + 1];
  if (!static_tryCopyRdapHost(base_url, host))
    return REGISTRYASK_UPSTREAM_ERROR;

  char hold_name[sizeof(REGISTRYASK_RDAP_HOLD_NAME_PREFIX) + THROTTLE_TARGET_NAME_MAX_LEN];
  snprintf(hold_name, sizeof(hold_name), "%s%s", REGISTRYASK_RDAP_HOLD_NAME_PREFIX, host);
  unsigned int hold_seconds = 0;
  if (!quota_dbTryReadHoldRemainingSeconds(conn, hold_name, &hold_seconds))
    return REGISTRYASK_DB_ERROR;
  if (hold_seconds > 0)
  {
    *retry_after_seconds_out = hold_seconds;
    return REGISTRYASK_UNAVAILABLE;
  }

  RegistryAskStatus_t charge_status = static_chargeServerRequest(conn, throttle_rules->mp_rdapRule, daily_quota_rule, host, retry_after_seconds_out);
  if (charge_status != REGISTRYASK_OK)
    return charge_status;

  unsigned int retry_after_seconds = 0;
  switch (rdap_lookupDomain(registrable_domain, base_url, registration_out, &retry_after_seconds))
  {
    case RDAP_OK:
      return REGISTRYASK_OK;
    case RDAP_NOT_REGISTERED:
      return REGISTRYASK_NOT_REGISTERED;
    case RDAP_RATE_LIMITED:
      quota_dbSetHold(conn, hold_name, retry_after_seconds);
      *retry_after_seconds_out = retry_after_seconds;
      return REGISTRYASK_UNAVAILABLE;
    case RDAP_UPSTREAM_ERROR:
      break;
    case RDAP_INVALID_NAME:
      return REGISTRYASK_INVALID_NAME;
  }
  return REGISTRYASK_UPSTREAM_ERROR;
}

static RegistryAskStatus_t static_askWhois(PGconn* conn, const RegistryAskThrottleRules_t* throttle_rules, const QuotaRule_t* daily_quota_rule, const WhoisServer_t* whois_server, const char* registrable_domain, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out)
{
  RegistryAskStatus_t charge_status = static_chargeServerRequest(conn, throttle_rules->mp_whoisRule, daily_quota_rule, whois_server->mp_host, retry_after_seconds_out);
  if (charge_status != REGISTRYASK_OK)
    return charge_status;

  switch (whois_lookupDomain(registrable_domain, whois_server, registration_out))
  {
    case WHOIS_OK:
      return REGISTRYASK_OK;
    case WHOIS_NOT_REGISTERED:
      return REGISTRYASK_NOT_REGISTERED;
    case WHOIS_UPSTREAM_ERROR:
      break;
    case WHOIS_INVALID_NAME:
      return REGISTRYASK_INVALID_NAME;
  }
  return REGISTRYASK_UPSTREAM_ERROR;
}
