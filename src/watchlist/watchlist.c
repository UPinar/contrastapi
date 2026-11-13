#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "watchlist.h"

typedef struct {
  const char*               mp_endpoint;
  WatchlistAddRequirement_t m_addRequirement;
} WatchlistEndpointKind_t;

static const WatchlistEndpointKind_t WATCHLIST_ENDPOINT_KINDS[] = {
  [WATCHLIST_ITEM_CVE_LOOKUP]       = { "cve_lookup",       WATCHLIST_ADD_REQUIRES_NOTHING },
  [WATCHLIST_ITEM_KEV_LOOKUP]       = { "kev_lookup",       WATCHLIST_ADD_REQUIRES_NOTHING },
  [WATCHLIST_ITEM_CVE_EXPLOIT]      = { "cve_exploit",      WATCHLIST_ADD_REQUIRES_NOTHING },
  [WATCHLIST_ITEM_PRODUCT_EXPOSURE] = { "product_exposure", WATCHLIST_ADD_REQUIRES_NOTHING },
  [WATCHLIST_ITEM_CVE_SEARCH]       = { "cve_search",       WATCHLIST_ADD_REQUIRES_NOTHING },
  [WATCHLIST_ITEM_DNS_LOOKUP]       = { "dns_lookup",       WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN },
  [WATCHLIST_ITEM_SSL_CHECK]        = { "ssl_check",        WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN },
  [WATCHLIST_ITEM_WHOIS_LOOKUP]     = { "whois_lookup",     WATCHLIST_ADD_REQUIRES_REGISTERED_DOMAIN_WITH_REGISTRY_SERVER },
  [WATCHLIST_ITEM_HEADERS_CHECK]    = { "headers_check",    WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN },
  [WATCHLIST_ITEM_CERT_SEARCH]      = { "cert_search",      WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN },
  [WATCHLIST_ITEM_PACKAGE_CHECK]    = { "package_check",    WATCHLIST_ADD_REQUIRES_NOTHING },
  [WATCHLIST_ITEM_IP_LOOKUP]        = { "ip_lookup",        WATCHLIST_ADD_REQUIRES_NOTHING },
};

static const size_t WATCHLIST_ENDPOINT_KIND_COUNT = sizeof(WATCHLIST_ENDPOINT_KINDS) / sizeof(WATCHLIST_ENDPOINT_KINDS[0]);

_Static_assert(sizeof(WATCHLIST_ENDPOINT_KINDS) / sizeof(WATCHLIST_ENDPOINT_KINDS[0]) == WATCHLIST_ITEM_KIND_COUNT,
               "WATCHLIST_ENDPOINT_KINDS needs one row for each WatchlistItemKind_t");

static const WatchlistEndpointKind_t* static_findKindRow(WatchlistItemKind_t kind)
{
  return ((size_t)kind < WATCHLIST_ENDPOINT_KIND_COUNT) ? &WATCHLIST_ENDPOINT_KINDS[kind] : NULL;
}

bool watchlist_findItemKind(const char* endpoint, WatchlistItemKind_t* kind_out)
{
  assert(endpoint != NULL);
  assert(kind_out != NULL);

  for (size_t i = 0; i < WATCHLIST_ENDPOINT_KIND_COUNT; i++)
  {
    if (strcmp(endpoint, WATCHLIST_ENDPOINT_KINDS[i].mp_endpoint) == 0)
    {
      *kind_out = (WatchlistItemKind_t)i;
      return true;
    }
  }
  return false;
}

const char* watchlist_findEndpointName(WatchlistItemKind_t kind)
{
  const WatchlistEndpointKind_t* row = static_findKindRow(kind);
  return (row != NULL) ? row->mp_endpoint : NULL;
}

bool watchlist_isDomainItemKind(WatchlistItemKind_t kind)
{
  WatchlistEventKind_t event_kind;
  return watchlist_findDomainEventKind(kind, &event_kind);
}

bool watchlist_findDomainEventKind(WatchlistItemKind_t kind, WatchlistEventKind_t* kind_out)
{
  assert(kind_out != NULL);

  switch (kind)
  {
    case WATCHLIST_ITEM_DNS_LOOKUP:
      *kind_out = WATCHLIST_EVENT_DNS_LOOKUP;
      return true;
    case WATCHLIST_ITEM_SSL_CHECK:
      *kind_out = WATCHLIST_EVENT_SSL_CHECK;
      return true;
    case WATCHLIST_ITEM_WHOIS_LOOKUP:
      *kind_out = WATCHLIST_EVENT_WHOIS_LOOKUP;
      return true;
    case WATCHLIST_ITEM_HEADERS_CHECK:
      *kind_out = WATCHLIST_EVENT_HEADERS_CHECK;
      return true;
    case WATCHLIST_ITEM_CERT_SEARCH:
      *kind_out = WATCHLIST_EVENT_CERT_SEARCH;
      return true;
    case WATCHLIST_ITEM_CVE_LOOKUP:
    case WATCHLIST_ITEM_KEV_LOOKUP:
    case WATCHLIST_ITEM_CVE_EXPLOIT:
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE:
    case WATCHLIST_ITEM_CVE_SEARCH:
    case WATCHLIST_ITEM_PACKAGE_CHECK:
    case WATCHLIST_ITEM_IP_LOOKUP:
      return false;
  }
  return false;
}

const char* watchlist_findDomainName(const WatchlistItem_t* item)
{
  assert(item != NULL);

  if (!watchlist_isDomainItemKind(item->m_itemKind))
    return NULL;
  switch (item->m_itemKind)
  {
    case WATCHLIST_ITEM_DNS_LOOKUP:
      return item->m_dnsLookup.ma_domainName;
    case WATCHLIST_ITEM_SSL_CHECK:
      return item->m_sslCheck.ma_domainName;
    case WATCHLIST_ITEM_WHOIS_LOOKUP:
      return item->m_whoisLookup.ma_domainName;
    case WATCHLIST_ITEM_HEADERS_CHECK:
      return item->m_headersCheck.ma_domainName;
    case WATCHLIST_ITEM_CERT_SEARCH:
      return item->m_certSearch.ma_domainName;
    case WATCHLIST_ITEM_CVE_LOOKUP:
    case WATCHLIST_ITEM_KEV_LOOKUP:
    case WATCHLIST_ITEM_CVE_EXPLOIT:
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE:
    case WATCHLIST_ITEM_CVE_SEARCH:
    case WATCHLIST_ITEM_PACKAGE_CHECK:
    case WATCHLIST_ITEM_IP_LOOKUP:
      break;
  }
  return NULL;
}

WatchlistAddRequirement_t watchlist_findAddRequirement(WatchlistItemKind_t kind)
{
  const WatchlistEndpointKind_t* row = static_findKindRow(kind);
  return (row != NULL) ? row->m_addRequirement : WATCHLIST_ADD_REQUIRES_NOTHING;
}
