#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "endpoint_run.h"
#include "cve.h"
#include "db.h"
#include "dns.h"
#include "endpoint.h"
#include "etld.h"
#include "ipguard.h"
#include "macro.h"
#include "pricing.h"
#include "registryask.h"
#include "request.h"
#include "serialize.h"
#include "watchlist/watchlist.h"

#define WATCHLIST_NEEDS_KEY_REFUSAL_MESSAGE           "watchlist needs a Pro API key: " PRICING_PAGE_URL
#define WATCHLIST_OVER_LIMIT_REFUSAL_MESSAGE          "watchlist holds at most " MACRO_STR(WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY) " items"
#define WATCHLIST_OVER_DOMAIN_LIMIT_REFUSAL_MESSAGE   "limit: at most " MACRO_STR(WATCHLIST_DOMAIN_NAME_MAX_COUNT_PER_REGISTERED_DOMAIN) " watched names per registered domain per key"
#define WATCHLIST_OVER_PACKAGE_LIMIT_REFUSAL_MESSAGE  "watchlist holds at most " MACRO_STR(WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY) " package items"
#define WATCHLIST_PACKAGE_PROBLEMS_REFUSAL_MESSAGE    "packages holds elements that are not packages or that repeat an earlier element: problems lists each one, and nothing changed"
#define WATCHLIST_OVER_PACKAGE_WEIGHT_REFUSAL_MESSAGE "watchlist package items weigh at most " MACRO_STR(PACKAGECHECKBULK_WEIGHT_BUDGET) ": each weighs " MACRO_STR(PACKAGECHECKBULK_ITEM_BASE_WEIGHT) " plus the OSV rows of its package and 1 per " MACRO_STR(PACKAGECHECKBULK_LISTED_VERSIONS_PER_WEIGHT) " versions those rows list"

#define WATCHLIST_DOMAIN_NOT_IN_DNS_REFUSAL_MESSAGE     "domain does not exist in DNS"
#define WATCHLIST_NOT_REGISTERED_DOMAIN_REFUSAL_MESSAGE "whois_lookup items take a registered domain, such as example.com, not a name under it"
#define WATCHLIST_NO_REGISTRY_SERVER_REFUSAL_MESSAGE    "whois_lookup items take a domain whose TLD has an RDAP or WHOIS server"

typedef enum {
  WATCHLISTEDIT_FIELD_CVE_ID       = 1u << 0,
  WATCHLISTEDIT_FIELD_VENDOR       = 1u << 1,
  WATCHLISTEDIT_FIELD_PRODUCT      = 1u << 2,
  WATCHLISTEDIT_FIELD_CVE_FILTER   = 1u << 3,
  WATCHLISTEDIT_FIELD_DOMAIN       = 1u << 4,
  WATCHLISTEDIT_FIELD_ECOSYSTEM    = 1u << 5,
  WATCHLISTEDIT_FIELD_PACKAGE_NAME = 1u << 6,
  WATCHLISTEDIT_FIELD_VERSION      = 1u << 7,
  WATCHLISTEDIT_FIELD_IP_ADDRESS   = 1u << 8,
} WATCHLISTEDITField_t;

typedef struct {
  unsigned int m_requiredAllFields;
  unsigned int m_requiredOneOfFields;
  unsigned int m_allowedFields;
  const char*  mp_refusalMessage;
} WATCHLISTEDITItemShape_t;

#define WATCHLISTEDIT_CVE_ID_ITEM_SHAPE { WATCHLISTEDIT_FIELD_CVE_ID,                                         \
                                          0,                                                                  \
                                          WATCHLISTEDIT_FIELD_CVE_ID,                                         \
                                          "cve_lookup, kev_lookup and cve_exploit items take exactly one cve_id" }
#define WATCHLISTEDIT_DOMAIN_ITEM_SHAPE { WATCHLISTEDIT_FIELD_DOMAIN,                                         \
                                          0,                                                                  \
                                          WATCHLISTEDIT_FIELD_DOMAIN,                                         \
                                          "dns_lookup, ssl_check, whois_lookup, headers_check and cert_search items take exactly one domain" }

#define WATCHLIST_PACKAGE_LIST_NEEDS_ACTION_REFUSAL_MESSAGE "packages need action=add or action=remove"
#define WATCHLIST_PACKAGE_LIST_ITEM_FIELD_REFUSAL_MESSAGE   "packages take no item field, and endpoint only as package_check"

static const WATCHLISTEDITItemShape_t WATCHLISTEDIT_ITEM_SHAPES[] = {
  [WATCHLIST_ITEM_CVE_LOOKUP]       = WATCHLISTEDIT_CVE_ID_ITEM_SHAPE,
  [WATCHLIST_ITEM_KEV_LOOKUP]       = WATCHLISTEDIT_CVE_ID_ITEM_SHAPE,
  [WATCHLIST_ITEM_CVE_EXPLOIT]      = WATCHLISTEDIT_CVE_ID_ITEM_SHAPE,
  [WATCHLIST_ITEM_PRODUCT_EXPOSURE] = { WATCHLISTEDIT_FIELD_VENDOR | WATCHLISTEDIT_FIELD_PRODUCT,
                                        0,
                                        WATCHLISTEDIT_FIELD_VENDOR | WATCHLISTEDIT_FIELD_PRODUCT | WATCHLISTEDIT_FIELD_VERSION,
                                        "product_exposure items take one vendor and one product, and may take a version" },
  [WATCHLIST_ITEM_CVE_SEARCH]       = { 0,
                                        WATCHLISTEDIT_FIELD_VENDOR | WATCHLISTEDIT_FIELD_PRODUCT | WATCHLISTEDIT_FIELD_CVE_FILTER,
                                        WATCHLISTEDIT_FIELD_VENDOR | WATCHLISTEDIT_FIELD_PRODUCT | WATCHLISTEDIT_FIELD_CVE_FILTER,
                                        "cve_search items take at least one filter and no cve_id, domain, ecosystem, name, version or ip_address" },
  [WATCHLIST_ITEM_DNS_LOOKUP]       = WATCHLISTEDIT_DOMAIN_ITEM_SHAPE,
  [WATCHLIST_ITEM_SSL_CHECK]        = WATCHLISTEDIT_DOMAIN_ITEM_SHAPE,
  [WATCHLIST_ITEM_WHOIS_LOOKUP]     = WATCHLISTEDIT_DOMAIN_ITEM_SHAPE,
  [WATCHLIST_ITEM_HEADERS_CHECK]    = WATCHLISTEDIT_DOMAIN_ITEM_SHAPE,
  [WATCHLIST_ITEM_CERT_SEARCH]      = WATCHLISTEDIT_DOMAIN_ITEM_SHAPE,
  [WATCHLIST_ITEM_PACKAGE_CHECK]    = { WATCHLISTEDIT_FIELD_ECOSYSTEM | WATCHLISTEDIT_FIELD_PACKAGE_NAME,
                                        0,
                                        WATCHLISTEDIT_FIELD_ECOSYSTEM | WATCHLISTEDIT_FIELD_PACKAGE_NAME | WATCHLISTEDIT_FIELD_VERSION,
                                        "package_check items take one ecosystem and one name, and may take a version" },
  [WATCHLIST_ITEM_IP_LOOKUP]        = { WATCHLISTEDIT_FIELD_IP_ADDRESS,
                                        0,
                                        WATCHLISTEDIT_FIELD_IP_ADDRESS,
                                        "ip_lookup items take exactly one ip_address" },
};

_Static_assert(sizeof(WATCHLISTEDIT_ITEM_SHAPES) / sizeof(WATCHLISTEDIT_ITEM_SHAPES[0]) == WATCHLIST_ITEM_KIND_COUNT,
               "WATCHLISTEDIT_ITEM_SHAPES needs one row for each WatchlistItemKind_t");

static unsigned int static_WATCHLISTEDITReadFields(const WATCHLISTEDITParams_t* edit_params)
{
  unsigned int fields = 0;
  if (edit_params->ma_cveId[0] != '\0')
    fields |= WATCHLISTEDIT_FIELD_CVE_ID;
  if (edit_params->ma_vendor[0] != '\0')
    fields |= WATCHLISTEDIT_FIELD_VENDOR;
  if (edit_params->ma_product[0] != '\0')
    fields |= WATCHLISTEDIT_FIELD_PRODUCT;
  if (edit_params->ma_domain[0] != '\0')
    fields |= WATCHLISTEDIT_FIELD_DOMAIN;
  if (edit_params->ma_ecosystem[0] != '\0')
    fields |= WATCHLISTEDIT_FIELD_ECOSYSTEM;
  if (edit_params->ma_packageName[0] != '\0')
    fields |= WATCHLISTEDIT_FIELD_PACKAGE_NAME;
  if (edit_params->ma_version[0] != '\0')
    fields |= WATCHLISTEDIT_FIELD_VERSION;
  if (edit_params->ma_ipAddress[0] != '\0')
    fields |= WATCHLISTEDIT_FIELD_IP_ADDRESS;

  bool has_cve_filter = edit_params->ma_severity[0] != '\0'         ||
                        edit_params->ma_cweId[0] != '\0'            ||
                        edit_params->m_minCvss >= 0.0               ||
                        edit_params->m_minEpss >= 0.0               ||
                        edit_params->m_inKev != CVE_KEV_FILTER_ANY  ||
                        edit_params->m_knownRansomware              ||
                        edit_params->m_hasNucleiTemplate;
  if (has_cve_filter)
    fields |= WATCHLISTEDIT_FIELD_CVE_FILTER;

  return fields;
}

static bool static_WATCHLISTEDITIsMinEpssWholeThousandths(double min_epss)
{
  return (double)llround(min_epss * 1000.0) / 1000.0 == min_epss;
}

static bool static_WATCHLISTEDITIsPackageListRequest(const WATCHLISTEDITParams_t* edit_params)
{
  return edit_params->m_packages.m_itemCount > 0;
}

static const char* static_WATCHLISTEDITPackageListRefusal(const WATCHLISTEDITParams_t* edit_params, unsigned int set_item_fields)
{
  bool has_endpoint = edit_params->ma_endpoint[0] != '\0';

  if (edit_params->ma_action[0] == '\0')
    return WATCHLIST_PACKAGE_LIST_NEEDS_ACTION_REFUSAL_MESSAGE;
  else if (set_item_fields != 0 || (has_endpoint && strcmp(edit_params->ma_endpoint, "package_check") != 0))
    return WATCHLIST_PACKAGE_LIST_ITEM_FIELD_REFUSAL_MESSAGE;
  return NULL;
}

static const char* static_WATCHLISTEDITRefusal(const WATCHLISTEDITParams_t* edit_params)
{
  unsigned int set_item_fields    = static_WATCHLISTEDITReadFields(edit_params);
  bool         has_action         = edit_params->ma_action[0] != '\0';
  bool         has_endpoint       = edit_params->ma_endpoint[0] != '\0';
  bool         has_any_item_value = has_endpoint || set_item_fields != 0;
  bool         is_package_list    = static_WATCHLISTEDITIsPackageListRequest(edit_params);

  if (edit_params->m_isWatchlistCleared && (has_action || has_any_item_value || is_package_list))
    return "clear takes no action and no item";
  else if (is_package_list)
    return static_WATCHLISTEDITPackageListRefusal(edit_params, set_item_fields);
  else if (!has_action && has_any_item_value)
    return "an item needs action=add or action=remove";
  else if (has_action && !has_endpoint)
    return "an item needs an endpoint";
  else if (!has_action)
    return NULL;

  WatchlistItemKind_t kind;
  if (!watchlist_findItemKind(edit_params->ma_endpoint, &kind))
    return "an item needs an endpoint";

  const WATCHLISTEDITItemShape_t* shape = &WATCHLISTEDIT_ITEM_SHAPES[kind];

  bool has_required_fields     = (set_item_fields & shape->m_requiredAllFields) == shape->m_requiredAllFields;
  bool has_one_of_fields       = shape->m_requiredOneOfFields == 0 || (set_item_fields & shape->m_requiredOneOfFields) != 0;
  bool has_only_allowed_fields = (set_item_fields & ~shape->m_allowedFields) == 0;

  if (!has_required_fields || !has_one_of_fields || !has_only_allowed_fields)
    return shape->mp_refusalMessage;

  if (edit_params->m_minEpss >= 0.0 && !static_WATCHLISTEDITIsMinEpssWholeThousandths(edit_params->m_minEpss))
    return "min_epss of a cve_search item takes at most three decimals";

  return NULL;
}

static WATCHLISTEDITAction_t static_WATCHLISTEDITFindAction(const WATCHLISTEDITParams_t* edit_params)
{
  if (edit_params->m_isWatchlistCleared)
    return WATCHLISTEDIT_ACTION_CLEAR;
  if (edit_params->ma_action[0] == '\0')
    return WATCHLISTEDIT_ACTION_LIST;
  return strcmp(edit_params->ma_action, "add") == 0 ? WATCHLISTEDIT_ACTION_ADD : WATCHLISTEDIT_ACTION_REMOVE;
}

static bool static_WATCHLISTEDITIsNxdomain(const char* domain_name)
{
  const DnsQuestion_t question = { domain_name, DNS_RECORD_TYPE_CNAME };
  DnsAnswer_t         answer;
  dns_askQuestions(&question, 1, DNS_LOOKUP_DEADLINE_MS, &answer);
  bool is_nxdomain = answer.m_status == DNS_ANSWER_NXDOMAIN;
  dns_answerFree(&answer);
  return is_nxdomain;
}

bool endpoint_WATCHLISTEDITWillAskResolver(const EndpointAnyParams_t* params)
{
  const WATCHLISTEDITParams_t* edit_params = &params->m_watchlistEdit;

  WatchlistItemKind_t kind;
  return static_WATCHLISTEDITFindAction(edit_params) == WATCHLISTEDIT_ACTION_ADD                &&
         edit_params->ma_domain[0] != '\0'                                                      &&
         watchlist_findItemKind(edit_params->ma_endpoint, &kind)                                &&
         watchlist_findAddRequirement(kind) == WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN;
}

static const char* static_WATCHLISTEDITRegistryRefusal(const char* domain_name, const char* registered_domain)
{
  bool is_registered_domain_itself = registered_domain == domain_name;
  if (!is_registered_domain_itself)
    return WATCHLIST_NOT_REGISTERED_DOMAIN_REFUSAL_MESSAGE;

  RegistryAskServer_t server;
  if (!registryask_tryFindServer(domain_name, &server))
    return WATCHLIST_NO_REGISTRY_SERVER_REFUSAL_MESSAGE;

  return NULL;
}

static const char* static_WATCHLISTEDITAddRequirementRefusal(const EndpointAnyParams_t* params, const WATCHLISTEDITItemsDbParams_t* db_params, const char* domain_name, const char* registered_domain)
{
  if (db_params->m_action != WATCHLISTEDIT_ACTION_ADD)
    return NULL;

  switch (watchlist_findAddRequirement(db_params->m_item.m_itemKind))
  {
    case WATCHLIST_ADD_REQUIRES_NOTHING:
      return NULL;
    case WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN:
      if (endpoint_WATCHLISTEDITWillAskResolver(params) && static_WATCHLISTEDITIsNxdomain(domain_name))
        return WATCHLIST_DOMAIN_NOT_IN_DNS_REFUSAL_MESSAGE;
      return NULL;
    case WATCHLIST_ADD_REQUIRES_REGISTERED_DOMAIN_WITH_REGISTRY_SERVER:
      return static_WATCHLISTEDITRegistryRefusal(domain_name, registered_domain);
  }
  return NULL;
}

static void static_WATCHLISTEDITCopyText(char* field, size_t field_size, const char* text)
{
  size_t text_len = strlen(text);
  assert(text_len < field_size);
  (void)field_size;
  
  memcpy(field, text, text_len + 1);
}

static bool static_WATCHLISTEDITBuildItemsDbParams(const WATCHLISTEDITParams_t* edit_params, WATCHLISTEDITItemsDbParams_t* params_out)
{
  assert(!static_WATCHLISTEDITIsPackageListRequest(edit_params));

  memset(params_out, 0, sizeof(*params_out));
  params_out->mp_creditBudget = edit_params->mp_creditBudget;
  params_out->m_action        = static_WATCHLISTEDITFindAction(edit_params);
  if (params_out->m_action == WATCHLISTEDIT_ACTION_CLEAR || params_out->m_action == WATCHLISTEDIT_ACTION_LIST)
    return true;

  WatchlistItem_t* item     = &params_out->m_item;
  bool             has_kind = watchlist_findItemKind(edit_params->ma_endpoint, &item->m_itemKind);
  assert(has_kind);
  (void)has_kind;

  switch (item->m_itemKind)
  {
    case WATCHLIST_ITEM_CVE_LOOKUP:
      static_WATCHLISTEDITCopyText(item->m_cveLookup.ma_cveId, sizeof(item->m_cveLookup.ma_cveId), edit_params->ma_cveId);
      return true;
    case WATCHLIST_ITEM_KEV_LOOKUP:
      static_WATCHLISTEDITCopyText(item->m_kevLookup.ma_cveId, sizeof(item->m_kevLookup.ma_cveId), edit_params->ma_cveId);
      return true;
    case WATCHLIST_ITEM_CVE_EXPLOIT:
      static_WATCHLISTEDITCopyText(item->m_cveExploit.ma_cveId, sizeof(item->m_cveExploit.ma_cveId), edit_params->ma_cveId);
      return true;
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE:
      static_WATCHLISTEDITCopyText(item->m_productExposure.ma_vendor,  sizeof(item->m_productExposure.ma_vendor),  edit_params->ma_vendor);
      static_WATCHLISTEDITCopyText(item->m_productExposure.ma_product, sizeof(item->m_productExposure.ma_product), edit_params->ma_product);
      static_WATCHLISTEDITCopyText(item->m_productExposure.ma_version, sizeof(item->m_productExposure.ma_version), edit_params->ma_version);
      return true;
    case WATCHLIST_ITEM_CVE_SEARCH:
    {
      WATCHLISTCVESEARCHItem_t* filter = &item->m_cveSearch;
      static_WATCHLISTEDITCopyText(filter->ma_vendor,   sizeof(filter->ma_vendor),   edit_params->ma_vendor);
      static_WATCHLISTEDITCopyText(filter->ma_product,  sizeof(filter->ma_product),  edit_params->ma_product);
      static_WATCHLISTEDITCopyText(filter->ma_severity, sizeof(filter->ma_severity), edit_params->ma_severity);
      static_WATCHLISTEDITCopyText(filter->ma_cweId,    sizeof(filter->ma_cweId),    edit_params->ma_cweId);
      filter->m_minCvss           = edit_params->m_minCvss;
      filter->m_minEpss           = edit_params->m_minEpss;
      filter->m_kevFilter         = edit_params->m_inKev;
      filter->m_knownRansomware   = edit_params->m_knownRansomware;
      filter->m_hasNucleiTemplate = edit_params->m_hasNucleiTemplate;
      return true;
    }
    case WATCHLIST_ITEM_DNS_LOOKUP:
      static_WATCHLISTEDITCopyText(item->m_dnsLookup.ma_domainName, sizeof(item->m_dnsLookup.ma_domainName), edit_params->ma_domain);
      return true;
    case WATCHLIST_ITEM_SSL_CHECK:
      static_WATCHLISTEDITCopyText(item->m_sslCheck.ma_domainName, sizeof(item->m_sslCheck.ma_domainName), edit_params->ma_domain);
      return true;
    case WATCHLIST_ITEM_WHOIS_LOOKUP:
      static_WATCHLISTEDITCopyText(item->m_whoisLookup.ma_domainName, sizeof(item->m_whoisLookup.ma_domainName), edit_params->ma_domain);
      return true;
    case WATCHLIST_ITEM_HEADERS_CHECK:
      static_WATCHLISTEDITCopyText(item->m_headersCheck.ma_domainName, sizeof(item->m_headersCheck.ma_domainName), edit_params->ma_domain);
      return true;
    case WATCHLIST_ITEM_CERT_SEARCH:
      static_WATCHLISTEDITCopyText(item->m_certSearch.ma_domainName, sizeof(item->m_certSearch.ma_domainName), edit_params->ma_domain);
      return true;
    case WATCHLIST_ITEM_PACKAGE_CHECK:
      static_WATCHLISTEDITCopyText(item->m_packageCheck.ma_ecosystem, sizeof(item->m_packageCheck.ma_ecosystem), edit_params->ma_ecosystem);
      static_WATCHLISTEDITCopyText(item->m_packageCheck.ma_name,      sizeof(item->m_packageCheck.ma_name),      edit_params->ma_packageName);
      static_WATCHLISTEDITCopyText(item->m_packageCheck.ma_version,   sizeof(item->m_packageCheck.ma_version),   edit_params->ma_version);
      return true;
    case WATCHLIST_ITEM_IP_LOOKUP:
      return ipguard_tryWriteCanonicalIp(edit_params->ma_ipAddress, item->m_ipLookup.ma_ipAddress);
  }
  return false;
}

static bool static_WATCHLISTEDITHasPackageProblem(const WATCHLISTEDITPackageElement_t* elements, int element_count)
{
  assert(elements != NULL || element_count == 0);
  for (int i = 0; i < element_count; i++)
  {
    if (elements[i].m_problem != PACKAGE_ELEMENT_PROBLEM_NONE)
      return true;
  }
  return false;
}

static bool static_WATCHLISTEDITMarkPackageRepeats(const WATCHLISTEDITPackageListResult_t* result, WATCHLISTEDITPackageElement_t* elements, int element_count)
{
  if (result->m_repeatedCount == 0 && !static_WATCHLISTEDITHasPackageProblem(elements, element_count))
    return false;

  for (int i = 0; i < result->m_repeatedCount; i++)
  {
    const WATCHLISTEDITPackageRepeat_t* repeat = &result->mp_repeatedPackages[i];
    if (repeat->m_earlierIndex < 0                                                  ||
        repeat->m_earlierIndex >= repeat->m_currentIndex                            ||
        repeat->m_currentIndex >= element_count                                     ||
        elements[repeat->m_currentIndex].m_problem != PACKAGE_ELEMENT_PROBLEM_NONE  ||
        elements[repeat->m_earlierIndex].m_problem != PACKAGE_ELEMENT_PROBLEM_NONE)
    {
      return false;
    }
    elements[repeat->m_currentIndex].m_problem      = PACKAGE_ELEMENT_PROBLEM_NORMALIZED_REPEAT;
    elements[repeat->m_currentIndex].m_earlierIndex = repeat->m_earlierIndex;
  }
  return true;
}

static EndpointRunStatus_t static_WATCHLISTEDITRunItems(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  const WATCHLISTEDITParams_t* edit_params = &params->m_watchlistEdit;

  WATCHLISTEDITItemsDbParams_t db_params;
  if (!static_WATCHLISTEDITBuildItemsDbParams(edit_params, &db_params))
  {
    *message_out = IPGUARD_GLOBALLY_REACHABLE_IP_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }

  const char* domain_name       = watchlist_findDomainName(&db_params.m_item);
  const char* registered_domain = NULL;
  if (domain_name != NULL)
  {
    registered_domain = etld_findPlusOne(domain_name);
    if (registered_domain == NULL)
    {
      *message_out = ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
    }
    const char* add_refusal = static_WATCHLISTEDITAddRequirementRefusal(params, &db_params, domain_name, registered_domain);
    if (add_refusal != NULL)
    {
      *message_out = add_refusal;
      return ENDPOINT_RUN_REFUSED;
    }
  }

  WATCHLISTEDITItemsResult_t result;
  memset(&result, 0, sizeof(result));

  EndpointRunStatus_t run_status = ENDPOINT_RUN_DB_ERROR;
  if (db_WATCHLISTEDITItems(conn, &db_params, registered_domain, &result) != DB_OK)
    goto done;

  switch (result.m_status)
  {
    case WATCHLISTEDIT_OK:
      serialize_WATCHLISTEDITItems_response(&result, json_buf);
      run_status = ENDPOINT_RUN_OK;
      break;
    case WATCHLISTEDIT_PACKAGE_PROBLEM:
    case WATCHLISTEDIT_UNKNOWN_KEY:
      run_status = ENDPOINT_RUN_DB_ERROR;
      break;
    case WATCHLISTEDIT_OVER_LIMIT:
      *message_out = WATCHLIST_OVER_LIMIT_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
    case WATCHLISTEDIT_OVER_DOMAIN_LIMIT:
      *message_out = WATCHLIST_OVER_DOMAIN_LIMIT_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
    case WATCHLISTEDIT_OVER_PACKAGE_LIMIT:
      *message_out = WATCHLIST_OVER_PACKAGE_LIMIT_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
    case WATCHLISTEDIT_OVER_PACKAGE_WEIGHT:
      *message_out = WATCHLIST_OVER_PACKAGE_WEIGHT_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
  }

done:
  db_WATCHLISTEDITItemsResultFree(&result);
  return run_status;
}

static EndpointRunStatus_t static_WATCHLISTEDITRunPackageList(PGconn* conn, const WATCHLISTEDITParams_t* edit_params, JsonBuf_t* json_buf, const char** message_out)
{
  WATCHLISTEDITPackageElement_t* packages = NULL;
  if (!endpoint_readWatchlistPackageElements(&edit_params->m_packages, &packages))
    return ENDPOINT_RUN_NO_MEMORY;

  WATCHLISTEDITPackageListDbParams_t db_params;
  memset(&db_params, 0, sizeof(db_params));
  db_params.mp_creditBudget = edit_params->mp_creditBudget;
  db_params.m_action        = static_WATCHLISTEDITFindAction(edit_params);
  db_params.mp_elements     = packages;
  db_params.m_elementCount  = edit_params->m_packages.m_itemCount;

  WATCHLISTEDITPackageListResult_t result;
  memset(&result, 0, sizeof(result));

  EndpointRunStatus_t run_status = ENDPOINT_RUN_DB_ERROR;
  if (db_WATCHLISTEDITPackageList(conn, &db_params, &result) != DB_OK)
    goto done;
  if (result.m_status != WATCHLISTEDIT_PACKAGE_PROBLEM && static_WATCHLISTEDITHasPackageProblem(packages, db_params.m_elementCount))
  {
    fprintf(stderr, "static_WATCHLISTEDITRunPackageList: status %d for elements with a problem\n", (int)result.m_status);
    goto done;
  }

  switch (result.m_status)
  {
    case WATCHLISTEDIT_OK:
      serialize_WATCHLISTEDITPackageList_response(&result, json_buf);
      run_status = ENDPOINT_RUN_OK;
      break;
    case WATCHLISTEDIT_PACKAGE_PROBLEM:
      if (static_WATCHLISTEDITMarkPackageRepeats(&result, packages, db_params.m_elementCount))
      {
        serialize_WATCHLISTEDITPackageList_problems_response(WATCHLIST_PACKAGE_PROBLEMS_REFUSAL_MESSAGE, packages, db_params.m_elementCount, json_buf);
        run_status = ENDPOINT_RUN_REFUSED_WITH_BODY;
      }
      break;
    case WATCHLISTEDIT_UNKNOWN_KEY:
      run_status = ENDPOINT_RUN_DB_ERROR;
      break;
    case WATCHLISTEDIT_OVER_LIMIT:
      *message_out = WATCHLIST_OVER_LIMIT_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
    case WATCHLISTEDIT_OVER_DOMAIN_LIMIT:
      *message_out = WATCHLIST_OVER_DOMAIN_LIMIT_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
    case WATCHLISTEDIT_OVER_PACKAGE_LIMIT:
      *message_out = WATCHLIST_OVER_PACKAGE_LIMIT_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
    case WATCHLISTEDIT_OVER_PACKAGE_WEIGHT:
      *message_out = WATCHLIST_OVER_PACKAGE_WEIGHT_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
  }

done:
  db_WATCHLISTEDITPackageListResultFree(&result);
  free(packages);

  return run_status;
}

EndpointRunStatus_t endpoint_WATCHLISTEDITRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  const WATCHLISTEDITParams_t* edit_params = &params->m_watchlistEdit;
  assert(edit_params->mp_creditBudget != NULL);

  if (edit_params->mp_creditBudget->m_tier != REQUEST_TIER_PRO)
  {
    *message_out = WATCHLIST_NEEDS_KEY_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }
  const char* refusal = static_WATCHLISTEDITRefusal(edit_params);
  if (refusal != NULL)
  {
    *message_out = refusal;
    return ENDPOINT_RUN_REFUSED;
  }

  if (static_WATCHLISTEDITIsPackageListRequest(edit_params))
    return static_WATCHLISTEDITRunPackageList(conn, edit_params, json_buf, message_out);
  return static_WATCHLISTEDITRunItems(conn, params, json_buf, message_out);
}

EndpointRunStatus_t endpoint_WATCHLISTEVENTSRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  const WATCHLISTEVENTSParams_t* events_params = &params->m_watchlistEvents;
  assert(events_params->mp_creditBudget != NULL);

  if (events_params->mp_creditBudget->m_tier != REQUEST_TIER_PRO)
  {
    *message_out = WATCHLIST_NEEDS_KEY_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }
  if (events_params->ma_cursor[0] != '\0' && events_params->m_isRepeat)
  {
    *message_out = "cursor and repeat cannot be combined";
    return ENDPOINT_RUN_REFUSED;
  }

  int event_row_count = events_params->m_isRepeat ? CVE_LIST_MAX_LIMIT : events_params->m_limit;

  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));

  EndpointRunStatus_t run_status = ENDPOINT_RUN_DB_ERROR;
  if (db_WATCHLISTEVENTS(conn, events_params, event_row_count, &result) != DB_OK)
    run_status = ENDPOINT_RUN_DB_ERROR;
  else if (result.m_status == WATCHLISTEVENTS_UNKNOWN_KEY)
    run_status = ENDPOINT_RUN_DB_ERROR;
  else if (result.m_status == WATCHLISTEVENTS_CURSOR_INVALID)
  {
    *message_out = "cursor_invalid: start again without cursor";
    run_status   = ENDPOINT_RUN_REFUSED;
  }
  else
  {
    serialize_WATCHLISTEVENTS_response(&result, events_params, json_buf);
    run_status = ENDPOINT_RUN_OK;
  }
  db_WATCHLISTEVENTSResultFree(&result);
  return run_status;
}
