#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <curl/curl.h>

#include "header_fetch.h"
#include "header_check.h"
#include "http.h"
#include "macro.h"
#include "monotonic.h"
#include "validate.h"

#define HEADER_FETCH_MAX_BODY_BYTE_COUNT (64 * 1024)

#define HEADER_FETCH_PORT_TEXT MACRO_STR(HEADER_FETCH_PORT)

#define HEADER_FETCH_HTTP_PORT_TEXT  MACRO_STR(HEADER_FETCH_HTTP_PORT)

#define HEADER_FETCH_WWW_PREFIX       "www."
#define HEADER_FETCH_WWW_PREFIX_LEN   (sizeof(HEADER_FETCH_WWW_PREFIX) - 1)

typedef enum {
  HEADER_FETCH_REDIRECT_HEADER_LOCATION = 0,
  HEADER_FETCH_REDIRECT_HEADER_REFRESH,
  HEADER_FETCH_REDIRECT_HEADER_COUNT
} HeaderFetchRedirectHeader_t;

static const char* const HEADER_FETCH_REDIRECT_HEADER_NAMES[HEADER_FETCH_REDIRECT_HEADER_COUNT] = {
  [HEADER_FETCH_REDIRECT_HEADER_LOCATION] = "Location",
  [HEADER_FETCH_REDIRECT_HEADER_REFRESH]  = "Refresh",
};

#define HEADER_FETCH_SITE_MAX_REQUEST_COUNT (HEADER_FETCH_MAX_REDIRECT_COUNT + 1)
_Static_assert(HEADER_FETCH_SITE_MAX_REQUEST_COUNT <= HEADER_FETCH_MAX_REQUEST_COUNT, "a site chain fits the hop list");

#define HEADER_FETCH_HOME_PAGE_PATH         "/"
#define HEADER_FETCH_FIRST_REQUEST_URL_SIZE (sizeof("https://" HEADER_FETCH_HOME_PAGE_PATH) + VALIDATE_DOMAIN_NAME_MAX_LEN)

typedef struct {
  const HeaderFetchPolicy_t*  mp_policy;
  int64_t                     m_deadlineMs;
  const char**                mp_headerNamesToCapture;
  int                         m_callerNameCount;
  CURLU*                      mp_url;
  bool                        m_isUserInfoDropped;
  char*                       ma_requestUrls[HEADER_FETCH_MAX_REQUEST_COUNT];
  char*                       mp_siteHost;
  HttpResponse_t              m_answer;
} HeaderFetchRun_t;

typedef struct {
  char*     mp_host;
  bool      m_isHttps;
  uint16_t  m_port;
} HeaderFetchRequestCheck_t;

static bool         static_tryBuildHeaderNamesToCapture (const char* const* caller_header_names, HeaderFetchRun_t* run);
static HttpError_t  static_sendNextRequest              (HeaderFetchRun_t* run, HeaderFetchChain_t* chain, bool* is_chain_ended_out);
static bool         static_isRequestAllowed             (HeaderFetchRun_t* run, int hop_count, const char* request_url, HeaderFetchRequestCheck_t* check_out, HeaderFetchStopReason_t* stop_reason_out);
static bool         static_passesSameSiteRule           (HeaderFetchRun_t* run, HeaderFetchRequestCheck_t* check_out);
static bool         static_passesAnyPublicHostRule      (const CURLU* url, HeaderFetchRequestCheck_t* check_out, HeaderFetchStopReason_t* stop_reason_out);
static bool         static_isIpAddressHost              (const char* host);
static HttpError_t  static_askPermission                (const HeaderFetchRun_t* run, const HeaderFetchRequestCheck_t* check, HeaderFetchChain_t* chain, bool* is_allowed_out, HeaderFetchStopReason_t* stop_reason_out);
static HttpError_t  static_followAnswer                 (HeaderFetchRun_t* run, HeaderFetchChain_t* chain, HeaderFetchHop_t* hop, char* location, bool* is_chain_ended_out);
static char*        static_takeCapturedValue            (HttpResponse_t* response, int index);
static bool         static_hasUserInfo                  (const CURLU* url);
static void         static_keepLastAnswer               (HeaderFetchRun_t* run, HeaderFetchChain_t* chain);
static void         static_runFree                      (HeaderFetchRun_t* run);
static bool         static_isHostOrWwwPair              (const char* host, const char* hostname);
static void         static_dropUserInfoAndFragment      (CURLU* url);
static bool         static_tryWriteUrl                  (CURLU* url, HeaderFetchHopRule_t hop_rule, char** text_out);
static bool         static_isSameRequestUrl             (const char* url, const char* other_url);
static size_t       static_findAuthorityEnd             (const char* url);

HttpError_t header_fetch_fetchChain(const char* first_url, const HeaderFetchPolicy_t* policy, int64_t deadline_ms, HeaderFetchChain_t* chain_out)
{
  assert(first_url != NULL);
  assert(policy    != NULL);
  assert(chain_out != NULL);
  assert(policy->m_maxBodyByteCount > 0);
  assert(policy->m_hopRule == HEADER_FETCH_HOP_RULE_SAME_SITE || policy->m_hopRule == HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST);

  memset(chain_out, 0, sizeof(*chain_out));
  HeaderFetchRun_t run = { .mp_policy = policy, .m_deadlineMs = deadline_ms };
  HttpError_t error = HTTP_ERROR_OTHER;
  if (!static_tryBuildHeaderNamesToCapture(policy->mp_headerNamesToCapture, &run))
    goto done;

  run.mp_url = curl_url();
  if (curl_url_set(run.mp_url, CURLUPART_URL, first_url, 0) != CURLUE_OK)
    goto done;

  bool is_chain_ended = false;
  do
    error = static_sendNextRequest(&run, chain_out, &is_chain_ended);
  while (error == HTTP_ERROR_NONE && !is_chain_ended);

  if (error == HTTP_ERROR_NONE)
    static_keepLastAnswer(&run, chain_out);

done:
  static_runFree(&run);
  if (error != HTTP_ERROR_NONE)
    header_fetch_chainFree(chain_out);
  return error;
}

void header_fetch_chainFree(HeaderFetchChain_t* chain)
{
  assert(chain != NULL);
  assert(chain->m_hopCount >= 0 && chain->m_hopCount <= HEADER_FETCH_MAX_REQUEST_COUNT);

  for (int i = 0; i < chain->m_hopCount; i++)
  {
    curl_free(chain->ma_hops[i].mp_url);
    free(chain->ma_hops[i].mp_refresh);
  }
  curl_free(chain->mp_unfollowedUrl);
  free(chain->mp_invalidLocation);
  for (int i = 0; i < chain->m_capturedHeaderValueCount; i++)
    free(chain->mp_capturedHeaderValues[i]);
  free(chain->mp_capturedHeaderValues);
  free(chain->mp_body);
  memset(chain, 0, sizeof(*chain));
}

HttpError_t header_fetch_chainError(const HeaderFetchChain_t* chain)
{
  assert(chain != NULL);

  if (chain->m_stopReason == HEADER_FETCH_STOP_REQUEST_FAILED && chain->m_hopCount > 0)
    return chain->ma_hops[chain->m_hopCount - 1].m_error;
  else if (chain->m_stopReason == HEADER_FETCH_STOP_DEADLINE)
    return HTTP_ERROR_TIMEOUT;
  return HTTP_ERROR_NONE;
}

HttpError_t header_fetch_fetchHomePage(const char* hostname, HeaderFetchResult_t* result_out)
{
  assert(hostname   != NULL);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));
  if (strnlen(hostname, VALIDATE_DOMAIN_NAME_MAX_LEN + 1) > VALIDATE_DOMAIN_NAME_MAX_LEN)
    return HTTP_ERROR_OTHER;
  char first_url[HEADER_FETCH_FIRST_REQUEST_URL_SIZE];
  int first_url_len = snprintf(first_url, sizeof(first_url), "https://%s" HEADER_FETCH_HOME_PAGE_PATH, hostname);
  if (first_url_len < 0 || (size_t)first_url_len >= sizeof(first_url))
    return HTTP_ERROR_OTHER;

  const HeaderFetchPolicy_t policy = {
    .m_hopRule                = HEADER_FETCH_HOP_RULE_SAME_SITE,
    .m_maxBodyByteCount       = HEADER_FETCH_MAX_BODY_BYTE_COUNT,
    .mp_headerNamesToCapture  = header_check_capturedHeaderNames,
    .m_askPermission          = NULL,
    .mp_permissionContext     = NULL,
  };
  HeaderFetchChain_t chain;
  HttpError_t error = header_fetch_fetchChain(first_url, &policy, monotonic_nowMs() + HEADER_FETCH_DEADLINE_MS, &chain);
  if (error != HTTP_ERROR_NONE)
    return error;
  error = header_fetch_chainError(&chain);
  if (error == HTTP_ERROR_NONE && chain.m_hopCount == 0)
    error = HTTP_ERROR_OTHER;
  if (error != HTTP_ERROR_NONE)
  {
    header_fetch_chainFree(&chain);
    return error;
  }

  HeaderFetchHop_t* last_hop = &chain.ma_hops[chain.m_hopCount - 1];
  result_out->m_httpStatus               = last_hop->m_httpStatus;
  result_out->mp_url                     = last_hop->mp_url;
  result_out->m_followedRedirectCount    = chain.m_hopCount - 1;
  result_out->mp_unfollowedRedirectUrl   = chain.mp_unfollowedUrl;
  result_out->m_isRedirectLimitReached   = chain.m_stopReason == HEADER_FETCH_STOP_REQUEST_LIMIT;
  result_out->mp_capturedHeaderValues    = chain.mp_capturedHeaderValues;
  result_out->m_capturedHeaderValueCount = chain.m_capturedHeaderValueCount;
  result_out->m_setCookieCopyCount       = chain.m_setCookieCopyCount;

  last_hop->mp_url                       = NULL;
  chain.mp_unfollowedUrl                 = NULL;
  chain.mp_capturedHeaderValues          = NULL;
  chain.m_capturedHeaderValueCount       = 0;
  header_fetch_chainFree(&chain);

  return HTTP_ERROR_NONE;
}

void header_fetch_resultFree(HeaderFetchResult_t* result)
{
  assert(result != NULL);

  curl_free(result->mp_url);
  curl_free(result->mp_unfollowedRedirectUrl);
  for (int i = 0; i < result->m_capturedHeaderValueCount; i++)
    free(result->mp_capturedHeaderValues[i]);
  free(result->mp_capturedHeaderValues);
  memset(result, 0, sizeof(*result));
}

HeaderFetchUrlStatus_t header_fetch_writeNormalUrl(const char* url, char* normal_url_out, size_t normal_url_size)
{
  assert(url != NULL);
  assert(normal_url_out != NULL);
  assert(normal_url_size > 0);

  normal_url_out[0] = '\0';
  HeaderFetchUrlStatus_t status = HEADER_FETCH_URL_UNPARSABLE;
  char* user     = NULL;
  char* password = NULL;
  char* host     = NULL;
  char* written  = NULL;

  CURLU* parsed_url = curl_url();
  if (curl_url_set(parsed_url, CURLUPART_URL, url, 0) != CURLUE_OK)
    goto done;

  CURLUcode user_code = curl_url_get(parsed_url, CURLUPART_USER, &user, 0);
  if (user_code == CURLUE_OK)
  {
    status = HEADER_FETCH_URL_USER_INFO;
    goto done;
  }
  else if (user_code != CURLUE_NO_USER)
    goto done;

  CURLUcode password_code = curl_url_get(parsed_url, CURLUPART_PASSWORD, &password, 0);
  if (password_code == CURLUE_OK)
  {
    status = HEADER_FETCH_URL_USER_INFO;
    goto done;
  }
  else if (password_code != CURLUE_NO_PASSWORD)
    goto done;

  if (curl_url_get(parsed_url, CURLUPART_HOST, &host, 0) != CURLUE_OK)
    goto done;
  for (char* host_byte = host; *host_byte != '\0'; host_byte++)
    *host_byte = (char)tolower((unsigned char)*host_byte);
  if (curl_url_set(parsed_url, CURLUPART_HOST, host, 0) != CURLUE_OK)
    goto done;
  curl_url_set(parsed_url, CURLUPART_FRAGMENT, NULL, 0);
  if (curl_url_get(parsed_url, CURLUPART_URL, &written, CURLU_NO_DEFAULT_PORT) != CURLUE_OK)
    goto done;

  size_t written_len = strlen(written);
  if (written_len >= normal_url_size)
  {
    status = HEADER_FETCH_URL_TOO_LONG;
    goto done;
  }
  memcpy(normal_url_out, written, written_len + 1);
  status = HEADER_FETCH_URL_OK;

done:
  curl_free(user);
  curl_free(password);
  curl_free(host);
  curl_free(written);
  curl_url_cleanup(parsed_url);
  return status;
}

static bool static_tryBuildHeaderNamesToCapture(const char* const* caller_header_names, HeaderFetchRun_t* run)
{
  int caller_header_name_count = 0;
  while (caller_header_names != NULL && caller_header_names[caller_header_name_count] != NULL)
    caller_header_name_count++;

  const char** header_names = malloc(((size_t)caller_header_name_count + HEADER_FETCH_REDIRECT_HEADER_COUNT + 1) * sizeof(*header_names));
  if (header_names == NULL)
    return false;

  for (int i = 0; i < caller_header_name_count; i++)
    header_names[i] = caller_header_names[i];
  for (int i = 0; i < HEADER_FETCH_REDIRECT_HEADER_COUNT; i++)
    header_names[caller_header_name_count + i] = HEADER_FETCH_REDIRECT_HEADER_NAMES[i];
  header_names[caller_header_name_count + HEADER_FETCH_REDIRECT_HEADER_COUNT] = NULL;

  run->mp_headerNamesToCapture  = header_names;
  run->m_callerNameCount        = caller_header_name_count;
  return true;
}

static HttpError_t static_sendNextRequest(HeaderFetchRun_t* run, HeaderFetchChain_t* chain, bool* is_chain_ended_out)
{
  *is_chain_ended_out = true;
  const HeaderFetchPolicy_t* policy = run->mp_policy;

  static_dropUserInfoAndFragment(run->mp_url);
  char* request_url = NULL;
  if (curl_url_get(run->mp_url, CURLUPART_URL, &request_url, CURLU_NO_DEFAULT_PORT) != CURLUE_OK)
    return HTTP_ERROR_OTHER;

  HeaderFetchRequestCheck_t check = { 0 };
  HeaderFetchStopReason_t stop_reason = HEADER_FETCH_STOP_FINAL_ANSWER;
  HttpError_t error = HTTP_ERROR_NONE;
  bool is_allowed = static_isRequestAllowed(run, chain->m_hopCount, request_url, &check, &stop_reason);
  if (is_allowed && policy->m_askPermission != NULL)
    error = static_askPermission(run, &check, chain, &is_allowed, &stop_reason);

  int64_t remaining_ms = 0;
  if (error == HTTP_ERROR_NONE && is_allowed)
  {
    remaining_ms = run->m_deadlineMs - monotonic_nowMs();
    if (remaining_ms <= 0)
    {
      is_allowed  = false;
      stop_reason = HEADER_FETCH_STOP_DEADLINE;
      if (chain->m_hopCount == 0)
        error = HTTP_ERROR_TIMEOUT;
    }
  }

  if (error != HTTP_ERROR_NONE || !is_allowed)
  {
    curl_free(request_url);
    curl_free(check.mp_host);
    if (error != HTTP_ERROR_NONE)
      return error;
    chain->m_stopReason = stop_reason;
    return static_tryWriteUrl(run->mp_url, policy->m_hopRule, &chain->mp_unfollowedUrl) ? HTTP_ERROR_NONE : HTTP_ERROR_OTHER;
  }

  const HttpRequest_t request = {
    .mp_url                   = request_url,
    .m_timeoutMs              = remaining_ms > INT_MAX ? INT_MAX : (int)remaining_ms,
    .mp_extraHeaders          = NULL,
    .m_maxBodyByteCount       = policy->m_maxBodyByteCount,
    .mp_headerNamesToCapture  = run->mp_headerNamesToCapture,
    .m_isTargetTrusted        = false,
    .m_isHttpsOnly            = check.m_isHttps,
    .m_isRedirectLeftToCaller = true,
    .m_isBodyCutAccepted      = true,
    .m_requiredPort           = check.m_port,
  };
  HttpResponse_t response = http_GETWithOptions(&request);
  curl_free(check.mp_host);

  int hop_index = chain->m_hopCount++;
  run->ma_requestUrls[hop_index] = request_url;
  HeaderFetchHop_t* hop = &chain->ma_hops[hop_index];
  hop->m_isUserInfoDropped = run->m_isUserInfoDropped;
  if (response.m_error != HTTP_ERROR_NONE)
  {
    hop->m_error = response.m_error;
    http_free(&response);
    if (hop_index == 0)
      return hop->m_error;
    chain->m_stopReason = HEADER_FETCH_STOP_REQUEST_FAILED;
    return static_tryWriteUrl(run->mp_url, policy->m_hopRule, &hop->mp_url) ? HTTP_ERROR_NONE : HTTP_ERROR_OTHER;
  }

  hop->m_httpStatus = response.m_status;
  hop->mp_refresh   = static_takeCapturedValue(&response, run->m_callerNameCount + HEADER_FETCH_REDIRECT_HEADER_REFRESH);
  char* location    = static_takeCapturedValue(&response, run->m_callerNameCount + HEADER_FETCH_REDIRECT_HEADER_LOCATION);
  http_free(&run->m_answer);
  run->m_answer = response;
  return static_followAnswer(run, chain, hop, location, is_chain_ended_out);
}

static bool static_isRequestAllowed(HeaderFetchRun_t* run, int hop_count, const char* request_url, HeaderFetchRequestCheck_t* check_out, HeaderFetchStopReason_t* stop_reason_out)
{
  if (hop_count > 0 && strlen(request_url) > HEADER_FETCH_MAX_URL_BYTE_COUNT)
  {
    *stop_reason_out = HEADER_FETCH_STOP_LOCATION_TOO_LONG;
    return false;
  }

  bool is_passed = false;
  if (run->mp_policy->m_hopRule == HEADER_FETCH_HOP_RULE_SAME_SITE)
  {
    is_passed        = static_passesSameSiteRule(run, check_out);
    *stop_reason_out = HEADER_FETCH_STOP_OFF_SITE;
  }
  else
    is_passed = static_passesAnyPublicHostRule(run->mp_url, check_out, stop_reason_out);
  if (!is_passed)
    return false;

  bool is_allowed = true;
  for (int i = 0; i < hop_count && is_allowed; i++)
  {
    if (static_isSameRequestUrl(request_url, run->ma_requestUrls[i]))
    {
      *stop_reason_out = HEADER_FETCH_STOP_LOOP;
      is_allowed       = false;
    }
  }
  int max_request_count = run->mp_policy->m_hopRule == HEADER_FETCH_HOP_RULE_SAME_SITE  ? HEADER_FETCH_SITE_MAX_REQUEST_COUNT 
                                                                                        : HEADER_FETCH_MAX_REQUEST_COUNT;
  if (is_allowed && hop_count >= max_request_count)
  {
    *stop_reason_out = HEADER_FETCH_STOP_REQUEST_LIMIT;
    is_allowed       = false;
  }

  if (!is_allowed)
  {
    curl_free(check_out->mp_host);
    check_out->mp_host = NULL;
  }
  return is_allowed;
}

static bool static_passesSameSiteRule(HeaderFetchRun_t* run, HeaderFetchRequestCheck_t* check_out)
{
  char* scheme = NULL;
  char* port   = NULL;
  char* host   = NULL;
  bool is_on_site =
      curl_url_get(run->mp_url, CURLUPART_SCHEME, &scheme, 0)               == CURLUE_OK && strcmp(scheme, "https") == 0 &&
      curl_url_get(run->mp_url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT)  == CURLUE_OK && strcmp(port, HEADER_FETCH_PORT_TEXT) == 0 &&
      curl_url_get(run->mp_url, CURLUPART_HOST, &host, 0)                   == CURLUE_OK;
  if (is_on_site && run->mp_siteHost == NULL)
    run->mp_siteHost = strdup(host);
  is_on_site = is_on_site && run->mp_siteHost != NULL && static_isHostOrWwwPair(host, run->mp_siteHost);

  curl_free(scheme);
  curl_free(port);
  if (!is_on_site)
  {
    curl_free(host);
    return false;
  }
  *check_out = (HeaderFetchRequestCheck_t){ .mp_host = host, .m_isHttps = true, .m_port = HEADER_FETCH_PORT };
  return true;
}

static bool static_passesAnyPublicHostRule(const CURLU* url, HeaderFetchRequestCheck_t* check_out, HeaderFetchStopReason_t* stop_reason_out)
{
  char* scheme = NULL;
  char* port   = NULL;
  char* host   = NULL;
  bool is_https     = false;
  bool is_passed    = false;
  bool is_scheme_ok = curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK  && 
                      (strcmp(scheme, "http") == 0 || strcmp(scheme, "https") == 0);
  if (is_scheme_ok)
    is_https = strcmp(scheme, "https") == 0;

  if (!is_scheme_ok)
    *stop_reason_out = HEADER_FETCH_STOP_SCHEME_NOT_FOLLOWED;
  else if ( curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) != CURLUE_OK  || 
            strcmp(port, is_https ? HEADER_FETCH_PORT_TEXT : HEADER_FETCH_HTTP_PORT_TEXT) != 0)
  {
    *stop_reason_out = HEADER_FETCH_STOP_PORT_NOT_ALLOWED;
  }
  else if (curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK)
    *stop_reason_out = HEADER_FETCH_STOP_HOST_NOT_PUBLIC;
  else if (static_isIpAddressHost(host))
    *stop_reason_out = HEADER_FETCH_STOP_IP_ADDRESS_NOT_FOLLOWED;
  else if (!validate_publicDnsName(host))
    *stop_reason_out = HEADER_FETCH_STOP_HOST_NOT_PUBLIC;
  else
    is_passed = true;

  curl_free(scheme);
  curl_free(port);
  if (!is_passed)
  {
    curl_free(host);
    return false;
  }
  *check_out = (HeaderFetchRequestCheck_t){
    .mp_host   = host,
    .m_isHttps = is_https,
    .m_port    = is_https ? HEADER_FETCH_PORT : HEADER_FETCH_HTTP_PORT,
  };
  return true;
}

static bool static_isIpAddressHost(const char* host)
{
  struct in_addr ipv4;
  return host[0] == '[' || inet_pton(AF_INET, host, &ipv4) == 1;
}

static HttpError_t static_askPermission(const HeaderFetchRun_t* run, const HeaderFetchRequestCheck_t* check, HeaderFetchChain_t* chain, bool* is_allowed_out, HeaderFetchStopReason_t* stop_reason_out)
{
  char* path  = NULL;
  char* query = NULL;
  char* path_and_query = NULL;
  HttpError_t error = HTTP_ERROR_OTHER;
  if (curl_url_get(run->mp_url, CURLUPART_PATH, &path, 0) != CURLUE_OK)
    goto done;
  CURLUcode query_code = curl_url_get(run->mp_url, CURLUPART_QUERY, &query, 0);
  if (query_code != CURLUE_OK && query_code != CURLUE_NO_QUERY)
    goto done;

  size_t text_size = strlen(path) + (query != NULL ? 1 + strlen(query) : 0) + 1;
  path_and_query = malloc(text_size);
  if (path_and_query == NULL)
    goto done;
  int text_len = snprintf(path_and_query, text_size, "%s%s%s", path, query != NULL ? "?" : "", query != NULL ? query : "");
  if (text_len < 0 || (size_t)text_len >= text_size)
    goto done;

  const HeaderFetchTarget_t target = { .mp_host = check->mp_host, .mp_pathAndQuery = path_and_query };
  unsigned retry_after_seconds = 0;
  HeaderFetchPermission_t permission = run->mp_policy->m_askPermission(run->mp_policy->mp_permissionContext, &target, &retry_after_seconds);
  if (permission == HEADER_FETCH_PERMISSION_THROTTLED)
  {
    *is_allowed_out           = false;
    *stop_reason_out          = HEADER_FETCH_STOP_THROTTLED;
    chain->m_retryAfterSeconds = retry_after_seconds;
  }
  else if (permission != HEADER_FETCH_PERMISSION_ALLOWED)
  {
    *is_allowed_out  = false;
    *stop_reason_out = HEADER_FETCH_STOP_PERMISSION_REFUSED;
  }
  error = HTTP_ERROR_NONE;

done:
  curl_free(path);
  curl_free(query);
  free(path_and_query);
  return error;
}

static HttpError_t static_followAnswer(HeaderFetchRun_t* run, HeaderFetchChain_t* chain, HeaderFetchHop_t* hop, char* location, bool* is_chain_ended_out)
{
  CURLU* target_url = NULL;
  if (hop->m_httpStatus >= 300 && hop->m_httpStatus <= 399 && location != NULL)
  {
    target_url = curl_url_dup(run->mp_url);
    if (target_url == NULL)
    {
      free(location);
      return HTTP_ERROR_OTHER;
    }
    if (curl_url_set(target_url, CURLUPART_URL, location, 0) != CURLUE_OK)
    {
      curl_url_cleanup(target_url);
      target_url                = NULL;
      chain->m_stopReason       = HEADER_FETCH_STOP_LOCATION_INVALID;
      chain->mp_invalidLocation = location;
      location                  = NULL;
    }
  }
  else
    chain->m_stopReason = HEADER_FETCH_STOP_FINAL_ANSWER;
  free(location);

  if (target_url != NULL)
    run->m_isUserInfoDropped = static_hasUserInfo(target_url);
  bool is_written = static_tryWriteUrl(run->mp_url, run->mp_policy->m_hopRule, &hop->mp_url);
  if (target_url != NULL)
  {
    curl_url_cleanup(run->mp_url);
    run->mp_url         = target_url;
    *is_chain_ended_out = false;
  }
  return is_written ? HTTP_ERROR_NONE : HTTP_ERROR_OTHER;
}

static char* static_takeCapturedValue(HttpResponse_t* response, int index)
{
  if (index >= response->m_capturedHeaderValueCount)
    return NULL;

  char* value = response->mp_capturedHeaderValues[index];
  response->mp_capturedHeaderValues[index] = NULL;
  return value;
}

static bool static_hasUserInfo(const CURLU* url)
{
  char* user     = NULL;
  char* password = NULL;
  bool has_user_info = curl_url_get(url, CURLUPART_USER, &user, 0) == CURLUE_OK ||
                       curl_url_get(url, CURLUPART_PASSWORD, &password, 0) == CURLUE_OK;
  curl_free(user);
  curl_free(password);
  return has_user_info;
}

static void static_keepLastAnswer(HeaderFetchRun_t* run, HeaderFetchChain_t* chain)
{
  HttpResponse_t* answer = &run->m_answer;
  int kept_count = answer->m_capturedHeaderValueCount < run->m_callerNameCount  ? answer->m_capturedHeaderValueCount 
                                                                                : run->m_callerNameCount;
  for (int i = kept_count; i < answer->m_capturedHeaderValueCount; i++)
    free(answer->mp_capturedHeaderValues[i]);

  if (kept_count > 0)
    chain->mp_capturedHeaderValues = answer->mp_capturedHeaderValues;
  else
    free(answer->mp_capturedHeaderValues);

  chain->m_capturedHeaderValueCount = kept_count;
  chain->m_setCookieCopyCount       = answer->m_setCookieCopyCount;
  chain->mp_body                    = answer->mp_body;
  chain->m_bodyLen                  = answer->m_bodyLen;
  chain->m_isBodyCut                = answer->m_isBodyCut;

  answer->mp_capturedHeaderValues    = NULL;
  answer->m_capturedHeaderValueCount = 0;
  answer->mp_body                    = NULL;
}

static void static_runFree(HeaderFetchRun_t* run)
{
  free(run->mp_headerNamesToCapture);
  curl_url_cleanup(run->mp_url);
  for (int i = 0; i < HEADER_FETCH_MAX_REQUEST_COUNT; i++)
    curl_free(run->ma_requestUrls[i]);
  free(run->mp_siteHost);
  http_free(&run->m_answer);
}

static bool static_isHostOrWwwPair(const char* host, const char* hostname)
{
  if (strcasecmp(host, hostname) == 0)
    return true;
  if (strncasecmp(hostname, HEADER_FETCH_WWW_PREFIX, HEADER_FETCH_WWW_PREFIX_LEN) == 0)
    return strcasecmp(host, hostname + HEADER_FETCH_WWW_PREFIX_LEN) == 0;

  return  strncasecmp(host, HEADER_FETCH_WWW_PREFIX, HEADER_FETCH_WWW_PREFIX_LEN) == 0 &&
          strcasecmp(host + HEADER_FETCH_WWW_PREFIX_LEN, hostname) == 0;
}

static bool static_tryWriteUrl(CURLU* url, HeaderFetchHopRule_t hop_rule, char** text_out)
{
  if (hop_rule == HEADER_FETCH_HOP_RULE_SAME_SITE)
    curl_url_set(url, CURLUPART_QUERY, NULL, 0);
  static_dropUserInfoAndFragment(url);

  return curl_url_get(url, CURLUPART_URL, text_out, CURLU_NO_DEFAULT_PORT) == CURLUE_OK;
}

static void static_dropUserInfoAndFragment(CURLU* url)
{
  curl_url_set(url, CURLUPART_USER,     NULL, 0);
  curl_url_set(url, CURLUPART_PASSWORD, NULL, 0);
  curl_url_set(url, CURLUPART_FRAGMENT, NULL, 0);
}

static bool static_isSameRequestUrl(const char* url, const char* other_url)
{
  size_t authority_end       = static_findAuthorityEnd(url);
  size_t other_authority_end = static_findAuthorityEnd(other_url);
  if (authority_end != other_authority_end)
    return false;
  if (strncasecmp(url, other_url, authority_end) != 0)
    return false;

  return strcmp(url + authority_end, other_url + authority_end) == 0;
}

static size_t static_findAuthorityEnd(const char* url)
{
  const char* scheme_end = strstr(url, "://");
  if (scheme_end == NULL)
    return 0;

  const char* authority = scheme_end + sizeof("://") - 1;
  const char* path      = strchr(authority, '/');
  return path != NULL ? (size_t)(path - url) : strlen(url);
}
