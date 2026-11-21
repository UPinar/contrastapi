#include <stdlib.h>
#include <string.h>

#include "header_fetch_stub.h"

#define HEADER_FETCH_STUB_DEFAULT_ANSWER {                                                                      \
  .m_httpStatus             = 200,                                                                              \
  .mp_url                   = "https://www.stub.example.com/",                                                  \
  .m_followedRedirectCount  = 1,                                                                                \
  .mp_unfollowedRedirectUrl = NULL,                                                                             \
  .m_setCookieCopyCount     = 2,                                                                                \
  .ma_capturedHeaderValues  = {                                                                                 \
    [HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY]   = "default-src 'self'; object-src 'none'; base-uri 'self'", \
    [HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=31536000",                                       \
    [HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS]    = "nosniff",                                                \
    [HEADER_CHECK_HEADER_REFERRER_POLICY]           = "unsafe-url",                                             \
    [HEADER_CHECK_HEADER_X_XSS_PROTECTION]          = "1; mode=block",                                          \
    [HEADER_CHECK_HEADER_SET_COOKIE]                = "sid=STUBTOKEN; Secure; HttpOnly; SameSite=Lax\nlang=en",  \
    [HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN] = "null",                                                 \
  },                                                                                                            \
}

const HeaderFetchStubAnswer_t g_stub_HEADER_FETCH_default_answer = HEADER_FETCH_STUB_DEFAULT_ANSWER;

HttpError_t             g_stub_HEADER_FETCH_error  = HTTP_ERROR_NONE;
HeaderFetchStubAnswer_t g_stub_HEADER_FETCH_answer = HEADER_FETCH_STUB_DEFAULT_ANSWER;

int  g_stub_HEADER_FETCH_call_count = 0;
char g_stub_HEADER_FETCH_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";
int  g_stub_HEADER_FETCH_free_count = 0;

void (*g_stub_HEADER_FETCH_on_call)(void) = NULL;

static char* static_copyOrNull(const char* text)
{
  return text != NULL ? strdup(text) : NULL;
}

HttpError_t header_fetch_fetchHomePage(const char* hostname, HeaderFetchResult_t* result_out)
{
  g_stub_HEADER_FETCH_call_count++;
  if (g_stub_HEADER_FETCH_on_call)
    g_stub_HEADER_FETCH_on_call();
  strncpy(g_stub_HEADER_FETCH_last_hostname, hostname, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_HEADER_FETCH_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';

  memset(result_out, 0, sizeof(*result_out));
  if (g_stub_HEADER_FETCH_error != HTTP_ERROR_NONE)
    return g_stub_HEADER_FETCH_error;

  result_out->m_httpStatus               = g_stub_HEADER_FETCH_answer.m_httpStatus;
  result_out->mp_url                     = static_copyOrNull(g_stub_HEADER_FETCH_answer.mp_url);
  result_out->m_followedRedirectCount    = g_stub_HEADER_FETCH_answer.m_followedRedirectCount;
  result_out->mp_unfollowedRedirectUrl   = static_copyOrNull(g_stub_HEADER_FETCH_answer.mp_unfollowedRedirectUrl);
  result_out->m_isRedirectLimitReached   = g_stub_HEADER_FETCH_answer.m_isRedirectLimitReached;
  result_out->m_setCookieCopyCount       = g_stub_HEADER_FETCH_answer.m_setCookieCopyCount;
  result_out->mp_capturedHeaderValues    = calloc((size_t)HEADER_CHECK_HEADER_COUNT, sizeof(char*));
  result_out->m_capturedHeaderValueCount = HEADER_CHECK_HEADER_COUNT;
  for (int i = 0; i < HEADER_CHECK_HEADER_COUNT; i++)
    result_out->mp_capturedHeaderValues[i] = static_copyOrNull(g_stub_HEADER_FETCH_answer.ma_capturedHeaderValues[i]);
  return HTTP_ERROR_NONE;
}

void header_fetch_resultFree(HeaderFetchResult_t* result)
{
  g_stub_HEADER_FETCH_free_count++;
  free(result->mp_url);
  free(result->mp_unfollowedRedirectUrl);
  for (int i = 0; i < result->m_capturedHeaderValueCount; i++)
    free(result->mp_capturedHeaderValues[i]);
  free(result->mp_capturedHeaderValues);
  memset(result, 0, sizeof(*result));
}

HeaderFetchUrlStatus_t g_stub_HEADER_FETCH_url_status      = HEADER_FETCH_URL_OK;
int                    g_stub_HEADER_FETCH_url_check_count = 0;
const char*            g_stub_HEADER_FETCH_normal_url      = NULL;

#define HEADER_FETCH_STUB_DEFAULT_CHAIN_SCRIPT {                             \
  .ma_hops      = { { .mp_url = "https://www.stub.example.com/", .m_httpStatus = 200 } }, \
  .m_hopCount   = 1,                                                         \
  .m_stopReason = HEADER_FETCH_STOP_FINAL_ANSWER,                            \
}

const HeaderFetchStubChainScript_t g_stub_HEADER_FETCH_default_chain_script = HEADER_FETCH_STUB_DEFAULT_CHAIN_SCRIPT;

HttpError_t                  g_stub_HEADER_FETCH_chain_error  = HTTP_ERROR_NONE;
HeaderFetchStubChainScript_t g_stub_HEADER_FETCH_chain_script = HEADER_FETCH_STUB_DEFAULT_CHAIN_SCRIPT;

int                 g_stub_HEADER_FETCH_chain_call_count = 0;
char                g_stub_HEADER_FETCH_chain_first_url[HEADER_FETCH_MAX_URL_BYTE_COUNT + 1] = "";
HeaderFetchPolicy_t g_stub_HEADER_FETCH_chain_policy      = { 0 };
int64_t             g_stub_HEADER_FETCH_chain_deadline_ms = 0;
int                 g_stub_HEADER_FETCH_chain_free_count  = 0;

void (*g_stub_HEADER_FETCH_before_hop)(int hop_index) = NULL;

#define HEADER_FETCH_STUB_HOST_SIZE (VALIDATE_DOMAIN_NAME_MAX_LEN + 2)

HeaderFetchUrlStatus_t header_fetch_writeNormalUrl(const char* url, char* normal_url_out, size_t normal_url_size)
{
  g_stub_HEADER_FETCH_url_check_count++;
  normal_url_out[0] = '\0';
  if (g_stub_HEADER_FETCH_url_status != HEADER_FETCH_URL_OK)
    return g_stub_HEADER_FETCH_url_status;
  if (g_stub_HEADER_FETCH_normal_url != NULL)
    url = g_stub_HEADER_FETCH_normal_url;
  if (strlen(url) >= normal_url_size)
    return HEADER_FETCH_URL_TOO_LONG;
  strncpy(normal_url_out, url, normal_url_size);
  return HEADER_FETCH_URL_OK;
}

static HeaderFetchPermission_t static_askPermission(const HeaderFetchPolicy_t* policy, const char* url, unsigned* retry_after_seconds_out)
{
  if (policy->m_askPermission == NULL)
    return HEADER_FETCH_PERMISSION_ALLOWED;

  const char* authority = strstr(url, "://");
  authority = authority != NULL ? authority + 3 : url;
  size_t host_len = strcspn(authority, "/:");
  if (host_len >= HEADER_FETCH_STUB_HOST_SIZE)
    host_len = HEADER_FETCH_STUB_HOST_SIZE - 1;
  char host[HEADER_FETCH_STUB_HOST_SIZE];
  memcpy(host, authority, host_len);
  host[host_len] = '\0';
  const char* path_and_query = authority + strcspn(authority, "/");
  const HeaderFetchTarget_t target = { .mp_host = host, .mp_pathAndQuery = *path_and_query != '\0' ? path_and_query : "/" };
  return policy->m_askPermission(policy->mp_permissionContext, &target, retry_after_seconds_out);
}

HttpError_t header_fetch_fetchChain(const char* first_url, const HeaderFetchPolicy_t* policy, int64_t deadline_ms, HeaderFetchChain_t* chain_out)
{
  g_stub_HEADER_FETCH_chain_call_count++;
  strncpy(g_stub_HEADER_FETCH_chain_first_url, first_url, HEADER_FETCH_MAX_URL_BYTE_COUNT);
  g_stub_HEADER_FETCH_chain_first_url[HEADER_FETCH_MAX_URL_BYTE_COUNT] = '\0';
  g_stub_HEADER_FETCH_chain_policy      = *policy;
  g_stub_HEADER_FETCH_chain_deadline_ms = deadline_ms;

  memset(chain_out, 0, sizeof(*chain_out));
  if (g_stub_HEADER_FETCH_chain_error != HTTP_ERROR_NONE)
    return g_stub_HEADER_FETCH_chain_error;

  const HeaderFetchStubChainScript_t* script = &g_stub_HEADER_FETCH_chain_script;
  for (int i = 0; i < script->m_hopCount; i++)
  {
    const HeaderFetchStubHop_t* scripted_hop = &script->ma_hops[i];
    if (g_stub_HEADER_FETCH_before_hop != NULL)
      g_stub_HEADER_FETCH_before_hop(i);
    unsigned retry_after_seconds = 0;
    HeaderFetchPermission_t permission = static_askPermission(policy, scripted_hop->mp_url, &retry_after_seconds);
    if (permission != HEADER_FETCH_PERMISSION_ALLOWED)
    {
      chain_out->m_stopReason        = permission == HEADER_FETCH_PERMISSION_THROTTLED ? HEADER_FETCH_STOP_THROTTLED : HEADER_FETCH_STOP_PERMISSION_REFUSED;
      chain_out->m_retryAfterSeconds = permission == HEADER_FETCH_PERMISSION_THROTTLED ? retry_after_seconds : 0;
      chain_out->mp_unfollowedUrl    = strdup(scripted_hop->mp_url);
      return HTTP_ERROR_NONE;
    }
    HeaderFetchHop_t* hop = &chain_out->ma_hops[chain_out->m_hopCount++];
    hop->mp_url              = strdup(scripted_hop->mp_url);
    hop->m_httpStatus        = scripted_hop->m_httpStatus;
    hop->m_error             = scripted_hop->m_error;
    hop->m_isUserInfoDropped = scripted_hop->m_isUserInfoDropped;
    hop->mp_refresh          = static_copyOrNull(scripted_hop->mp_refresh);
  }
  chain_out->m_stopReason       = script->m_stopReason;
  chain_out->mp_unfollowedUrl   = static_copyOrNull(script->mp_unfollowedUrl);
  chain_out->mp_invalidLocation = static_copyOrNull(script->mp_invalidLocation);
  return HTTP_ERROR_NONE;
}

void header_fetch_chainFree(HeaderFetchChain_t* chain)
{
  g_stub_HEADER_FETCH_chain_free_count++;
  for (int i = 0; i < chain->m_hopCount; i++)
  {
    free(chain->ma_hops[i].mp_url);
    free(chain->ma_hops[i].mp_refresh);
  }
  free(chain->mp_unfollowedUrl);
  free(chain->mp_invalidLocation);
  memset(chain, 0, sizeof(*chain));
}
