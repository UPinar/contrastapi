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
