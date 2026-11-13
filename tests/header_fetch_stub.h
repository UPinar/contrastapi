#ifndef HEADER_FETCH_STUB_H
#define HEADER_FETCH_STUB_H

#include "header_check.h"
#include "header_fetch.h"
#include "http.h"
#include "validate.h"

typedef struct {
  int         m_httpStatus;
  const char* mp_url;
  int         m_followedRedirectCount;
  const char* mp_unfollowedRedirectUrl;
  bool        m_isRedirectLimitReached;
  size_t      m_setCookieCopyCount;
  const char* ma_capturedHeaderValues[HEADER_CHECK_HEADER_COUNT];
} HeaderFetchStubAnswer_t;

extern const HeaderFetchStubAnswer_t g_stub_HEADER_FETCH_default_answer;

extern HttpError_t             g_stub_HEADER_FETCH_error;
extern HeaderFetchStubAnswer_t g_stub_HEADER_FETCH_answer;

extern int  g_stub_HEADER_FETCH_call_count;
extern char g_stub_HEADER_FETCH_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern int  g_stub_HEADER_FETCH_free_count;

extern void (*g_stub_HEADER_FETCH_on_call)(void);

#endif
