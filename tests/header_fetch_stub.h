#ifndef HEADER_FETCH_STUB_H
#define HEADER_FETCH_STUB_H

#include <stdint.h>

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

extern HeaderFetchUrlStatus_t g_stub_HEADER_FETCH_url_status;
extern int                    g_stub_HEADER_FETCH_url_check_count;

typedef struct {
  const char*  mp_url;
  int          m_httpStatus;
  HttpError_t  m_error;
  bool         m_isUserInfoDropped;
  const char*  mp_refresh;
} HeaderFetchStubHop_t;

typedef struct {
  HeaderFetchStubHop_t     ma_hops[HEADER_FETCH_MAX_REQUEST_COUNT];
  int                      m_hopCount;
  HeaderFetchStopReason_t  m_stopReason;
  const char*              mp_unfollowedUrl;
  const char*              mp_invalidLocation;
} HeaderFetchStubChainScript_t;

extern HttpError_t                  g_stub_HEADER_FETCH_chain_error;
extern HeaderFetchStubChainScript_t g_stub_HEADER_FETCH_chain_script;

extern const char* g_stub_HEADER_FETCH_normal_url;

extern const HeaderFetchStubChainScript_t g_stub_HEADER_FETCH_default_chain_script;

extern int                 g_stub_HEADER_FETCH_chain_call_count;
extern char                g_stub_HEADER_FETCH_chain_first_url[HEADER_FETCH_MAX_URL_BYTE_COUNT + 1];
extern HeaderFetchPolicy_t g_stub_HEADER_FETCH_chain_policy;
extern int64_t             g_stub_HEADER_FETCH_chain_deadline_ms;
extern int                 g_stub_HEADER_FETCH_chain_free_count;

extern void (*g_stub_HEADER_FETCH_before_hop)(int hop_index);

#endif
