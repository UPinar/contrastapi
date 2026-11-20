#ifndef HEADER_FETCH_H
#define HEADER_FETCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "header_check.h"
#include "http.h"
#include "validate.h"

#define HEADER_FETCH_PORT 443

#define HEADER_FETCH_DEADLINE_MS 5000

#define HEADER_FETCH_MAX_REDIRECT_COUNT 5

#define HEADER_FETCH_MAX_REQUEST_COUNT 10

#define HEADER_FETCH_MAX_URL_BYTE_COUNT 4096

#define HEADER_FETCH_ADDRESS_NOT_GLOBALLY_REACHABLE_REFUSAL_MESSAGE   "hostname resolves to an address that is not globally reachable"

typedef enum {
  HEADER_FETCH_HOP_RULE_SAME_SITE = 0,
  HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST
} HeaderFetchHopRule_t;

typedef enum {
  HEADER_FETCH_STOP_FINAL_ANSWER = 0,
  HEADER_FETCH_STOP_REQUEST_LIMIT,
  HEADER_FETCH_STOP_LOOP,
  HEADER_FETCH_STOP_LOCATION_INVALID,
  HEADER_FETCH_STOP_LOCATION_TOO_LONG,
  HEADER_FETCH_STOP_OFF_SITE,
  HEADER_FETCH_STOP_SCHEME_NOT_FOLLOWED,
  HEADER_FETCH_STOP_PORT_NOT_ALLOWED,
  HEADER_FETCH_STOP_IP_ADDRESS_NOT_FOLLOWED,
  HEADER_FETCH_STOP_HOST_NOT_PUBLIC,
  HEADER_FETCH_STOP_PERMISSION_REFUSED,
  HEADER_FETCH_STOP_THROTTLED,
  HEADER_FETCH_STOP_DEADLINE,
  HEADER_FETCH_STOP_REQUEST_FAILED
} HeaderFetchStopReason_t;

typedef enum {
  HEADER_FETCH_PERMISSION_ALLOWED = 0,
  HEADER_FETCH_PERMISSION_REFUSED,
  HEADER_FETCH_PERMISSION_THROTTLED
} HeaderFetchPermission_t;

typedef struct {
  const char*  mp_host;
  const char*  mp_pathAndQuery;
} HeaderFetchTarget_t;

typedef HeaderFetchPermission_t (*HeaderFetchAskPermissionFunction_t)(void* permission_context, const HeaderFetchTarget_t* target, unsigned* retry_after_seconds_out);

typedef struct {
  HeaderFetchHopRule_t                m_hopRule;
  size_t                              m_maxBodyByteCount;
  const char* const*                  mp_headerNamesToCapture;
  HeaderFetchAskPermissionFunction_t  m_askPermission;
  void*                               mp_permissionContext;
} HeaderFetchPolicy_t;

typedef struct {
  char*        mp_url;
  int          m_httpStatus;
  HttpError_t  m_error;
  bool         m_isUserInfoDropped;
  char*        mp_refresh;
} HeaderFetchHop_t;

typedef struct {
  HeaderFetchStopReason_t  m_stopReason;
  HeaderFetchHop_t         ma_hops[HEADER_FETCH_MAX_REQUEST_COUNT];
  int                      m_hopCount;
  char*                    mp_unfollowedUrl;
  char*                    mp_invalidLocation;
  unsigned                 m_retryAfterSeconds;
  char**                   mp_capturedHeaderValues;
  int                      m_capturedHeaderValueCount;
  size_t                   m_setCookieCopyCount;
  char*                    mp_body;
  size_t                   m_bodyLen;
  bool                     m_isBodyCut;
} HeaderFetchChain_t;

typedef struct {
  int     m_httpStatus;
  char*   mp_url;
  int     m_followedRedirectCount;
  char*   mp_unfollowedRedirectUrl;
  bool    m_isRedirectLimitReached;
  char**  mp_capturedHeaderValues;
  int     m_capturedHeaderValueCount;
  size_t  m_setCookieCopyCount;
} HeaderFetchResult_t;

#define HEADERSCHECK_CHECKED_AT_TEXT_SIZE 21

typedef struct {
  char  ma_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  bool  m_isFullHeaderValueIncluded;
} HEADERSCHECKParams_t;

typedef struct {
  HeaderFetchResult_t   m_fetchResult;
  HeaderCheckReport_t   m_report;
  char                  ma_checkedAt[HEADERSCHECK_CHECKED_AT_TEXT_SIZE];
} HEADERSCHECKRecord_t;

HttpError_t header_fetch_fetchChain     (const char* first_url, const HeaderFetchPolicy_t* policy, int64_t deadline_ms, HeaderFetchChain_t* chain_out);
void        header_fetch_chainFree      (HeaderFetchChain_t* chain);
HttpError_t header_fetch_chainError     (const HeaderFetchChain_t* chain);
HttpError_t header_fetch_fetchHomePage  (const char* hostname, HeaderFetchResult_t* result_out);
void        header_fetch_resultFree     (HeaderFetchResult_t* result);

#endif
