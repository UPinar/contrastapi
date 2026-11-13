#ifndef HEADER_FETCH_H
#define HEADER_FETCH_H

#include <stdbool.h>
#include <stddef.h>

#include "header_check.h"
#include "http.h"
#include "validate.h"

#define HEADER_FETCH_PORT 443

#define HEADER_FETCH_DEADLINE_MS 5000

#define HEADER_FETCH_MAX_REDIRECT_COUNT 5

#define HEADER_FETCH_ADDRESS_NOT_GLOBALLY_REACHABLE_REFUSAL_MESSAGE   "hostname resolves to an address that is not globally reachable"

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

typedef struct {
  int     m_httpStatus;
  char*   mp_body;
  size_t  m_bodyLen;
  bool    m_isBodyCut;
} HeaderFetchRobotsTxt_t;

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

HttpError_t header_fetch_fetchHomePage  (const char* hostname, HeaderFetchResult_t* result_out);
HttpError_t header_fetch_fetchRobotsTxt (const char* hostname, HeaderFetchRobotsTxt_t* result_out);
void        header_fetch_resultFree     (HeaderFetchResult_t* result);
void        header_fetch_robotsTxtFree  (HeaderFetchRobotsTxt_t* result);

#endif
