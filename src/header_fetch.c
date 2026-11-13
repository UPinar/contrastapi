#include <assert.h>
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
#include "robotstxt.h"
#include "validate.h"

#define HEADER_FETCH_MAX_BODY_BYTE_COUNT (64 * 1024)

#define HEADER_FETCH_PORT_TEXT MACRO_STR(HEADER_FETCH_PORT)

#define HEADER_FETCH_WWW_PREFIX       "www."
#define HEADER_FETCH_WWW_PREFIX_LEN   (sizeof(HEADER_FETCH_WWW_PREFIX) - 1)

typedef struct {
  const char*         mp_path;
  size_t              m_maxBodyByteCount;
  const char* const*  mp_headerNamesToCapture;
} HeaderFetchPath_t;

#define HEADER_FETCH_ROBOTS_TXT_PATH "/robots.txt"

static const HeaderFetchPath_t HEADER_FETCH_HOME_PAGE  = { "/",                          HEADER_FETCH_MAX_BODY_BYTE_COUNT, header_check_capturedHeaderNames };
static const HeaderFetchPath_t HEADER_FETCH_ROBOTS_TXT = { HEADER_FETCH_ROBOTS_TXT_PATH, ROBOTSTXT_MAX_BODY_BYTE_COUNT,    NULL                             };

#define HEADER_FETCH_FIRST_REQUEST_URL_SIZE (sizeof("https://" HEADER_FETCH_ROBOTS_TXT_PATH) + VALIDATE_DOMAIN_NAME_MAX_LEN)

static HttpError_t  static_fetchSitePath             (const char* hostname, const HeaderFetchPath_t* path, HeaderFetchResult_t* result_out, HeaderFetchRobotsTxt_t* robots_txt_out);
static HttpError_t  static_sendRequest               (CURLU* request_url, const HeaderFetchPath_t* path, int64_t deadline_ms, HttpResponse_t* response_out);
static bool         static_isTargetOnSite            (CURLU* target_url, const char* hostname);
static bool         static_isHostOrWwwPair           (const char* host, const char* hostname);
static void         static_dropLoginPortAndFragment  (CURLU* url);
static bool         static_tryWriteUrlWithoutQuery   (CURLU* url, char** text_out);

HttpError_t header_fetch_fetchHomePage(const char* hostname, HeaderFetchResult_t* result_out)
{
  assert(hostname   != NULL);
  assert(result_out != NULL);

  return static_fetchSitePath(hostname, &HEADER_FETCH_HOME_PAGE, result_out, NULL);
}

HttpError_t header_fetch_fetchRobotsTxt(const char* hostname, HeaderFetchRobotsTxt_t* result_out)
{
  assert(hostname   != NULL);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));
  HeaderFetchResult_t chain;
  HttpError_t error = static_fetchSitePath(hostname, &HEADER_FETCH_ROBOTS_TXT, &chain, result_out);
  header_fetch_resultFree(&chain);
  return error;
}

static HttpError_t static_fetchSitePath(const char* hostname, const HeaderFetchPath_t* path, HeaderFetchResult_t* result_out, HeaderFetchRobotsTxt_t* robots_txt_out)
{
  memset(result_out, 0, sizeof(*result_out));

  if (strnlen(hostname, VALIDATE_DOMAIN_NAME_MAX_LEN + 1) > VALIDATE_DOMAIN_NAME_MAX_LEN)
    return HTTP_ERROR_OTHER;
  char first_request_url[HEADER_FETCH_FIRST_REQUEST_URL_SIZE];
  int first_request_url_len = snprintf(first_request_url, sizeof(first_request_url), "https://%s%s", hostname, path->mp_path);
  if (first_request_url_len < 0 || (size_t)first_request_url_len >= sizeof(first_request_url))
    return HTTP_ERROR_OTHER;

  CURLU* request_url = curl_url();
  if (curl_url_set(request_url, CURLUPART_URL, first_request_url, 0) != CURLUE_OK)
  {
    curl_url_cleanup(request_url);
    return HTTP_ERROR_OTHER;
  }

  int64_t deadline_ms = monotonic_nowMs() + HEADER_FETCH_DEADLINE_MS;
  HttpResponse_t response = { 0 };
  HttpError_t error = static_sendRequest(request_url, path, deadline_ms, &response);
  CURLU* unfollowed_url = NULL;
  while (error == HTTP_ERROR_NONE && response.mp_redirectUrl != NULL)
  {
    CURLU* target_url = curl_url();
    if (target_url == NULL)
    {
      error = HTTP_ERROR_OTHER;
      break;
    }

    if (curl_url_set(target_url, CURLUPART_URL, response.mp_redirectUrl, 0) != CURLUE_OK)
    {
      curl_url_cleanup(target_url);
      break;
    }

    if (!static_isTargetOnSite(target_url, hostname))
    {
      unfollowed_url = target_url;
      break;
    }
    if (result_out->m_followedRedirectCount == HEADER_FETCH_MAX_REDIRECT_COUNT)
    {
      result_out->m_isRedirectLimitReached = true;
      unfollowed_url = target_url;
      break;
    }

    static_dropLoginPortAndFragment(target_url);
    curl_url_cleanup(request_url);
    request_url = target_url;
    result_out->m_followedRedirectCount++;
    http_free(&response);
    error = static_sendRequest(request_url, path, deadline_ms, &response);
  }

  if (error == HTTP_ERROR_NONE &&
      ((unfollowed_url != NULL && !static_tryWriteUrlWithoutQuery(unfollowed_url, &result_out->mp_unfollowedRedirectUrl)) ||
       !static_tryWriteUrlWithoutQuery(request_url, &result_out->mp_url)))
  {
    error = HTTP_ERROR_OTHER;
  }
  curl_url_cleanup(unfollowed_url);
  curl_url_cleanup(request_url);
  if (error != HTTP_ERROR_NONE)
  {
    http_free(&response);
    header_fetch_resultFree(result_out);
    return error;
  }

  result_out->m_httpStatus               = response.m_status;
  result_out->mp_capturedHeaderValues    = response.mp_capturedHeaderValues;
  result_out->m_capturedHeaderValueCount = response.m_capturedHeaderValueCount;
  result_out->m_setCookieCopyCount       = response.m_setCookieCopyCount;
  response.mp_capturedHeaderValues       = NULL;
  response.m_capturedHeaderValueCount    = 0;
  if (robots_txt_out != NULL)
  {
    robots_txt_out->m_httpStatus = response.m_status;
    robots_txt_out->mp_body      = response.mp_body;
    robots_txt_out->m_bodyLen    = response.m_bodyLen;
    robots_txt_out->m_isBodyCut  = response.m_isBodyCut;
    response.mp_body       = NULL;
  }
  http_free(&response);
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

void header_fetch_robotsTxtFree(HeaderFetchRobotsTxt_t* result)
{
  assert(result != NULL);

  free(result->mp_body);
  memset(result, 0, sizeof(*result));
}

static HttpError_t static_sendRequest(CURLU* request_url, const HeaderFetchPath_t* path, int64_t deadline_ms, HttpResponse_t* response_out)
{
  int64_t remaining_ms = deadline_ms - monotonic_nowMs();
  if (remaining_ms <= 0)
  {
    *response_out = (HttpResponse_t){ .m_error = HTTP_ERROR_TIMEOUT };
    return HTTP_ERROR_TIMEOUT;
  }

  char* url = NULL;
  if (curl_url_get(request_url, CURLUPART_URL, &url, 0) != CURLUE_OK)
  {
    *response_out = (HttpResponse_t){ .m_error = HTTP_ERROR_OTHER };
    return HTTP_ERROR_OTHER;
  }

  const HttpRequest_t request = {
    .mp_url                   = url,
    .m_timeoutMs              = (int)remaining_ms,
    .mp_extraHeaders          = NULL,
    .m_maxBodyByteCount       = path->m_maxBodyByteCount,
    .mp_headerNamesToCapture  = path->mp_headerNamesToCapture,
    .m_isTargetTrusted        = false,
    .m_isHttpsOnly            = true,
    .m_isRedirectLeftToCaller = true,
    .m_isBodyCutAccepted      = true,
    .m_requiredPort           = HEADER_FETCH_PORT,
  };
  *response_out = http_GETWithOptions(&request);

  curl_free(url);
  return response_out->m_error;
}

static bool static_isTargetOnSite(CURLU* target_url, const char* hostname)
{
  char* scheme = NULL;
  char* port   = NULL;
  char* host   = NULL;
  bool is_target_on_site =
      curl_url_get(target_url, CURLUPART_SCHEME, &scheme, 0)                == CURLUE_OK && strcmp(scheme, "https") == 0 &&
      curl_url_get(target_url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT)   == CURLUE_OK && strcmp(port, HEADER_FETCH_PORT_TEXT) == 0 &&
      curl_url_get(target_url, CURLUPART_HOST, &host, 0)                    == CURLUE_OK && static_isHostOrWwwPair(host, hostname);

  curl_free(scheme);
  curl_free(port);
  curl_free(host);
  return is_target_on_site;
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

static void static_dropLoginPortAndFragment(CURLU* url)
{
  curl_url_set(url, CURLUPART_USER,     NULL, 0);
  curl_url_set(url, CURLUPART_PASSWORD, NULL, 0);
  curl_url_set(url, CURLUPART_PORT,     NULL, 0);
  curl_url_set(url, CURLUPART_FRAGMENT, NULL, 0);
}

static bool static_tryWriteUrlWithoutQuery(CURLU* url, char** text_out)
{
  curl_url_set(url, CURLUPART_QUERY,    NULL, 0);
  curl_url_set(url, CURLUPART_FRAGMENT, NULL, 0);
  curl_url_set(url, CURLUPART_USER,     NULL, 0);
  curl_url_set(url, CURLUPART_PASSWORD, NULL, 0);
  return curl_url_get(url, CURLUPART_URL, text_out, CURLU_NO_DEFAULT_PORT) == CURLUE_OK;
}
