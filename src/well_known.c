#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include <curl/curl.h>

#include "well_known.h"
#include "header_fetch.h"
#include "http.h"
#include "monotonic.h"
#include "robotstxt.h"
#include "securitytxt.h"
#include "validate.h"

#define WELL_KNOWN_ROBOTS_TXT_PATH    "/robots.txt"
#define WELL_KNOWN_SECURITY_TXT_PATH  "/.well-known/security.txt"
#define WELL_KNOWN_FILE_URL_SIZE      (sizeof("https://" WELL_KNOWN_SECURITY_TXT_PATH) + VALIDATE_DOMAIN_NAME_MAX_LEN)

#define WELL_KNOWN_IDENTITY_ENCODING "identity"

static const char* const WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_NAMES[WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_COUNT + 1] = {
  [WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_CONTENT_TYPE]     = "Content-Type",
  [WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_CONTENT_ENCODING] = "Content-Encoding",
  [WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_COUNT]            = NULL,
};

static bool                     static_tryWriteFileUrl            (const char* hostname, const char* path, char* url_out, size_t url_size);
static WellKnownRobotsState_t   static_readRobotsAnswer           (const char* hostname, WellKnownRobotsGate_t* gate);
static void                     static_readSecurityTxtAnswer      (const char* hostname, int64_t now_epoch, WellKnownReport_t* report);
static HeaderFetchPermission_t  static_askRobotsGate              (void* permission_context, const HeaderFetchTarget_t* target, unsigned* retry_after_seconds_out);
static const char*              static_plainTextCheckHeaderValue  (const HeaderFetchChain_t* chain, WellKnownPlainTextCheckHeader_t header);
static bool                     static_hasContentEncoding         (const HeaderFetchChain_t* chain);
static int                      static_finalHttpStatus            (const HeaderFetchChain_t* chain);
static bool                     static_isRedirectedToOtherHost    (const HeaderFetchChain_t* chain, const char* hostname);
static bool                     static_didHopFetchRobotsTxtOfHost (const HeaderFetchChain_t* chain, int hop_index, const char* host);
static bool                     static_isHttpStatusInClass        (int http_status, int status_class);

HttpError_t well_known_fetchRobotsGate(const char* hostname, int64_t deadline_ms, WellKnownRobotsGate_t* gate_out)
{
  assert(hostname != NULL);
  assert(gate_out != NULL);

  memset(gate_out, 0, sizeof(*gate_out));
  char file_url[WELL_KNOWN_FILE_URL_SIZE];
  if (!static_tryWriteFileUrl(hostname, WELL_KNOWN_ROBOTS_TXT_PATH, file_url, sizeof(file_url)))
    return HTTP_ERROR_OTHER;

  const HeaderFetchPolicy_t policy = {
    .m_hopRule                = HEADER_FETCH_HOP_RULE_SAME_SITE,
    .m_maxBodyByteCount       = ROBOTSTXT_MAX_BODY_BYTE_COUNT,
    .mp_headerNamesToCapture  = WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_NAMES,
    .m_askPermission          = NULL,
    .mp_permissionContext     = NULL,
  };
  HttpError_t error = header_fetch_fetchChain(file_url, &policy, deadline_ms, &gate_out->m_chain);
  if (error != HTTP_ERROR_NONE)
    return error;
  error = header_fetch_chainError(&gate_out->m_chain);
  if (error != HTTP_ERROR_NONE)
  {
    well_known_robotsGateFree(gate_out);
    return error;
  }

  gate_out->m_state = static_readRobotsAnswer(hostname, gate_out);
  return HTTP_ERROR_NONE;
}

RobotsTxtVerdict_t well_known_robotsGateVerdict(const WellKnownRobotsGate_t* gate, const char* path, size_t path_len)
{
  assert(gate != NULL);
  assert(path != NULL || path_len == 0);

  if (gate->m_state == WELL_KNOWN_ROBOTS_NO_FILE)
    return (RobotsTxtVerdict_t){ ROBOTSTXT_DECISION_ALLOWED, -1 };
  else if (gate->m_state == WELL_KNOWN_ROBOTS_FILE_READ)
    return robotstxt_checkPath(&gate->m_robots, gate->m_chain.mp_body, path, path_len);
  return (RobotsTxtVerdict_t){ ROBOTSTXT_DECISION_UNKNOWN, -1 };
}

void well_known_robotsGateFree(WellKnownRobotsGate_t* gate)
{
  assert(gate != NULL);

  robotstxt_free(&gate->m_robots);
  header_fetch_chainFree(&gate->m_chain);
  memset(gate, 0, sizeof(*gate));
}

HttpError_t well_known_fetchFiles(const char* hostname, int64_t now_epoch, WellKnownReport_t* report_out)
{
  assert(hostname   != NULL);
  assert(report_out != NULL);

  memset(report_out, 0, sizeof(*report_out));
  int64_t deadline_ms = monotonic_nowMs() + HEADER_FETCH_DEADLINE_MS;
  HttpError_t error = well_known_fetchRobotsGate(hostname, deadline_ms, &report_out->m_robotsGate);
  if (error != HTTP_ERROR_NONE)
    return error;

  char file_url[WELL_KNOWN_FILE_URL_SIZE];
  if (!static_tryWriteFileUrl(hostname, WELL_KNOWN_SECURITY_TXT_PATH, file_url, sizeof(file_url)))
  {
    well_known_reportFree(report_out);
    return HTTP_ERROR_OTHER;
  }

  report_out->m_securityTxt.m_pathRobotsVerdict = (RobotsTxtVerdict_t){ ROBOTSTXT_DECISION_UNKNOWN, -1 };
  const HeaderFetchPolicy_t policy = {
    .m_hopRule                = HEADER_FETCH_HOP_RULE_SAME_SITE,
    .m_maxBodyByteCount       = SECURITYTXT_MAX_BODY_BYTE_COUNT,
    .mp_headerNamesToCapture  = WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_NAMES,
    .m_askPermission          = static_askRobotsGate,
    .mp_permissionContext     = report_out,
  };
  error = header_fetch_fetchChain(file_url, &policy, deadline_ms, &report_out->m_securityTxt.m_chain);
  if (error == HTTP_ERROR_TIMEOUT)
  {
    report_out->m_securityTxt.m_status = WELL_KNOWN_SECURITY_TXT_NOT_FETCHED;
    return HTTP_ERROR_NONE;
  }
  if (error == HTTP_ERROR_NONE && report_out->m_securityTxt.m_chain.m_stopReason == HEADER_FETCH_STOP_REQUEST_FAILED)
    error = header_fetch_chainError(&report_out->m_securityTxt.m_chain);
  if (error != HTTP_ERROR_NONE)
  {
    well_known_reportFree(report_out);
    return error;
  }

  static_readSecurityTxtAnswer(hostname, now_epoch, report_out);
  return HTTP_ERROR_NONE;
}

void well_known_reportFree(WellKnownReport_t* report)
{
  assert(report != NULL);

  well_known_robotsGateFree(&report->m_robotsGate);
  header_fetch_chainFree(&report->m_securityTxt.m_chain);
  memset(report, 0, sizeof(*report));
}

static bool static_tryWriteFileUrl(const char* hostname, const char* path, char* url_out, size_t url_size)
{
  if (strnlen(hostname, VALIDATE_DOMAIN_NAME_MAX_LEN + 1) > VALIDATE_DOMAIN_NAME_MAX_LEN)
    return false;
  int url_len = snprintf(url_out, url_size, "https://%s%s", hostname, path);
  return url_len >= 0 && (size_t)url_len < url_size;
}

static WellKnownRobotsState_t static_readRobotsAnswer(const char* hostname, WellKnownRobotsGate_t* gate)
{
  const HeaderFetchChain_t* chain = &gate->m_chain;
  int http_status = static_finalHttpStatus(chain);
  if (static_isHttpStatusInClass(http_status, 2))
  {
    if (static_hasContentEncoding(chain))
    {
      gate->m_hasContentEncoding = true;
      return WELL_KNOWN_ROBOTS_UNKNOWN;
    }
    if (!robotstxt_parse(chain->mp_body, chain->m_bodyLen, chain->m_isBodyCut, HTTP_USER_AGENT_PRODUCT_TOKEN, &gate->m_robots))
      return WELL_KNOWN_ROBOTS_UNKNOWN;

    robotstxt_checkResponse(&gate->m_robots,
                            static_plainTextCheckHeaderValue(chain, WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_CONTENT_TYPE),
                            static_isRedirectedToOtherHost(chain, hostname));
    return WELL_KNOWN_ROBOTS_FILE_READ;
  }
  else if (http_status == 429)
    return WELL_KNOWN_ROBOTS_UNKNOWN;
  else if (static_isHttpStatusInClass(http_status, 4))
    return WELL_KNOWN_ROBOTS_NO_FILE;
  return WELL_KNOWN_ROBOTS_UNKNOWN;
}

static void static_readSecurityTxtAnswer(const char* hostname, int64_t now_epoch, WellKnownReport_t* report)
{
  const HeaderFetchChain_t* chain = &report->m_securityTxt.m_chain;
  int http_status = static_finalHttpStatus(chain);
  if (chain->m_stopReason == HEADER_FETCH_STOP_PERMISSION_REFUSED)
  {
    bool is_disallowed = report->m_securityTxt.m_pathRobotsVerdict.m_decision == ROBOTSTXT_DECISION_DISALLOWED;
    report->m_securityTxt.m_status = is_disallowed ? WELL_KNOWN_SECURITY_TXT_ROBOTS_DISALLOWED : WELL_KNOWN_SECURITY_TXT_ROBOTS_UNKNOWN;
  }
  else if (static_isHttpStatusInClass(http_status, 3))
    report->m_securityTxt.m_status = WELL_KNOWN_SECURITY_TXT_NOT_FETCHED;
  else if (http_status == 429 || static_isHttpStatusInClass(http_status, 5))
    report->m_securityTxt.m_status = WELL_KNOWN_SECURITY_TXT_UNAVAILABLE;
  else if (static_isHttpStatusInClass(http_status, 2) && chain->m_isBodyCut)
    report->m_securityTxt.m_status = WELL_KNOWN_SECURITY_TXT_TOO_LARGE;
  else if (static_isHttpStatusInClass(http_status, 2))
  {
    report->m_securityTxt.m_status = WELL_KNOWN_SECURITY_TXT_FOUND;
    if (static_hasContentEncoding(chain))
    {
      report->m_securityTxt.m_hasContentEncoding = true;
      return;
    }
    securitytxt_parse(chain->mp_body, chain->m_bodyLen, false, now_epoch, &report->m_securityTxt.m_report);
    securitytxt_checkResponse(&report->m_securityTxt.m_report,
                              chain->mp_body,
                              static_plainTextCheckHeaderValue(chain, WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_CONTENT_TYPE),
                              chain->ma_hops[chain->m_hopCount - 1].mp_url,
                              static_isRedirectedToOtherHost(chain, hostname));
  }
  else
    report->m_securityTxt.m_status = WELL_KNOWN_SECURITY_TXT_NOT_FOUND;
}

static HeaderFetchPermission_t static_askRobotsGate(void* permission_context, const HeaderFetchTarget_t* target, unsigned* retry_after_seconds_out)
{
  (void)retry_after_seconds_out;
  WellKnownReport_t* report = permission_context;
  const HeaderFetchChain_t* robots_chain = &report->m_robotsGate.m_chain;
  int  last_hop_index = robots_chain->m_hopCount - 1;
  bool is_robots_host = last_hop_index >= 0 &&
                          (static_didHopFetchRobotsTxtOfHost(robots_chain, 0, target->mp_host) ||
                           static_didHopFetchRobotsTxtOfHost(robots_chain, last_hop_index, target->mp_host));
  if (!is_robots_host)
  {
    report->m_securityTxt.m_pathRobotsVerdict = (RobotsTxtVerdict_t){ ROBOTSTXT_DECISION_UNKNOWN, -1 };
    return HEADER_FETCH_PERMISSION_REFUSED;
  }
  report->m_securityTxt.m_pathRobotsVerdict = well_known_robotsGateVerdict( &report->m_robotsGate, 
                                                                            target->mp_pathAndQuery, 
                                                                            strlen(target->mp_pathAndQuery));
  return report->m_securityTxt.m_pathRobotsVerdict.m_decision == ROBOTSTXT_DECISION_ALLOWED ? HEADER_FETCH_PERMISSION_ALLOWED 
                                                                                            : HEADER_FETCH_PERMISSION_REFUSED;
}

static const char* static_plainTextCheckHeaderValue(const HeaderFetchChain_t* chain, WellKnownPlainTextCheckHeader_t header)
{
  if ((int)header >= chain->m_capturedHeaderValueCount)
    return NULL;
  return chain->mp_capturedHeaderValues[header];
}

static bool static_hasContentEncoding(const HeaderFetchChain_t* chain)
{
  const char* encoding = static_plainTextCheckHeaderValue(chain, WELL_KNOWN_PLAIN_TEXT_CHECK_HEADER_CONTENT_ENCODING);
  return encoding != NULL && strcasecmp(encoding, WELL_KNOWN_IDENTITY_ENCODING) != 0;
}

static int static_finalHttpStatus(const HeaderFetchChain_t* chain)
{
  return chain->m_hopCount > 0 ? chain->ma_hops[chain->m_hopCount - 1].m_httpStatus : 0;
}

static bool static_isRedirectedToOtherHost(const HeaderFetchChain_t* chain, const char* hostname)
{
  CURLU* url  = curl_url();
  char*  host = NULL;
  bool is_other =
      curl_url_set(url, CURLUPART_URL, chain->ma_hops[chain->m_hopCount - 1].mp_url, 0) == CURLUE_OK  &&
      curl_url_get(url, CURLUPART_HOST, &host, 0) == CURLUE_OK                                        &&
      strcasecmp(host, hostname) != 0;
  curl_free(host);
  curl_url_cleanup(url);
  return is_other;
}

static bool static_didHopFetchRobotsTxtOfHost(const HeaderFetchChain_t* chain, int hop_index, const char* host)
{
  assert(hop_index >= 0 && hop_index < chain->m_hopCount);

  CURLU* url      = curl_url();
  char*  hop_host = NULL;
  char*  hop_path = NULL;
  bool did_hop_fetch_robots_txt_of_host =
      curl_url_set(url, CURLUPART_URL, chain->ma_hops[hop_index].mp_url, 0) == CURLUE_OK &&
      curl_url_get(url, CURLUPART_HOST, &hop_host, 0)                       == CURLUE_OK &&
      curl_url_get(url, CURLUPART_PATH, &hop_path, 0)                       == CURLUE_OK &&
      strcasecmp(hop_host, host) == 0                                                    &&
      strcmp(hop_path, WELL_KNOWN_ROBOTS_TXT_PATH) == 0;
  curl_free(hop_host);
  curl_free(hop_path);
  curl_url_cleanup(url);
  return did_hop_fetch_robots_txt_of_host;
}

static bool static_isHttpStatusInClass(int http_status, int status_class)
{
  return http_status >= status_class * 100 && http_status <= status_class * 100 + 99;
}
