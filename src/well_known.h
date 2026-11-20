#ifndef WELL_KNOWN_H
#define WELL_KNOWN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "header_fetch.h"
#include "http.h"
#include "robotstxt.h"
#include "securitytxt.h"

typedef enum {
  WELL_KNOWN_ROBOTS_UNKNOWN = 0,
  WELL_KNOWN_ROBOTS_FILE_READ,
  WELL_KNOWN_ROBOTS_NO_FILE
} WellKnownRobotsState_t;

typedef struct {
  HeaderFetchChain_t      m_chain;
  WellKnownRobotsState_t  m_state;
  RobotsTxt_t             m_robots;
  bool                    m_hasContentEncoding;
} WellKnownRobotsGate_t;

typedef enum {
  WELL_KNOWN_SECURITY_TXT_NOT_FETCHED = 0,
  WELL_KNOWN_SECURITY_TXT_FOUND,
  WELL_KNOWN_SECURITY_TXT_NOT_FOUND,
  WELL_KNOWN_SECURITY_TXT_TOO_LARGE,
  WELL_KNOWN_SECURITY_TXT_ROBOTS_DISALLOWED,
  WELL_KNOWN_SECURITY_TXT_ROBOTS_UNKNOWN,
  WELL_KNOWN_SECURITY_TXT_UNAVAILABLE
} WellKnownSecurityTxtStatus_t;

typedef struct {
  WellKnownSecurityTxtStatus_t  m_status;
  RobotsTxtVerdict_t            m_pathRobotsVerdict;
  HeaderFetchChain_t            m_chain;
  SecurityTxtReport_t           m_report;
  bool                          m_hasContentEncoding;
} WellKnownSecurityTxt_t;

typedef struct {
  WellKnownRobotsGate_t   m_robotsGate;
  WellKnownSecurityTxt_t  m_securityTxt;
} WellKnownReport_t;

HttpError_t         well_known_fetchRobotsGate   (const char* hostname, int64_t deadline_ms, WellKnownRobotsGate_t* gate_out);
RobotsTxtVerdict_t  well_known_robotsGateVerdict (const WellKnownRobotsGate_t* gate, const char* path, size_t path_len);
void                well_known_robotsGateFree    (WellKnownRobotsGate_t* gate);
HttpError_t         well_known_fetchFiles        (const char* hostname, int64_t now_epoch, WellKnownReport_t* report_out);
void                well_known_reportFree        (WellKnownReport_t* report);

#endif
