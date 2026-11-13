#ifndef CERTSPOTTER_STUB_H
#define CERTSPOTTER_STUB_H

#include "external/certspotter.h"
#include "quota.h"
#include "validate.h"

typedef struct {
  CertSpotterStatus_t           m_status;
  CertSpotterCertificateList_t  m_certificateList;
  unsigned int                  m_retryAfterSeconds;
} CertSpotterStubAnswer_t;

extern const CertSpotterStubAnswer_t g_stub_CERTSPOTTER_default_answer;

extern CertSpotterStubAnswer_t g_stub_CERTSPOTTER_answer;

extern int                 g_stub_CERTSPOTTER_lookup_count;
extern char                g_stub_CERTSPOTTER_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern PGconn*             g_stub_CERTSPOTTER_last_lookup_conn;
extern const QuotaRule_t*  g_stub_CERTSPOTTER_last_lookup_rule;

extern bool g_stub_CERTSPOTTER_has_api_key;

extern void (*g_stub_CERTSPOTTER_on_call)(void);

#define CERTSPOTTER_STUB_SUBTREE_NAME_MAX_COUNT 64

typedef struct {
  CertSpotterStatus_t  m_status;
  char                 ma_names[CERTSPOTTER_STUB_SUBTREE_NAME_MAX_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  int                  m_nameCount;
  bool                 m_isAnswerEmpty;
  unsigned int         m_retryAfterSeconds;
} CertSpotterStubSubtreeAnswer_t;

extern const CertSpotterStubSubtreeAnswer_t g_stub_CERTSPOTTER_default_subtree_answer;

extern CertSpotterStubSubtreeAnswer_t g_stub_CERTSPOTTER_subtree_answer;

extern int  g_stub_CERTSPOTTER_subtree_lookup_count;
extern char g_stub_CERTSPOTTER_last_subtree_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

#endif
