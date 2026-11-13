#ifndef ENDPOINT_H
#define ENDPOINT_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include <libpq-fe.h>

#include "bulk.h"
#include "cve.h"
#include "cvss.h"
#include "jsonbuf.h"
#include "jsonread.h"
#include "picohttpparser.h"
#include "request.h"
#include "external/hibp.h"
#include "dns.h"
#include "emailcheck.h"
#include "tlsprobe.h"
#include "header_fetch.h"
#include "external/rdap.h"
#include "external/wayback.h"
#include "external/certspotter.h"
#include "subdomain.h"
#include "ip.h"
#include "watchlist/watchlist.h"
#include "d3fend.h"
#include "lol.h"
#include "package.h"
#include "billing.h"
#include "validate.h"
#include "vendorkey.h"

#define ENDPOINT_SCALAR_VALUE_BUF_SIZE 32

#define ENDPOINT_JSON_OBJECT_BUF_SIZE 2048

#define ENDPOINT_MESSAGE_BUF_SIZE 256

#define ENDPOINT_GATE_FALLBACK_REFUSAL_MESSAGE "a parameter was refused"

#define ENDPOINT_PACKAGE_ITEM_SCHEMA_JSON \
  R"({"type":"object","properties":{"ecosystem":{"type":"string"},"name":{"type":"string"},"version":{"type":"string"}},"required":["ecosystem","name","version"],"additionalProperties":false})"

#define ENDPOINT_PACKAGE_ITEM_OPTIONAL_VERSION_SCHEMA_JSON \
  R"({"type":"object","properties":{"ecosystem":{"type":"string"},"name":{"type":"string"},"version":{"type":"string"}},"required":["ecosystem","name"],"additionalProperties":false})"

typedef enum {
  ENDPOINT_COST_FLAT,
  ENDPOINT_COST_BULK_IDS,
} EndpointCostRule_t;

typedef enum {
  ENDPOINT_PARAM_TYPE_STRING,
  ENDPOINT_PARAM_TYPE_ENUM,
  ENDPOINT_PARAM_TYPE_INT,
  ENDPOINT_PARAM_TYPE_DOUBLE,
  ENDPOINT_PARAM_TYPE_BOOL,
  ENDPOINT_PARAM_TYPE_KEV_FILTER,
  ENDPOINT_PARAM_TYPE_CVE_ID,
  ENDPOINT_PARAM_TYPE_CWE_ID,
  ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY,
  ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY,
  ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY,
  ENDPOINT_PARAM_TYPE_BYTES,
} EndpointParamType_t;

typedef enum {
  ENDPOINT_PARAM_SRC_REST_QUERY         = 1u << 0,
  ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT  = 1u << 1,
  ENDPOINT_PARAM_SRC_REST_BODY          = 1u << 2,
  ENDPOINT_PARAM_SRC_MCP_ARG            = 1u << 3,
  ENDPOINT_PARAM_SRC_REST_RAW_BODY      = 1u << 4,
  ENDPOINT_PARAM_SRC_REST_HEADER        = 1u << 5,
} EndpointParamSource_t;

typedef struct {
  const char*         mp_name;
  EndpointParamType_t m_type;
  double              m_min;
  double              m_max;
  size_t              m_maxLen;
  const char* const*  mp_enumValues;
  bool                m_isOnlyTrueAccepted;
  bool               (*m_validatorFunction)(const char* value);
  const char*         mp_message;
  bool                m_isPathSegmentPercentDecoded;
  bool                m_isWrittenInLowerCase;
  bool                m_isPackageVersionOptional;
  double              m_default;
} EndpointParamSpec_t;

typedef struct {
  const EndpointParamSpec_t* mp_spec;
  unsigned int               m_sources;
  bool                       m_isRequired;
  const char*                mp_mcpArgDescription;
  size_t                     m_offset;
  size_t                     m_size;
} EndpointParam_t;

typedef struct {
  const unsigned char* mp_bytes;
  size_t               m_byteCount;
} EndpointByteSpan_t;

typedef struct {
  const char*               mp_pathSegment;
  const char*               mp_query;
  EndpointByteSpan_t        m_body;
  const struct phr_header*  mp_headers;
  size_t                    m_headerCount;
} EndpointRestInput_t;

typedef struct {
  EndpointByteSpan_t m_image;
} IMAGEINSPECTParams_t;

typedef struct {
  EndpointByteSpan_t  m_body;
  char                ma_signature[BILLING_LEMONSQUEEZY_SIGNATURE_LEN + 1];
} WEBHOOKLEMONSQUEEZYParams_t;

typedef struct {
  EndpointByteSpan_t  m_body;
  char                ma_signature[BILLING_NOWPAYMENTS_SIGNATURE_LEN + 1];
} WEBHOOKNOWPAYMENTSParams_t;

typedef struct {
  char ma_orderId[VALIDATE_UUID_LEN + 1];
} APIKEYCLAIMParams_t;

typedef struct {
  const RequestCreditBudget_t* mp_creditBudget;
} PRIVACYMYDATAParams_t;

typedef union {
  const RequestCreditBudget_t* mp_creditBudget;
  CVELOOKUPParams_t            m_cveLookup;
  CveIdParams_t                m_cveId;
  CWELOOKUPParams_t            m_cweLookup;
  CVESEARCHParams_t            m_cveSearch;
  CVELEADINGParams_t           m_cveLeading;
  CVETRIAGEParams_t            m_cveTriage;
  PRODUCTEXPOSUREParams_t      m_productExposure;
  CPESEARCHParams_t            m_cpeSearch;
  CVEPRODUCTSParams_t          m_cveProducts;
  CVSSCALCULATORParams_t       m_cvssCalculator;
  BulkIdsParams_t              m_bulkIds;
  PRIVACYMYDATAParams_t        m_privacyMyData;
  PASSWORDCHECKParams_t        m_passwordCheck;
  DNSLOOKUPParams_t            m_dnsLookup;
  DNSTAKEOVERCHECKParams_t     m_dnsTakeoverCheck;
  EMAILAUTHCHECKParams_t       m_emailAuthCheck;
  EMAILADDRESSCHECKParams_t    m_emailAddressCheck;
  SSLCHECKParams_t             m_sslCheck;
  HEADERSCHECKParams_t         m_headersCheck;
  WHOISLOOKUPParams_t          m_whoisLookup;
  WAYBACKLOOKUPParams_t        m_waybackLookup;
  CERTSEARCHParams_t           m_certSearch;
  SUBDOMAINENUMParams_t        m_subdomainEnum;
  IPLOOKUPParams_t             m_ipLookup;
  ASNLOOKUPParams_t            m_asnLookup;
  WATCHLISTEDITParams_t        m_watchlistEdit;
  WATCHLISTEVENTSParams_t      m_watchlistEvents;
  D3FENDFORATTACKParams_t      m_d3fendForAttack;
  DRIVERLOOKUPParams_t         m_driverLookup;
  PACKAGECHECKParams_t         m_packageCheck;
  PACKAGECHECKBULKParams_t     m_packageCheckBulk;
  IMAGEINSPECTParams_t         m_imageInspect;
  WEBHOOKLEMONSQUEEZYParams_t  m_webhookLemonSqueezy;
  WEBHOOKNOWPAYMENTSParams_t   m_webhookNowPayments;
  APIKEYCLAIMParams_t          m_apiKeyClaim;
  VENDORKEYEDITParams_t        m_vendorKeyEdit;
} EndpointAnyParams_t;

typedef enum {
  ENDPOINT_RUN_OK = 0,
  ENDPOINT_RUN_NOT_FOUND,
  ENDPOINT_RUN_REFUSED,
  ENDPOINT_RUN_REFUSED_WITH_BODY,
  ENDPOINT_RUN_DEGRADED,
  ENDPOINT_RUN_DB_ERROR,
  ENDPOINT_RUN_UPSTREAM_ERROR,
  ENDPOINT_RUN_TARGET_UNREACHABLE,
  ENDPOINT_RUN_NO_MEMORY,
  ENDPOINT_RUN_NO_CONNECTION,
  ENDPOINT_RUN_NO_CREDIT_BUDGET,
  ENDPOINT_RUN_UNAUTHORIZED,
  ENDPOINT_RUN_GONE,
} EndpointRunStatus_t;

typedef struct {
  EndpointRunStatus_t m_status;
  char*               mp_body;
  const char*         mp_message;
} EndpointRunResult_t;

#define ENDPOINT_FULL_CHARGE UINT_MAX

typedef EndpointRunStatus_t (*EndpointRunFunction_t)(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);

typedef EndpointRunStatus_t (*EndpointWeighFunction_t)(PGconn* conn, const EndpointAnyParams_t* params, int weighed_item_count, int* served_item_count_out);

typedef bool (*EndpointCallsUpstreamFunction_t)(const EndpointAnyParams_t* params);

typedef enum {
  ENDPOINT_MCP_TOOL_CATEGORY_NONE = 0,
  ENDPOINT_MCP_TOOL_CATEGORY_CVE,
  ENDPOINT_MCP_TOOL_CATEGORY_PACKAGE,
  ENDPOINT_MCP_TOOL_CATEGORY_CREDENTIAL,
  ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
  ENDPOINT_MCP_TOOL_CATEGORY_IP,
  ENDPOINT_MCP_TOOL_CATEGORY_THREAT_DEFENSE,
  ENDPOINT_MCP_TOOL_CATEGORY_MONITORING,
  ENDPOINT_MCP_TOOL_CATEGORY_OPERATIONS,
} EndpointMcpToolCategory_t;

typedef enum {
  ENDPOINT_MCP_TOOL_EFFECT_NONE = 0,
  ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
  ENDPOINT_MCP_TOOL_EFFECT_MOVES_POSITION,
  ENDPOINT_MCP_TOOL_EFFECT_EDITS,
} EndpointMcpToolEffect_t;

typedef struct {
  const char*                     mp_httpPath;
  bool                            m_hasPathSegment;
  const char*                     ma_allowedMethods[8];
  bool                            m_isMcpEndpoint;
  bool                            m_readsCreditBudget;
  bool                            m_isPayable;
  const char*                     mp_mcpToolName;
  const char*                     mp_mcpToolDescription;
  const char*                     mp_mcpToolTitle;
  EndpointMcpToolCategory_t       m_mcpToolCategory;
  EndpointMcpToolEffect_t         m_mcpToolEffect;
  unsigned int                    m_creditCost;
  EndpointCostRule_t              m_costRule;
  const EndpointParam_t*          mp_params;
  int                             m_paramCount;
  size_t                          m_paramsSize;
  const char*                     mp_notFoundMessage;
  EndpointRunFunction_t           m_runFunction;
  EndpointWeighFunction_t         m_weighFunction;
  bool                            m_isDbRequired;
  bool                            m_callsUpstream;
  EndpointCallsUpstreamFunction_t m_callsUpstreamFunction;
  size_t                          m_jsonCeiling;
} Endpoint_t;

#define ENDPOINT_MAX_BODY_BYTE_COUNT (16u * 1024u * 1024u)

#define ENDPOINT_SMALL_RAW_BODY_MAX_BYTE_COUNT (64u * 1024u)

#define ENDPOINT_MCP_ENVELOPE_RESERVE_BYTE_COUNT  4096

#define ENDPOINT_MCP_MAX_BODY_BYTE_COUNT  (PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE + ENDPOINT_MCP_ENVELOPE_RESERVE_BYTE_COUNT)

#define ENDPOINT_MAX_PARAMS 32

typedef enum {
  ENDPOINT_GATE_OK = 0,
  ENDPOINT_GATE_REJECT_MISSING,
  ENDPOINT_GATE_REJECT_TOOLONG,
  ENDPOINT_GATE_REJECT_VALUE,
  ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,
  ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME,
  ENDPOINT_GATE_REJECT_MALFORMED_PARAM,
  ENDPOINT_GATE_REJECT_BODY,
  ENDPOINT_GATE_REJECT_ITEMS_EMPTY,
  ENDPOINT_GATE_REJECT_ITEMS_TOO_MANY,
  ENDPOINT_GATE_REJECT_ITEMS_REPEATED,
  ENDPOINT_GATE_REJECT_BODY_TOO_LARGE,
  ENDPOINT_GATE_REJECT_ESCAPE,
  ENDPOINT_GATE_REJECT_TYPE,
  ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE,
  ENDPOINT_GATE_REJECT_ENCODING,
  ENDPOINT_GATE_REJECT_CONTROL_CHAR,
  ENDPOINT_GATE_REJECT_INVALID_UTF8,
} EndpointGateStatus_t;

typedef struct {
  EndpointGateStatus_t m_status;
  int                  m_refusedParamIndex;
  int                  m_duplicateItemIndex;
  int                  m_originalItemIndex;
} EndpointGateResult_t;

typedef struct {
  unsigned int        m_creditCost;
  bool                m_isPartialChargeAllowed;
  bool                m_willCallUpstream;
  bool                m_isPaymentOfferable;
  const Endpoint_t*   mp_pricedEndpoint;
  const Endpoint_t*   mp_weighedEndpoint;
  EndpointAnyParams_t m_weighedParams;
} EndpointPrice_t;

typedef enum {
  ENDPOINT_PARAM_NAME_LIST_WRITTEN,
  ENDPOINT_PARAM_NAME_LIST_EMPTY,
  ENDPOINT_PARAM_NAME_LIST_TOO_LONG,
} EndpointParamNameListStatus_t;

typedef enum {
  ENDPOINT_REFUSAL_MESSAGE_NAMES_PARAM,
  ENDPOINT_REFUSAL_MESSAGE_FALLBACK,
} EndpointRefusalMessage_t;

extern const Endpoint_t endpoints[];
extern const int        endpoint_count;

const Endpoint_t*              endpoint_findByHttpPath                      (const char* path, const char** path_segment_out);
const Endpoint_t*              endpoint_findByMcpName                       (const char* tool_name);
int                            endpoint_mcpToolCount                        (void);
const char*                    endpoint_mcpToolCategoryName                 (EndpointMcpToolCategory_t category);
EndpointGateResult_t           endpoint_checkHttpQueryParamNames            (const Endpoint_t* endpoint, const char* query);
EndpointGateResult_t           endpoint_restQueryGate                       (const Endpoint_t* endpoint, const char* query, void* params_out, size_t params_size);
EndpointGateResult_t           endpoint_restPathSegmentGate                 (const Endpoint_t* endpoint, const char* path_segment, void* params_out, size_t params_size);
EndpointGateResult_t           endpoint_restBulkBodyGate                    (const Endpoint_t* endpoint, const char* body, void* params_out, size_t params_size);
EndpointGateResult_t           endpoint_restFieldsBodyGate                  (const Endpoint_t* endpoint, const char* body, void* params_out, size_t params_size);
EndpointGateResult_t           endpoint_restRequestGate                     (const Endpoint_t* endpoint, const EndpointRestInput_t* input, void* params_out, size_t params_size);
EndpointGateResult_t           endpoint_mcpArgsGate                         (const Endpoint_t* endpoint, JsonReadSpan_t args_span, void* params_out, size_t params_size);
bool                           endpoint_isHttpMethodAllowed                 (const Endpoint_t* endpoint, const char* http_method);
bool                           endpoint_isIdArrayType                       (EndpointParamType_t type);
const char*                    endpoint_jsonSchemaTypeName                  (EndpointParamType_t type);
bool                           endpoint_isBulkArrayType                     (EndpointParamType_t type);
void                           endpoint_appendSchemaBounds                  (const EndpointParamSpec_t* spec, JsonBuf_t* json_buf);
size_t                         endpoint_jsonObjectSizeLimit                 (const Endpoint_t* endpoint);
bool                           endpoint_tryReadPackageItem                  (JsonReadSpan_t element_span, PACKAGECHECKBULKItem_t* item_out);
bool                           endpoint_readKeptPackageItems                (const PACKAGECHECKBULKParams_t* bulk_params, int read_count, PACKAGECHECKBULKItem_t** items_out);
bool                           endpoint_readWatchlistPackageElements        (const PACKAGECHECKBULKParams_t* package_list, WATCHLISTEDITPackageElement_t** elements_out);
bool                           endpoint_hasRestBodyParam                    (const Endpoint_t* endpoint);
bool                           endpoint_hasPackageArrayWithOtherMembers     (const Endpoint_t* endpoint);
bool                           endpoint_hasRawBodyParam                     (const Endpoint_t* endpoint);
size_t                         endpoint_rawBodyByteLimit                    (const Endpoint_t* endpoint);
unsigned int                   endpoint_price                               (const Endpoint_t* endpoint, EndpointGateStatus_t gate_status, const EndpointAnyParams_t* params, size_t params_size);
bool                           endpoint_willCallUpstream                    (const Endpoint_t* endpoint, EndpointGateStatus_t gate_status, const EndpointAnyParams_t* params);
bool                           endpoint_isPartialChargeAllowed              (const Endpoint_t* endpoint);
void                           endpoint_limitWorkToCharge                   (const Endpoint_t* endpoint, EndpointAnyParams_t* params, unsigned int charged_credit_count);
EndpointRunStatus_t            endpoint_limitWorkToWeight                   (const Endpoint_t* endpoint, PGconn* conn, EndpointAnyParams_t* params, unsigned int max_item_count);
EndpointRunResult_t            endpoint_runRow                              (const Endpoint_t* endpoint, EndpointAnyParams_t* params, PGconn* conn, const RequestCharge_t* charge);
EndpointRefusalMessage_t       endpoint_writeGateRefusalMessage             (const Endpoint_t* endpoint, EndpointGateResult_t gate_result, char* message_out, size_t message_size);
EndpointParamNameListStatus_t  endpoint_appendParamNameListToRefusalMessage (const Endpoint_t* endpoint, unsigned int param_source, char* refusal_message, size_t refusal_message_size);

#endif
