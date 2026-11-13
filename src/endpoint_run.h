#ifndef ENDPOINT_RUN_H
#define ENDPOINT_RUN_H

#include <libpq-fe.h>

#include "endpoint.h"
#include "jsonbuf.h"
#include "db.h"
#include "keyvault.h"
#include "pricing.h"

#define ENDPOINT_RUN_VENDOR_KEYS_MANAGE_URL_BUF_SIZE (sizeof(PRICING_VENDOR_KEYS_PAGE_URL "#l=") + KEYVAULT_VENDOR_KEY_LINK_LEN)

#define ENDPOINT_RUN_HEALTH_CACHE_TTL_MS 5000

EndpointRunStatus_t endpoint_HEALTHRun              (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVELOOKUPRun           (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVELOOKUPBULKRun       (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVEPRODUCTSRun         (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVESEARCHRun           (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVELEADINGRun          (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_KEVLOOKUPRun           (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CWELOOKUPRun           (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVERISKSCORERun        (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVEEXPLOITRun          (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVETRIAGERun           (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVETRIAGEBULKRun       (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_PRODUCTEXPOSURERun     (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CPESEARCHRun           (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CVSSCALCULATORRun      (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_PRIVACYMYDATARun       (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_PASSWORDCHECKRun       (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_DNSLOOKUPRun           (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_DNSTAKEOVERCHECKRun    (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_EMAILAUTHCHECKRun      (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_EMAILADDRESSCHECKRun   (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_SSLCHECKRun            (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_HEADERSCHECKRun        (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_WHOISLOOKUPRun         (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_WAYBACKLOOKUPRun       (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CERTSEARCHRun          (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_SUBDOMAINENUMRun       (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_IPLOOKUPRun            (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_ASNLOOKUPRun           (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_WATCHLISTEDITRun       (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_WATCHLISTEVENTSRun     (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_D3FENDFORATTACKRun     (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_DRIVERLOOKUPRun        (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_DRIVERLOOKUPBULKRun    (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_PACKAGECHECKRun        (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_PACKAGECHECKBULKRun    (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_IMAGEINSPECTRun        (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_WEBHOOKLEMONSQUEEZYRun (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_WEBHOOKNOWPAYMENTSRun  (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_APIKEYCLAIMRun         (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_CRYPTOCHECKOUTRun      (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);
EndpointRunStatus_t endpoint_VENDORKEYEDITRun       (PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out);

bool endpoint_WATCHLISTEDITWillAskResolver  (const EndpointAnyParams_t* params);
bool endpoint_VENDORKEYEDITWillCallVendor   (const EndpointAnyParams_t* params);
bool endpoint_tryWriteVendorKeysManageUrl   (PGconn* conn, const DbVendorKeys_t* vendor_keys, char* manage_url_out);

#endif
