#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "cve.h"
#include "cvss.h"
#include "jsonbuf.h"
#include "db.h"
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
#include "watchlist/watchlist.h"
#include "d3fend.h"
#include "lol.h"
#include "ip.h"
#include "package.h"
#include "imagescan.h"
#include "exifclient.h"
#include "imageindicator.h"
#include "vendorkey.h"

void   serialize_CVELOOKUP_response                         (const CVELOOKUPRecord_t* record, JsonBuf_t* json_buf);
void   serialize_CVELOOKUPBULK_response                     (const CVELOOKUPBULKResult_t* results, JsonBuf_t* json_buf);
void   serialize_CVEPRODUCTS_response                       (const CVEPRODUCTSResult_t* result, const CVEPRODUCTSParams_t* params, JsonBuf_t* json_buf);
void   serialize_CVESEARCH_response                         (const CveListResult_t* results, const CVESEARCHParams_t* params, JsonBuf_t* json_buf);
void   serialize_CVELEADING_response                        (const CveListResult_t* results, const CVELEADINGParams_t* params, JsonBuf_t* json_buf);
void   serialize_KEVLOOKUP_response                         (const KEVLOOKUPRecord_t* record, JsonBuf_t* json_buf);
void   serialize_CWELOOKUP_response                         (const CWELOOKUPRecord_t* record, JsonBuf_t* json_buf);
void   serialize_HEALTH_response                            (const HEALTHData_t* db, JsonBuf_t* json_buf);
void   serialize_CVERISKSCORE_response                      (const CVERISKSCORERecord_t* record, JsonBuf_t* json_buf);
void   serialize_CVEEXPLOIT_response                        (const CVEEXPLOITRecord_t* record, JsonBuf_t* json_buf);
void   serialize_CVETRIAGE_response                         (const CVETRIAGEResult_t* results, const CVETRIAGEParams_t* params, JsonBuf_t* json_buf);
void   serialize_CVETRIAGEBULK_response                     (const CVETRIAGEBULKResult_t* results, JsonBuf_t* json_buf);
void   serialize_PRODUCTEXPOSURE_response                   (const PRODUCTEXPOSURERecord_t* record, JsonBuf_t* json_buf);
void   serialize_CPESEARCH_response                         (const CPESEARCHResult_t* results, const CPESEARCHParams_t* params, JsonBuf_t* json_buf);
void   serialize_CVSSCALCULATOR_response                    (const CvssResult_t* result, JsonBuf_t* json_buf);
void   serialize_PRIVACYMYDATA_response                     (const RequestCreditBudget_t* credit_budget, const char* resets_in, const PRIVACYMYDATAVendorKeys_t* vendor_keys, JsonBuf_t* json_buf);
void   serialize_PASSWORDCHECK_response                     (const PASSWORDCHECKRecord_t* record, JsonBuf_t* json_buf);
void   serialize_DNSLOOKUP_response                         (const DNSLOOKUPRecord_t* record, JsonBuf_t* json_buf);
void   serialize_DNSTAKEOVERCHECK_response                  (const DNSTAKEOVERCHECKRecord_t* record, JsonBuf_t* json_buf);
void   serialize_EMAILAUTHCHECK_response                    (const EMAILAUTHCHECKRecord_t* record, JsonBuf_t* json_buf);
void   serialize_EMAILADDRESSCHECK_response                 (const EMAILADDRESSCHECKRecord_t* record, JsonBuf_t* json_buf);
void   serialize_SSLCHECK_response                          (const SSLCHECKRecord_t* record, JsonBuf_t* json_buf);
void   serialize_HEADERSCHECK_response                      (const HEADERSCHECKRecord_t* record, const HEADERSCHECKParams_t* params, JsonBuf_t* json_buf);
void   serialize_WHOISLOOKUP_response                       (const WHOISLOOKUPRecord_t* record, JsonBuf_t* json_buf);
void   serialize_WAYBACKLOOKUP_response                     (const WAYBACKLOOKUPRecord_t* record, JsonBuf_t* json_buf);
void   serialize_CERTSEARCH_response                        (const CERTSEARCHRecord_t* record, JsonBuf_t* json_buf);
void   serialize_SUBDOMAINENUM_response                     (const SUBDOMAINENUMRecord_t* record, JsonBuf_t* json_buf);
void   serialize_IPLOOKUP_response                          (const IPLOOKUPRecord_t* record, const IPLOOKUPVendorSlots_t* slots, JsonBuf_t* json_buf);
void   serialize_ASNLOOKUP_response                         (const ASNLOOKUPRecord_t* record, const ASNLOOKUPParams_t* params, JsonBuf_t* json_buf);
void   serialize_WATCHLISTEDITItems_response                (const WATCHLISTEDITItemsResult_t* result, JsonBuf_t* json_buf);
void   serialize_WATCHLISTEDITPackageList_response          (const WATCHLISTEDITPackageListResult_t* result, JsonBuf_t* json_buf);
void   serialize_WATCHLISTEDITPackageList_problems_response (const char* message, const WATCHLISTEDITPackageElement_t* elements, int element_count, JsonBuf_t* json_buf);
void   serialize_WATCHLISTEVENTS_response                   (const WATCHLISTEVENTSResult_t* result, const WATCHLISTEVENTSParams_t* params, JsonBuf_t* json_buf);
void   serialize_D3FENDFORATTACK_response                   (const D3FENDFORATTACKResult_t* result, const D3FENDFORATTACKParams_t* params, JsonBuf_t* json_buf);
void   serialize_DRIVERLOOKUP_response                      (const DRIVERLOOKUPRecord_t* record, JsonBuf_t* json_buf);
void   serialize_DRIVERLOOKUPBULK_response                  (const DRIVERLOOKUPBULKResult_t* results, JsonBuf_t* json_buf);
void   serialize_PACKAGECHECK_response                      (const PACKAGECHECKResult_t* result, const PACKAGECHECKParams_t* params, JsonBuf_t* json_buf);
void   serialize_PACKAGECHECKBULK_response                  (const PACKAGECHECKBULKResult_t* results, JsonBuf_t* json_buf);
void   serialize_IMAGEINSPECT_response                      (const ImageScanResult_t* result, const ExifClientResult_t* exif, const ImageIndicatorResult_t* indicators, JsonBuf_t* json_buf);
void   serialize_WEBHOOK_status_response                    (const char* status_text, JsonBuf_t* json_buf);
void   serialize_CRYPTOCHECKOUT_response                    (const char* invoice_id, const char* invoice_url, const char* order_id, JsonBuf_t* json_buf);
void   serialize_APIKEYCLAIM_response                       (const char* api_key, JsonBuf_t* json_buf);
void   serialize_VENDORKEYEDIT_applyResponse                (const VENDORKEYEDITApplyResult_t* result, JsonBuf_t* json_buf);
void   serialize_VENDORKEYEDIT_statusResponse               (const VENDORKEYEDITStatusResult_t* result, JsonBuf_t* json_buf);
void   serialize_error_response                             (const char* code, const char* message, JsonBuf_t* json_buf);

#endif
