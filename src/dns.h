#ifndef DNS_H
#define DNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "validate.h"

#define DNS_NAME_TEXT_SIZE 1025

#define DNS_MESSAGE_MAX_SIZE 65535

#define DNS_UDP_PAYLOAD_SIZE 1232

#define DNS_RETRANSMIT_MS 1000

#define DNS_MAX_QUESTION_COUNT 32

#define DNS_ANSWER_MAX_RECORD_COUNT 256

typedef enum {
  DNS_RECORD_TYPE_A = 0,
  DNS_RECORD_TYPE_AAAA,
  DNS_RECORD_TYPE_MX,
  DNS_RECORD_TYPE_NS,
  DNS_RECORD_TYPE_TXT,
  DNS_RECORD_TYPE_CNAME,
  DNS_RECORD_TYPE_SOA,
  DNS_RECORD_TYPE_CAA,
  DNS_RECORD_TYPE_PTR,
} DnsRecordType_t;

#define DNS_RECORD_TYPE_COUNT 9

#define DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT 8

typedef enum {
  DNS_ANSWER_OK = 0,
  DNS_ANSWER_NXDOMAIN,
  DNS_ANSWER_SERVER_ERROR,
  DNS_ANSWER_TRUNCATED,
  DNS_ANSWER_MALFORMED,
  DNS_ANSWER_NO_MEMORY,
  DNS_ANSWER_TIMEOUT,
  DNS_ANSWER_NO_RESOLVER,
  DNS_ANSWER_BAD_QUESTION,
  DNS_ANSWER_NOT_PUBLIC_NAME,
} DnsAnswerStatus_t;

typedef struct {
  const char*     mp_domainName;
  DnsRecordType_t m_type;
} DnsQuestion_t;

typedef struct {
  char*  mp_bytes;
  size_t m_byteCount;
} DnsRecordText_t;

typedef struct {
  uint16_t m_priority;
  char*    mp_hostname;
} DnsMxRecord_t;

typedef struct {
  char*    mp_primaryNameServer;
  char*    mp_adminEmail;
  uint32_t m_serial;
} DnsSoaRecord_t;

typedef struct {
  uint8_t         m_flags;
  DnsRecordText_t m_tag;
  DnsRecordText_t m_value;
} DnsCaaRecord_t;

typedef struct {
  DnsAnswerStatus_t m_status;
  int               m_recordCount;
  DnsRecordText_t*  mp_texts;
  DnsMxRecord_t*    mp_mxRecords;
  DnsSoaRecord_t*   mp_soaRecord;
  DnsCaaRecord_t*   mp_caaRecords;
  bool              m_hasNullMx;
} DnsAnswer_t;

#define DNS_LOOKUP_DEADLINE_MS 5000

#define DNS_PTR_DEADLINE_MS 3000

typedef struct {
  const char* mp_serviceName;
  const char* mp_evidence;
} DnsTxtService_t;

#define DNS_TXT_SERVICE_COUNT 96

extern const DnsTxtService_t dns_txtServices[DNS_TXT_SERVICE_COUNT];

typedef struct {
  const char* mp_serviceName;
  const char* mp_suffix;
} DnsTakeoverSuffix_t;

#define DNS_TAKEOVER_SUFFIX_COUNT 17

extern const DnsTakeoverSuffix_t dns_takeoverSuffixes[DNS_TAKEOVER_SUFFIX_COUNT];

typedef enum {
  DNS_LOOKUP_OK = 0,
  DNS_LOOKUP_NOT_FOUND,
  DNS_LOOKUP_NO_ANSWER,
  DNS_LOOKUP_INVALID_NAME,
  DNS_LOOKUP_NO_MEMORY,
} DnsLookupStatus_t;

typedef struct {
  char ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} DNSLOOKUPParams_t;

typedef struct {
  char                    ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  DnsAnswer_t             ma_answers[DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT];
  const DnsRecordText_t** mp_nonPublicAddresses;
  int                     m_nonPublicAddressCount;
  const DnsTxtService_t*  ma_services[DNS_TXT_SERVICE_COUNT];
  int                     m_serviceCount;
} DNSLOOKUPRecord_t;

typedef struct {
  char ma_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} DNSTAKEOVERCHECKParams_t;

#define DNS_TAKEOVER_HOSTNAME_CHAIN_MAX 8

typedef struct {
  char                       ma_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char                       ma_hostnameChain[DNS_TAKEOVER_HOSTNAME_CHAIN_MAX][DNS_NAME_TEXT_SIZE];
  int                        m_hostnameChainLength;
  bool                       m_isTargetFound;
  const DnsTakeoverSuffix_t* mp_matchedSuffix;
} DNSTAKEOVERCHECKRecord_t;

bool                dns_tryReadResponse     (const unsigned char* message, size_t message_len, const DnsQuestion_t* question, uint16_t question_message_id, DnsAnswer_t* answer_out);
void                dns_askQuestions        (const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out);
void                dns_resetQuestionCount  (void);
int                 dns_readQuestionCount   (void);
void                dns_answerFree          (DnsAnswer_t* answer);
DnsLookupStatus_t   dns_lookupDomain        (const char* domain, DNSLOOKUPRecord_t* record_out);
void                dns_DNSLOOKUPRecordFree (DNSLOOKUPRecord_t* record);
DnsLookupStatus_t   dns_checkTakeover       (const char* hostname, DNSTAKEOVERCHECKRecord_t* record_out);
void                dns_lookupPtr           (const char* ip_address, DnsAnswer_t* answer_out);

#endif
