#define _GNU_SOURCE

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>

#include "dns.h"
#include "bytes.h"
#include "ipguard.h"
#include "monotonic.h"
#include "validate.h"

_Static_assert(DNS_NAME_TEXT_SIZE == NS_MAXDNAME, "DNS_NAME_TEXT_SIZE must be NS_MAXDNAME");

#define DNS_HEADER_SIZE 12

#define DNS_HEADER_QR_BIT 0x80

#define DNS_HEADER_RCODE_MASK 0x0F

#define DNS_HEADER_ADDITIONAL_COUNT_OFFSET 10

#define DNS_MX_PRIORITY_SIZE 2

#define DNS_SOA_NUMBERS_SIZE 20

#define DNS_CAA_FLAGS_OFFSET 0

#define DNS_CAA_TAG_LENGTH_OFFSET 1

#define DNS_CAA_TAG_OFFSET 2

static const ns_type DNS_RECORD_TYPE_WIRE_VALUES[DNS_RECORD_TYPE_COUNT] = {
  [DNS_RECORD_TYPE_A]     = ns_t_a,
  [DNS_RECORD_TYPE_AAAA]  = ns_t_aaaa,
  [DNS_RECORD_TYPE_MX]    = ns_t_mx,
  [DNS_RECORD_TYPE_NS]    = ns_t_ns,
  [DNS_RECORD_TYPE_TXT]   = ns_t_txt,
  [DNS_RECORD_TYPE_CNAME] = ns_t_cname,
  [DNS_RECORD_TYPE_SOA]   = ns_t_soa,
  [DNS_RECORD_TYPE_CAA]   = ns_t_caa,
  [DNS_RECORD_TYPE_PTR]   = ns_t_ptr,
};

_Static_assert(DNS_RECORD_TYPE_PTR == DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT, "DNS_RECORD_TYPE_PTR must follow the types dns_lookupDomain asks for");

#define DNS_REVERSE_NAME_SIZE (32 * 2 + sizeof("ip6.arpa"))

#define DNS_QUESTION_MESSAGE_BUFFER_SIZE 512

#define DNS_EDNS_OPT_SIZE 11

#define DNS_TCP_LENGTH_PREFIX_SIZE 2

typedef enum {
  DNS_PENDING_UDP_READ = 0,
  DNS_PENDING_TCP_SEND,
  DNS_PENDING_TCP_READ,
  DNS_PENDING_DONE,
} DnsPendingPhase_t;

typedef struct {
  unsigned char     ma_message[DNS_TCP_LENGTH_PREFIX_SIZE + DNS_QUESTION_MESSAGE_BUFFER_SIZE];
  size_t            m_questionMessageByteCount;
  uint16_t          m_questionMessageId;
  DnsPendingPhase_t m_pendingPhase;
  int               m_nameserverIndex;
  int64_t           m_udpResendAtMs;
  int               m_udpSendCount;
  int               m_tcpFd;
  size_t            m_tcpSentByteCount;
  unsigned char     ma_tcpLengthPrefixBytes[DNS_TCP_LENGTH_PREFIX_SIZE];
  size_t            m_tcpLengthPrefixReadByteCount;
  unsigned char*    mp_tcpAnswerBytes;
  size_t            m_tcpAnswerByteCount;
  size_t            m_tcpAnswerReadByteCount;
} DnsQuestionState_t;

typedef struct {
  struct sockaddr_storage m_address;
  socklen_t               m_addressLen;
  int                     m_udpFd;
} DnsNameserver_t;

typedef struct {
  const DnsQuestion_t* mp_questions;
  DnsQuestionState_t*  mp_questionStates;
  DnsAnswer_t*         mp_answers;
  int                  m_questionCount;
  DnsNameserver_t*     mp_nameservers;
  int                  m_nameserverCount;
} DnsQuestionBatch_t;

#define DNS_POLL_FD_MAX_COUNT (DNS_MAX_QUESTION_COUNT + MAXNS)

typedef struct {
  struct pollfd ma_fds[DNS_POLL_FD_MAX_COUNT];
  int           ma_tcpQuestionIndexes[DNS_MAX_QUESTION_COUNT];
  int           m_tcpFdCount;
  int           m_fdCount;
} DnsPollList_t;

static __thread unsigned int g_questionCount = 0;

static bool                       static_isAnswerToQuestion        (ns_msg* message_handle, const DnsQuestion_t* question);
static int                        static_expandDomainName          (const ns_msg* message_handle, const unsigned char* domain_name_start, char domain_name_out[NS_MAXDNAME]);
static DnsAnswerStatus_t          static_readIpAddress             (const ns_rr* record, int family, size_t ip_address_size, DnsRecordText_t* text_out);
static DnsAnswerStatus_t          static_readDomainName            (const ns_msg* message_handle, const ns_rr* record, DnsRecordText_t* text_out);
static DnsAnswerStatus_t          static_readTxtRecord             (const ns_rr* record, DnsRecordText_t* text_out);
static DnsAnswerStatus_t          static_readMxRecord              (const ns_msg* message_handle, const ns_rr* record, DnsMxRecord_t* mx_out, bool* is_null_mx_out);
static DnsAnswerStatus_t          static_readSoaRecord             (const ns_msg* message_handle, const ns_rr* record, DnsSoaRecord_t* soa_out);
static bool                       static_tryCopyBytes              (const unsigned char* bytes, size_t byte_count, DnsRecordText_t* text_out);
static DnsAnswerStatus_t          static_readCaaRecord             (const ns_rr* record, DnsCaaRecord_t* caa_out);
static bool                       static_tryAllocateRecords        (DnsRecordType_t record_type, int max_record_count, DnsAnswer_t* answer);
static bool                       static_hasCnameToNonPublicName   (ns_msg* message_handle);
static DnsAnswerStatus_t          static_readRecords               (ns_msg* message_handle, const DnsQuestion_t* question, DnsAnswer_t* answer);

static void                       static_openNameserverSockets     (const struct __res_state* state, DnsNameserver_t nameservers_out[MAXNS], int* nameserver_count_out);
static bool                       static_tryWriteQuestionMessage   (struct __res_state* state, const DnsQuestion_t* question, DnsQuestionState_t* question_state);
static void                       static_appendEdnsOptRecord       (unsigned char* question_message, int question_message_len);
static void                       static_sendUdp                   (DnsQuestionState_t* question_state, const DnsNameserver_t* nameserver, int64_t now_ms);
static void                       static_finishQuestion            (DnsQuestionState_t* question_state, DnsAnswer_t answer, DnsAnswer_t* answer_out);
static void                       static_finishQuestionWithStatus  (DnsQuestionState_t* question_state, DnsAnswerStatus_t status, DnsAnswer_t* answer_out);
static void                       static_startTcp                  (DnsQuestionState_t* question_state, const DnsNameserver_t* nameserver, DnsAnswer_t* answer_out);
static bool                       static_shouldAskNextNameserver   (const unsigned char* datagram, const DnsQuestionState_t* question_state, int nameserver_count);
static void                       static_readUdpAnswer             (const DnsQuestionBatch_t* batch, const DnsNameserver_t* nameserver);
static void                       static_sendTcp                   (DnsQuestionState_t* question_state, DnsAnswer_t* answer_out);
static void                       static_readTcp                   (const DnsQuestion_t* question, DnsQuestionState_t* question_state, DnsAnswer_t* answer_out);
static bool                       static_tryReceiveTcpBytes        (DnsQuestionState_t* question_state, unsigned char* fill_position, size_t missing_byte_count, size_t* received_byte_count_out, DnsAnswer_t* answer_out);
static void                       static_readTcpLengthPrefix       (DnsQuestionState_t* question_state, DnsAnswer_t* answer_out);
static void                       static_prepareTcpAnswerBuffer    (DnsQuestionState_t* question_state, DnsAnswer_t* answer_out);
static void                       static_readTcpAnswer             (const DnsQuestion_t* question, DnsQuestionState_t* question_state, DnsAnswer_t* answer_out);
static void                       static_runPollLoop               (const DnsQuestionBatch_t* batch, int64_t deadline_at);
static bool                       static_isAnyQuestionPending      (const DnsQuestionBatch_t* batch);
static void                       static_buildPollList             (const DnsQuestionBatch_t* batch, DnsPollList_t* poll_list_out);
static int64_t                    static_computePollWaitMs         (const DnsQuestionBatch_t* batch, int64_t now_ms, int64_t deadline_at);
static void                       static_serveReadySockets         (const DnsQuestionBatch_t* batch, const DnsPollList_t* poll_list);
static void                       static_resendOverdueUdpQuestions (const DnsQuestionBatch_t* batch, int64_t now_ms);

static bool                       static_tryFindNonPublicAddresses (DNSLOOKUPRecord_t* record);
static void                       static_findTxtServices           (DNSLOOKUPRecord_t* record);

static const DnsTakeoverSuffix_t* static_findTakeoverSuffix        (const char* hostname);

static bool                       static_tryWriteReverseName       (const char* ip_address, char reverse_name_out[DNS_REVERSE_NAME_SIZE]);

bool dns_tryReadResponse(const unsigned char* message, size_t message_len, const DnsQuestion_t* question, uint16_t question_message_id, DnsAnswer_t* answer_out)
{
  if (message_len < DNS_HEADER_SIZE || message_len > DNS_MESSAGE_MAX_SIZE)
    return false;

  if (ns_get16(message) != question_message_id || (message[2] & DNS_HEADER_QR_BIT) == 0)
    return false;

  DnsAnswer_t answer;
  memset(&answer, 0, sizeof(answer));

  ns_msg message_handle;
  if (ns_initparse(message, (int)message_len, &message_handle) != 0)
    answer.m_status = DNS_ANSWER_MALFORMED;
  else if (!static_isAnswerToQuestion(&message_handle, question))
    return false;
  else if (ns_msg_getflag(message_handle, ns_f_tc))
    answer.m_status = DNS_ANSWER_TRUNCATED;
  else if (question->m_type != DNS_RECORD_TYPE_CNAME && static_hasCnameToNonPublicName(&message_handle))
    answer.m_status = DNS_ANSWER_NOT_PUBLIC_NAME;
  else if (ns_msg_getflag(message_handle, ns_f_rcode) == ns_r_nxdomain)
    answer.m_status = DNS_ANSWER_NXDOMAIN;
  else if (ns_msg_getflag(message_handle, ns_f_rcode) != ns_r_noerror)
    answer.m_status = DNS_ANSWER_SERVER_ERROR;
  else
    answer.m_status = static_readRecords(&message_handle, question, &answer);

  if (answer.m_status != DNS_ANSWER_OK)
    dns_answerFree(&answer);
  *answer_out = answer;

  return true;
}

void dns_answerFree(DnsAnswer_t* answer)
{
  int record_count = answer->m_recordCount;

  if (answer->mp_texts != NULL)
    for (int i = 0; i < record_count; i++)
      free(answer->mp_texts[i].mp_bytes);

  if (answer->mp_mxRecords != NULL)
    for (int i = 0; i < record_count; i++)
      free(answer->mp_mxRecords[i].mp_hostname);

  if (answer->mp_soaRecord != NULL)
  {
    free(answer->mp_soaRecord->mp_primaryNameServer);
    free(answer->mp_soaRecord->mp_adminEmail);
  }

  if (answer->mp_caaRecords != NULL)
    for (int i = 0; i < record_count; i++)
    {
      free(answer->mp_caaRecords[i].m_tag.mp_bytes);
      free(answer->mp_caaRecords[i].m_value.mp_bytes);
    }

  free(answer->mp_texts);
  free(answer->mp_mxRecords);
  free(answer->mp_soaRecord);
  free(answer->mp_caaRecords);

  DnsAnswerStatus_t status = answer->m_status;
  memset(answer, 0, sizeof(*answer));
  answer->m_status = status;
}

void dns_askQuestions(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out)
{
  assert(question_count > 0 && question_count <= DNS_MAX_QUESTION_COUNT);
  g_questionCount += (unsigned int)question_count;

  DnsQuestionState_t question_states[DNS_MAX_QUESTION_COUNT];
  for (int i = 0; i < question_count; i++)
  {
    memset(&answers_out[i], 0, sizeof(answers_out[i]));
    answers_out[i].m_status = DNS_ANSWER_TIMEOUT;

    memset(&question_states[i], 0, sizeof(question_states[i]));
    question_states[i].m_tcpFd = -1;
  }

  struct __res_state state;
  memset(&state, 0, sizeof(state));
  if (res_ninit(&state) != 0)
  {
    for (int i = 0; i < question_count; i++)
      static_finishQuestionWithStatus(&question_states[i], DNS_ANSWER_NO_RESOLVER, &answers_out[i]);
    return;
  }

  state.options &= ~(unsigned long)RES_TRUSTAD;

  DnsNameserver_t nameservers[MAXNS];
  int             nameserver_count = 0;
  static_openNameserverSockets(&state, nameservers, &nameserver_count);

  for (int i = 0; i < question_count; i++)
  {
    if (nameserver_count == 0)
      static_finishQuestionWithStatus(&question_states[i], DNS_ANSWER_NO_RESOLVER, &answers_out[i]);
    else if (!static_tryWriteQuestionMessage(&state, &questions[i], &question_states[i]))
      static_finishQuestionWithStatus(&question_states[i], DNS_ANSWER_BAD_QUESTION, &answers_out[i]);
  }
  res_nclose(&state);

  const DnsQuestionBatch_t batch = {
    .mp_questions      = questions,
    .mp_questionStates = question_states,
    .mp_answers        = answers_out,
    .m_questionCount   = question_count,
    .mp_nameservers    = nameservers,
    .m_nameserverCount = nameserver_count,
  };

  int64_t start_ms    = monotonic_nowMs();
  int64_t deadline_at = start_ms + deadline_ms;
  for (int i = 0; i < question_count; i++)
    if (question_states[i].m_pendingPhase == DNS_PENDING_UDP_READ)
      static_sendUdp(&question_states[i], &nameservers[0], start_ms);

  static_runPollLoop(&batch, deadline_at);

  for (int i = 0; i < question_count; i++)
    if (question_states[i].m_pendingPhase != DNS_PENDING_DONE)
      static_finishQuestionWithStatus(&question_states[i], DNS_ANSWER_TIMEOUT, &answers_out[i]);

  for (int i = 0; i < nameserver_count; i++)
    close(nameservers[i].m_udpFd);
}

void dns_resetQuestionCount(void)
{
  g_questionCount = 0;
}

int dns_readQuestionCount(void)
{
  return (int)g_questionCount;
}

DnsLookupStatus_t dns_lookupDomain(const char* domain, DNSLOOKUPRecord_t* record_out)
{
  memset(record_out, 0, sizeof(*record_out));

  if (!validate_publicDnsName(domain))
    return DNS_LOOKUP_INVALID_NAME;

  for (size_t i = 0; domain[i] != '\0'; i++)
    record_out->ma_domain[i] = (char)tolower((unsigned char)domain[i]);

  DnsQuestion_t questions[DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT];
  for (int record_type = 0; record_type < DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT; record_type++)
  {
    questions[record_type].mp_domainName = record_out->ma_domain;
    questions[record_type].m_type        = (DnsRecordType_t)record_type;
  }
  dns_askQuestions(questions, DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT, DNS_LOOKUP_DEADLINE_MS, record_out->ma_answers);

  bool is_any_answered  = false;
  bool is_any_nxdomain  = false;
  bool is_any_no_memory = false;
  for (int record_type = 0; record_type < DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT; record_type++)
  {
    DnsAnswerStatus_t status = record_out->ma_answers[record_type].m_status;
    if (status == DNS_ANSWER_OK)
      is_any_answered = true;
    else if (status == DNS_ANSWER_NXDOMAIN)
      is_any_nxdomain = true;
    else if (status == DNS_ANSWER_NO_MEMORY)
      is_any_no_memory = true;
  }

  if (is_any_no_memory)
    return DNS_LOOKUP_NO_MEMORY;
  if (!static_tryFindNonPublicAddresses(record_out))
    return DNS_LOOKUP_NO_MEMORY;

  if (!is_any_answered)
    return is_any_nxdomain ? DNS_LOOKUP_NOT_FOUND : DNS_LOOKUP_NO_ANSWER;

  static_findTxtServices(record_out);
  return DNS_LOOKUP_OK;
}

void dns_DNSLOOKUPRecordFree(DNSLOOKUPRecord_t* record)
{
  for (int record_type = 0; record_type < DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT; record_type++)
    dns_answerFree(&record->ma_answers[record_type]);

  free(record->mp_nonPublicAddresses);
  record->mp_nonPublicAddresses = NULL;
  record->m_nonPublicAddressCount = 0;
}

DnsLookupStatus_t dns_checkTakeover(const char* hostname, DNSTAKEOVERCHECKRecord_t* record_out)
{
  memset(record_out, 0, sizeof(*record_out));

  if (!validate_publicDnsName(hostname))
    return DNS_LOOKUP_INVALID_NAME;

  for (size_t i = 0; hostname[i] != '\0'; i++)
    record_out->ma_hostname[i] = (char)tolower((unsigned char)hostname[i]);

  int64_t     deadline_at    = monotonic_nowMs() + DNS_LOOKUP_DEADLINE_MS;
  const char* asked_hostname = record_out->ma_hostname;
  for (;;)
  {
    int64_t wait_ms = deadline_at - monotonic_nowMs();
    if (wait_ms <= 0)
      return DNS_LOOKUP_NO_ANSWER;

    const DnsQuestion_t question = { asked_hostname, DNS_RECORD_TYPE_CNAME };
    DnsAnswer_t answer;
    dns_askQuestions(&question, 1, (int)wait_ms, &answer);

    DnsAnswerStatus_t status = answer.m_status;
    bool has_cname = status == DNS_ANSWER_OK && answer.m_recordCount > 0;
    if (has_cname && record_out->m_hostnameChainLength < DNS_TAKEOVER_HOSTNAME_CHAIN_MAX)
      snprintf(record_out->ma_hostnameChain[record_out->m_hostnameChainLength], DNS_NAME_TEXT_SIZE, "%s", answer.mp_texts[0].mp_bytes);
    dns_answerFree(&answer);

    if (status == DNS_ANSWER_NO_MEMORY)
      return DNS_LOOKUP_NO_MEMORY;
    if (status == DNS_ANSWER_NXDOMAIN && record_out->m_hostnameChainLength == 0)
      return DNS_LOOKUP_NOT_FOUND;
    if (status != DNS_ANSWER_OK && status != DNS_ANSWER_NXDOMAIN)
      return DNS_LOOKUP_NO_ANSWER;

    if (!has_cname)
    {
      record_out->m_isTargetFound = record_out->m_hostnameChainLength > 0 && status == DNS_ANSWER_OK;
      break;
    }

    if (record_out->m_hostnameChainLength == DNS_TAKEOVER_HOSTNAME_CHAIN_MAX)
      return DNS_LOOKUP_NO_ANSWER;

    asked_hostname = record_out->ma_hostnameChain[record_out->m_hostnameChainLength++];
    if (!validate_publicDnsName(asked_hostname))
      return DNS_LOOKUP_NO_ANSWER;
  }

  if (record_out->m_hostnameChainLength > 0)
  {
    const char* last_hostname = record_out->ma_hostnameChain[record_out->m_hostnameChainLength - 1];
    record_out->mp_matchedSuffix = static_findTakeoverSuffix(last_hostname);
  }

  return DNS_LOOKUP_OK;
}

void dns_lookupPtr(const char* ip_address, DnsAnswer_t* answer_out)
{
  char reverse_name[DNS_REVERSE_NAME_SIZE];
  if (!static_tryWriteReverseName(ip_address, reverse_name))
  {
    memset(answer_out, 0, sizeof(*answer_out));
    answer_out->m_status = DNS_ANSWER_BAD_QUESTION;
    return;
  }

  const DnsQuestion_t question = { reverse_name, DNS_RECORD_TYPE_PTR };
  dns_askQuestions(&question, 1, DNS_PTR_DEADLINE_MS, answer_out);
}

static bool static_isAnswerToQuestion(ns_msg* message_handle, const DnsQuestion_t* question)
{
  if (ns_msg_count(*message_handle, ns_s_qd) != 1)
    return false;

  ns_rr question_record;
  if (ns_parserr(message_handle, ns_s_qd, 0, &question_record) != 0)
    return false;

  return ns_rr_type(question_record)  == DNS_RECORD_TYPE_WIRE_VALUES[question->m_type]
      && ns_rr_class(question_record) == ns_c_in
      && strcasecmp(ns_rr_name(question_record), question->mp_domainName) == 0;
}

static int static_expandDomainName(const ns_msg* message_handle, const unsigned char* domain_name_start, char domain_name_out[NS_MAXDNAME])
{
  return dn_expand(ns_msg_base(*message_handle), ns_msg_end(*message_handle), domain_name_start, domain_name_out, NS_MAXDNAME);
}

static DnsAnswerStatus_t static_readIpAddress(const ns_rr* record, int family, size_t ip_address_size, DnsRecordText_t* text_out)
{
  if (ns_rr_rdlen(*record) != ip_address_size)
    return DNS_ANSWER_MALFORMED;

  char ip_address_text[INET6_ADDRSTRLEN];
  if (inet_ntop(family, ns_rr_rdata(*record), ip_address_text, sizeof(ip_address_text)) == NULL)
    return DNS_ANSWER_MALFORMED;

  text_out->mp_bytes = strdup(ip_address_text);
  if (text_out->mp_bytes == NULL)
    return DNS_ANSWER_NO_MEMORY;

  text_out->m_byteCount = strlen(ip_address_text);
  return DNS_ANSWER_OK;
}

static DnsAnswerStatus_t static_readDomainName(const ns_msg* message_handle, const ns_rr* record, DnsRecordText_t* text_out)
{
  char domain_name[NS_MAXDNAME];
  if (static_expandDomainName(message_handle, ns_rr_rdata(*record), domain_name) != ns_rr_rdlen(*record))
    return DNS_ANSWER_MALFORMED;

  text_out->mp_bytes = strdup(domain_name);
  if (text_out->mp_bytes == NULL)
    return DNS_ANSWER_NO_MEMORY;

  text_out->m_byteCount = strlen(domain_name);
  return DNS_ANSWER_OK;
}

static DnsAnswerStatus_t static_readTxtRecord(const ns_rr* record, DnsRecordText_t* text_out)
{
  const unsigned char* data = ns_rr_rdata(*record);
  size_t data_len           = ns_rr_rdlen(*record);

  char* text = malloc(data_len + 1);
  if (text == NULL)
    return DNS_ANSWER_NO_MEMORY;

  size_t text_byte_count = 0;
  size_t chunk_start     = 0;
  while (chunk_start < data_len)
  {
    uint8_t              chunk_byte_count     = data[chunk_start];
    const unsigned char* chunk_bytes          = data + chunk_start + 1;
    size_t               remaining_byte_count = data_len - chunk_start - 1;
    if (chunk_byte_count > remaining_byte_count)
    {
      free(text);
      return DNS_ANSWER_MALFORMED;
    }

    memcpy(text + text_byte_count, chunk_bytes, chunk_byte_count);
    text_byte_count += chunk_byte_count;
    chunk_start += 1 + chunk_byte_count;
  }
  text[text_byte_count] = '\0';

  text_out->mp_bytes    = text;
  text_out->m_byteCount = text_byte_count;
  return DNS_ANSWER_OK;
}

static DnsAnswerStatus_t static_readMxRecord(const ns_msg* message_handle, const ns_rr* record, DnsMxRecord_t* mx_out, bool* is_null_mx_out)
{
  const unsigned char* data     = ns_rr_rdata(*record);
  int                  data_len = ns_rr_rdlen(*record);

  *is_null_mx_out = false;

  if (data_len < DNS_MX_PRIORITY_SIZE)
    return DNS_ANSWER_MALFORMED;

  const unsigned char* hostname_start = data + DNS_MX_PRIORITY_SIZE;
  char hostname[NS_MAXDNAME];
  if (static_expandDomainName(message_handle, hostname_start, hostname) != data_len - DNS_MX_PRIORITY_SIZE)
    return DNS_ANSWER_MALFORMED;

  if (hostname[0] == '\0')
  {
    *is_null_mx_out = true;
    return DNS_ANSWER_OK;
  }

  mx_out->mp_hostname = strdup(hostname);
  if (mx_out->mp_hostname == NULL)
    return DNS_ANSWER_NO_MEMORY;

  mx_out->m_priority = (uint16_t)ns_get16(data);
  return DNS_ANSWER_OK;
}

static DnsAnswerStatus_t static_readSoaRecord(const ns_msg* message_handle, const ns_rr* record, DnsSoaRecord_t* soa_out)
{
  const unsigned char* data     = ns_rr_rdata(*record);
  int                  data_len = ns_rr_rdlen(*record);

  char primary_name_server[NS_MAXDNAME];
  int  primary_name_server_len = static_expandDomainName(message_handle, data, primary_name_server);
  if (primary_name_server_len < 0)
    return DNS_ANSWER_MALFORMED;

  char admin_email[NS_MAXDNAME];
  int  admin_email_len = static_expandDomainName(message_handle, data + primary_name_server_len, admin_email);
  if (admin_email_len < 0 || data_len - primary_name_server_len - admin_email_len != DNS_SOA_NUMBERS_SIZE)
    return DNS_ANSWER_MALFORMED;

  const unsigned char* serial_start = data + primary_name_server_len + admin_email_len;

  char* primary_name_server_copy  = strdup(primary_name_server);
  char* admin_email_copy          = strdup(admin_email);
  if (primary_name_server_copy == NULL || admin_email_copy == NULL)
  {
    free(primary_name_server_copy);
    free(admin_email_copy);
    return DNS_ANSWER_NO_MEMORY;
  }
  soa_out->mp_primaryNameServer = primary_name_server_copy;
  soa_out->mp_adminEmail        = admin_email_copy;
  soa_out->m_serial             = (uint32_t)ns_get32(serial_start);
  return DNS_ANSWER_OK;
}

static bool static_tryCopyBytes(const unsigned char* bytes, size_t byte_count, DnsRecordText_t* text_out)
{
  char* copy = malloc(byte_count + 1);
  if (copy == NULL)
    return false;

  memcpy(copy, bytes, byte_count);
  copy[byte_count] = '\0';

  text_out->mp_bytes    = copy;
  text_out->m_byteCount = byte_count;
  return true;
}

static DnsAnswerStatus_t static_readCaaRecord(const ns_rr* record, DnsCaaRecord_t* caa_out)
{
  const unsigned char* data     = ns_rr_rdata(*record);
  size_t               data_len = ns_rr_rdlen(*record);
  if (data_len < DNS_CAA_TAG_OFFSET)
    return DNS_ANSWER_MALFORMED;

  uint8_t tag_len = data[DNS_CAA_TAG_LENGTH_OFFSET];
  if (tag_len == 0 || tag_len > data_len - DNS_CAA_TAG_OFFSET)
    return DNS_ANSWER_MALFORMED;

  const unsigned char* tag_start   = data + DNS_CAA_TAG_OFFSET;
  const unsigned char* value_start = tag_start + tag_len;
  size_t               value_len   = data_len - DNS_CAA_TAG_OFFSET - tag_len;

  DnsCaaRecord_t caa;
  caa.m_flags = data[DNS_CAA_FLAGS_OFFSET];

  if (!static_tryCopyBytes(tag_start, tag_len, &caa.m_tag))
    return DNS_ANSWER_NO_MEMORY;

  if (!static_tryCopyBytes(value_start, value_len, &caa.m_value))
  {
    free(caa.m_tag.mp_bytes);
    return DNS_ANSWER_NO_MEMORY;
  }
  *caa_out = caa;
  return DNS_ANSWER_OK;
}

static bool static_tryAllocateRecords(DnsRecordType_t record_type, int max_record_count, DnsAnswer_t* answer)
{
  switch (record_type)
  {
    case DNS_RECORD_TYPE_A:
    case DNS_RECORD_TYPE_AAAA:
    case DNS_RECORD_TYPE_NS:
    case DNS_RECORD_TYPE_TXT:
    case DNS_RECORD_TYPE_CNAME:
    case DNS_RECORD_TYPE_PTR:
      answer->mp_texts = calloc((size_t)max_record_count, sizeof(DnsRecordText_t));
      return answer->mp_texts != NULL;
    case DNS_RECORD_TYPE_MX:
      answer->mp_mxRecords = calloc((size_t)max_record_count, sizeof(DnsMxRecord_t));
      return answer->mp_mxRecords != NULL;
    case DNS_RECORD_TYPE_SOA:
      answer->mp_soaRecord = calloc(1, sizeof(DnsSoaRecord_t));
      return answer->mp_soaRecord != NULL;
    case DNS_RECORD_TYPE_CAA:
      answer->mp_caaRecords = calloc((size_t)max_record_count, sizeof(DnsCaaRecord_t));
      return answer->mp_caaRecords != NULL;
  }
  return false;
}

static bool static_hasCnameToNonPublicName(ns_msg* message_handle)
{
  int answer_count = ns_msg_count(*message_handle, ns_s_an);
  for (int i = 0; i < answer_count; i++)
  {
    ns_rr record;
    if (ns_parserr(message_handle, ns_s_an, i, &record) != 0)
      return false;
    if (ns_rr_type(record) != ns_t_cname || ns_rr_class(record) != ns_c_in)
      continue;

    char target[NS_MAXDNAME];
    if (static_expandDomainName(message_handle, ns_rr_rdata(record), target) < 0)
      continue;
    if (!validate_publicUnderscoredDnsName(target))
      return true;
  }
  return false;
}

static DnsAnswerStatus_t static_readRecords(ns_msg* message_handle, const DnsQuestion_t* question, DnsAnswer_t* answer)
{
  DnsRecordType_t record_type = question->m_type;

  int answer_count = ns_msg_count(*message_handle, ns_s_an);
  if (answer_count == 0)
    return DNS_ANSWER_OK;
  if (answer_count > DNS_ANSWER_MAX_RECORD_COUNT)
    return DNS_ANSWER_MALFORMED;

  if (!static_tryAllocateRecords(record_type, answer_count, answer))
    return DNS_ANSWER_NO_MEMORY;

  for (int i = 0; i < answer_count; i++)
  {
    ns_rr record;
    if (ns_parserr(message_handle, ns_s_an, i, &record) != 0)
      return DNS_ANSWER_MALFORMED;

    if (ns_rr_type(record) != DNS_RECORD_TYPE_WIRE_VALUES[record_type] || ns_rr_class(record) != ns_c_in)
      continue;

    const char* owner = ns_rr_name(record);
    if (strcasecmp(owner, question->mp_domainName) != 0 && !validate_publicUnderscoredDnsName(owner))
      return DNS_ANSWER_NOT_PUBLIC_NAME;

    DnsAnswerStatus_t record_status = DNS_ANSWER_OK;
    switch (record_type)
    {
      case DNS_RECORD_TYPE_A:
        record_status = static_readIpAddress(&record, AF_INET, NS_INADDRSZ, &answer->mp_texts[answer->m_recordCount]);
        break;
      case DNS_RECORD_TYPE_AAAA:
        record_status = static_readIpAddress(&record, AF_INET6, NS_IN6ADDRSZ, &answer->mp_texts[answer->m_recordCount]);
        break;
      case DNS_RECORD_TYPE_NS:
      case DNS_RECORD_TYPE_CNAME:
      case DNS_RECORD_TYPE_PTR:
        record_status = static_readDomainName(message_handle, &record, &answer->mp_texts[answer->m_recordCount]);
        break;
      case DNS_RECORD_TYPE_TXT:
        record_status = static_readTxtRecord(&record, &answer->mp_texts[answer->m_recordCount]);
        break;
      case DNS_RECORD_TYPE_MX:
      {
        bool is_null_mx = false;
        record_status = static_readMxRecord(message_handle, &record, &answer->mp_mxRecords[answer->m_recordCount], &is_null_mx);
        if (record_status == DNS_ANSWER_OK && is_null_mx)
        {
          answer->m_hasNullMx = true;
          continue;
        }
        break;
      }
      case DNS_RECORD_TYPE_SOA:
        if (answer->m_recordCount == 1)
          continue;
        record_status = static_readSoaRecord(message_handle, &record, answer->mp_soaRecord);
        break;
      case DNS_RECORD_TYPE_CAA:
        record_status = static_readCaaRecord(&record, &answer->mp_caaRecords[answer->m_recordCount]);
        break;
    }
    if (record_status != DNS_ANSWER_OK)
      return record_status;

    answer->m_recordCount++;
  }
  return DNS_ANSWER_OK;
}

static void static_openNameserverSockets(const struct __res_state* state, DnsNameserver_t nameservers_out[MAXNS], int* nameserver_count_out)
{
  int nameserver_count = 0;
  for (int i = 0; i < state->nscount && i < MAXNS; i++)
  {
    DnsNameserver_t nameserver;
    memset(&nameserver, 0, sizeof(nameserver));

    if (state->nsaddr_list[i].sin_family == AF_INET)
    {
      memcpy(&nameserver.m_address, &state->nsaddr_list[i], sizeof(struct sockaddr_in));
      nameserver.m_addressLen = sizeof(struct sockaddr_in);
    }
    else if (state->_u._ext.nsaddrs[i] != NULL && state->_u._ext.nsaddrs[i]->sin6_family == AF_INET6)
    {
      memcpy(&nameserver.m_address, state->_u._ext.nsaddrs[i], sizeof(struct sockaddr_in6));
      nameserver.m_addressLen = sizeof(struct sockaddr_in6);
    }
    else
      continue;

    nameserver.m_udpFd = socket(nameserver.m_address.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (nameserver.m_udpFd < 0)
      continue;
    if (connect(nameserver.m_udpFd, (const struct sockaddr*)&nameserver.m_address, nameserver.m_addressLen) != 0)
    {
      close(nameserver.m_udpFd);
      continue;
    }
    nameservers_out[nameserver_count++] = nameserver;
  }

  *nameserver_count_out = nameserver_count;
}

static bool static_tryWriteQuestionMessage(struct __res_state* state, const DnsQuestion_t* question, DnsQuestionState_t* question_state)
{
  unsigned char* question_message = question_state->ma_message + DNS_TCP_LENGTH_PREFIX_SIZE;
  int question_message_len = res_nmkquery(state, ns_o_query, question->mp_domainName, ns_c_in, DNS_RECORD_TYPE_WIRE_VALUES[question->m_type], NULL, 0, NULL, question_message, DNS_QUESTION_MESSAGE_BUFFER_SIZE - DNS_EDNS_OPT_SIZE);
  if (question_message_len < 0)
    return false;

  static_appendEdnsOptRecord(question_message, question_message_len);

  question_state->m_questionMessageByteCount = (size_t)question_message_len + DNS_EDNS_OPT_SIZE;
  question_state->m_questionMessageId        = (uint16_t)ns_get16(question_message);
  ns_put16((unsigned int)question_state->m_questionMessageByteCount, question_state->ma_message);
  return true;
}

static void static_appendEdnsOptRecord(unsigned char* question_message, int question_message_len)
{
  unsigned char* field = question_message + question_message_len;
  *field++ = 0;
  NS_PUT16(ns_t_opt, field);
  NS_PUT16(DNS_UDP_PAYLOAD_SIZE, field);
  NS_PUT32(0, field);
  NS_PUT16(0, field);
  ns_put16(1, question_message + DNS_HEADER_ADDITIONAL_COUNT_OFFSET);
}

static void static_sendUdp(DnsQuestionState_t* question_state, const DnsNameserver_t* nameserver, int64_t now_ms)
{
  (void)send(nameserver->m_udpFd, question_state->ma_message + DNS_TCP_LENGTH_PREFIX_SIZE, question_state->m_questionMessageByteCount, MSG_DONTWAIT | MSG_NOSIGNAL);
  question_state->m_udpResendAtMs = now_ms + DNS_RETRANSMIT_MS;
  question_state->m_udpSendCount++;
}

static void static_finishQuestion(DnsQuestionState_t* question_state, DnsAnswer_t answer, DnsAnswer_t* answer_out)
{
  if (question_state->m_tcpFd >= 0)
    close(question_state->m_tcpFd);
  question_state->m_tcpFd = -1;

  free(question_state->mp_tcpAnswerBytes);
  question_state->mp_tcpAnswerBytes = NULL;
  question_state->m_pendingPhase = DNS_PENDING_DONE;

  *answer_out = answer;
}

static void static_finishQuestionWithStatus(DnsQuestionState_t* question_state, DnsAnswerStatus_t status, DnsAnswer_t* answer_out)
{
  DnsAnswer_t answer;
  memset(&answer, 0, sizeof(answer));
  answer.m_status = status;
  static_finishQuestion(question_state, answer, answer_out);
}

static void static_startTcp(DnsQuestionState_t* question_state, const DnsNameserver_t* nameserver, DnsAnswer_t* answer_out)
{
  question_state->m_tcpFd = socket(nameserver->m_address.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (question_state->m_tcpFd < 0)
  {
    static_finishQuestionWithStatus(question_state, DNS_ANSWER_TRUNCATED, answer_out);
    return;
  }
  if (connect(question_state->m_tcpFd, (const struct sockaddr*)&nameserver->m_address, nameserver->m_addressLen) != 0 && errno != EINPROGRESS)
  {
    static_finishQuestionWithStatus(question_state, DNS_ANSWER_TRUNCATED, answer_out);
    return;
  }
  question_state->m_pendingPhase = DNS_PENDING_TCP_SEND;
}

static bool static_shouldAskNextNameserver(const unsigned char* datagram, const DnsQuestionState_t* question_state, int nameserver_count)
{
  int  rcode             = datagram[3] & DNS_HEADER_RCODE_MASK;
  bool is_server_failure = rcode == ns_r_servfail || rcode == ns_r_notimpl || rcode == ns_r_refused;

  return is_server_failure && question_state->m_udpSendCount < nameserver_count;
}

static void static_readUdpAnswer(const DnsQuestionBatch_t* batch, const DnsNameserver_t* nameserver)
{
  const DnsQuestion_t* questions        = batch->mp_questions;
  DnsQuestionState_t*  question_states  = batch->mp_questionStates;
  DnsAnswer_t*         answers_out      = batch->mp_answers;
  int                  question_count   = batch->m_questionCount;
  int                  nameserver_count = batch->m_nameserverCount;

  unsigned char datagram[DNS_UDP_PAYLOAD_SIZE];
  ssize_t datagram_len = recv(nameserver->m_udpFd, datagram, sizeof(datagram), MSG_DONTWAIT | MSG_TRUNC);
  if (datagram_len < 0 || (size_t)datagram_len > sizeof(datagram))
    return;

  for (int i = 0; i < question_count; i++)
  {
    if (question_states[i].m_pendingPhase != DNS_PENDING_UDP_READ)
      continue;

    DnsAnswer_t answer;
    if (!dns_tryReadResponse(datagram, (size_t)datagram_len, &questions[i], question_states[i].m_questionMessageId, &answer))
      continue;

    if (answer.m_status == DNS_ANSWER_TRUNCATED)
      static_startTcp(&question_states[i], nameserver, &answers_out[i]);
    else if (answer.m_status == DNS_ANSWER_SERVER_ERROR && static_shouldAskNextNameserver(datagram, &question_states[i], nameserver_count))
      question_states[i].m_udpResendAtMs = 0;
    else
      static_finishQuestion(&question_states[i], answer, &answers_out[i]);
    return;
  }
}

static void static_sendTcp(DnsQuestionState_t* question_state, DnsAnswer_t* answer_out)
{
  size_t  message_len = DNS_TCP_LENGTH_PREFIX_SIZE + question_state->m_questionMessageByteCount;
  ssize_t sent        = send(question_state->m_tcpFd, question_state->ma_message + question_state->m_tcpSentByteCount, message_len - question_state->m_tcpSentByteCount, MSG_DONTWAIT | MSG_NOSIGNAL);
  if (sent < 0)
  {
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      static_finishQuestionWithStatus(question_state, DNS_ANSWER_TRUNCATED, answer_out);
    return;
  }
  question_state->m_tcpSentByteCount += (size_t)sent;
  if (question_state->m_tcpSentByteCount == message_len)
    question_state->m_pendingPhase = DNS_PENDING_TCP_READ;
}

static void static_readTcp(const DnsQuestion_t* question, DnsQuestionState_t* question_state, DnsAnswer_t* answer_out)
{
  if (question_state->m_tcpLengthPrefixReadByteCount < DNS_TCP_LENGTH_PREFIX_SIZE)
    static_readTcpLengthPrefix(question_state, answer_out);
  else
    static_readTcpAnswer(question, question_state, answer_out);
}

static bool static_tryReceiveTcpBytes(DnsQuestionState_t* question_state, unsigned char* fill_position, size_t missing_byte_count, size_t* received_byte_count_out, DnsAnswer_t* answer_out)
{
  ssize_t received_byte_count = recv(question_state->m_tcpFd, fill_position, missing_byte_count, MSG_DONTWAIT);
  if (received_byte_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return false;
  if (received_byte_count <= 0)
  {
    static_finishQuestionWithStatus(question_state, DNS_ANSWER_TRUNCATED, answer_out);
    return false;
  }
  *received_byte_count_out = (size_t)received_byte_count;
  return true;
}

static void static_readTcpLengthPrefix(DnsQuestionState_t* question_state, DnsAnswer_t* answer_out)
{
  unsigned char* fill_position       = question_state->ma_tcpLengthPrefixBytes + question_state->m_tcpLengthPrefixReadByteCount;
  size_t         missing_byte_count  = DNS_TCP_LENGTH_PREFIX_SIZE - question_state->m_tcpLengthPrefixReadByteCount;
  size_t         received_byte_count = 0;
  if (!static_tryReceiveTcpBytes(question_state, fill_position, missing_byte_count, &received_byte_count, answer_out))
    return;

  question_state->m_tcpLengthPrefixReadByteCount += received_byte_count;
  if (question_state->m_tcpLengthPrefixReadByteCount < DNS_TCP_LENGTH_PREFIX_SIZE)
    return;

  static_prepareTcpAnswerBuffer(question_state, answer_out);
}

static void static_prepareTcpAnswerBuffer(DnsQuestionState_t* question_state, DnsAnswer_t* answer_out)
{
  question_state->m_tcpAnswerByteCount = ns_get16(question_state->ma_tcpLengthPrefixBytes);
  if (question_state->m_tcpAnswerByteCount == 0)
  {
    static_finishQuestionWithStatus(question_state, DNS_ANSWER_MALFORMED, answer_out);
    return;
  }
  question_state->mp_tcpAnswerBytes = malloc(question_state->m_tcpAnswerByteCount);
  if (question_state->mp_tcpAnswerBytes == NULL)
    static_finishQuestionWithStatus(question_state, DNS_ANSWER_NO_MEMORY, answer_out);
}

static void static_readTcpAnswer(const DnsQuestion_t* question, DnsQuestionState_t* question_state, DnsAnswer_t* answer_out)
{
  unsigned char* fill_position       = question_state->mp_tcpAnswerBytes + question_state->m_tcpAnswerReadByteCount;
  size_t         missing_byte_count  = question_state->m_tcpAnswerByteCount - question_state->m_tcpAnswerReadByteCount;
  size_t         received_byte_count = 0;
  if (!static_tryReceiveTcpBytes(question_state, fill_position, missing_byte_count, &received_byte_count, answer_out))
    return;

  question_state->m_tcpAnswerReadByteCount += received_byte_count;
  if (question_state->m_tcpAnswerReadByteCount < question_state->m_tcpAnswerByteCount)
    return;

  DnsAnswer_t answer;
  if (!dns_tryReadResponse(question_state->mp_tcpAnswerBytes, question_state->m_tcpAnswerByteCount, question, question_state->m_questionMessageId, &answer))
  {
    static_finishQuestionWithStatus(question_state, DNS_ANSWER_MALFORMED, answer_out);
    return;
  }
  static_finishQuestion(question_state, answer, answer_out);
}

static void static_runPollLoop(const DnsQuestionBatch_t* batch, int64_t deadline_at)
{
  for (;;)
  {
    int64_t now_ms = monotonic_nowMs();
    if (!static_isAnyQuestionPending(batch) || now_ms >= deadline_at)
      return;

    DnsPollList_t poll_list;
    static_buildPollList(batch, &poll_list);
    int64_t poll_wait_ms = static_computePollWaitMs(batch, now_ms, deadline_at);

    int ready_socket_count = poll(poll_list.ma_fds, (nfds_t)poll_list.m_fdCount, (int)poll_wait_ms);
    if (ready_socket_count < 0 && errno != EINTR)
      return;

    if (ready_socket_count > 0)
      static_serveReadySockets(batch, &poll_list);

    static_resendOverdueUdpQuestions(batch, monotonic_nowMs());
  }
}

static bool static_isAnyQuestionPending(const DnsQuestionBatch_t* batch)
{
  for (int i = 0; i < batch->m_questionCount; i++)
    if (batch->mp_questionStates[i].m_pendingPhase != DNS_PENDING_DONE)
      return true;

  return false;
}

static void static_buildPollList(const DnsQuestionBatch_t* batch, DnsPollList_t* poll_list_out)
{
  int fd_count = 0;
  for (int i = 0; i < batch->m_questionCount; i++)
  {
    const DnsQuestionState_t* question_state = &batch->mp_questionStates[i];
    if (question_state->m_pendingPhase != DNS_PENDING_TCP_SEND && question_state->m_pendingPhase != DNS_PENDING_TCP_READ)
      continue;

    poll_list_out->ma_fds[fd_count].fd                = question_state->m_tcpFd;
    poll_list_out->ma_fds[fd_count].events            = question_state->m_pendingPhase == DNS_PENDING_TCP_SEND ? POLLOUT : POLLIN;
    poll_list_out->ma_tcpQuestionIndexes[fd_count++]  = i;
  }
  poll_list_out->m_tcpFdCount = fd_count;

  for (int i = 0; i < batch->m_nameserverCount; i++)
  {
    poll_list_out->ma_fds[fd_count].fd     = batch->mp_nameservers[i].m_udpFd;
    poll_list_out->ma_fds[fd_count].events = POLLIN;
    fd_count++;
  }
  poll_list_out->m_fdCount = fd_count;
}

static int64_t static_computePollWaitMs(const DnsQuestionBatch_t* batch, int64_t now_ms, int64_t deadline_at)
{
  int64_t wait_ms = deadline_at - now_ms;
  for (int i = 0; i < batch->m_questionCount; i++)
  {
    const DnsQuestionState_t* question_state = &batch->mp_questionStates[i];
    if (question_state->m_pendingPhase == DNS_PENDING_UDP_READ && question_state->m_udpResendAtMs - now_ms < wait_ms)
      wait_ms = question_state->m_udpResendAtMs - now_ms;
  }
  return wait_ms < 0 ? 0 : wait_ms;
}

static void static_serveReadySockets(const DnsQuestionBatch_t* batch, const DnsPollList_t* poll_list)
{
  for (int i = 0; i < poll_list->m_fdCount; i++)
  {
    if (poll_list->ma_fds[i].revents == 0)
      continue;
    if (i >= poll_list->m_tcpFdCount)
    {
      static_readUdpAnswer(batch, &batch->mp_nameservers[i - poll_list->m_tcpFdCount]);
      continue;
    }

    int question_index = poll_list->ma_tcpQuestionIndexes[i];
    if (batch->mp_questionStates[question_index].m_pendingPhase == DNS_PENDING_TCP_SEND)
      static_sendTcp(&batch->mp_questionStates[question_index], &batch->mp_answers[question_index]);
    else if (batch->mp_questionStates[question_index].m_pendingPhase == DNS_PENDING_TCP_READ)
      static_readTcp(&batch->mp_questions[question_index], &batch->mp_questionStates[question_index], &batch->mp_answers[question_index]);
  }
}

static void static_resendOverdueUdpQuestions(const DnsQuestionBatch_t* batch, int64_t now_ms)
{
  for (int i = 0; i < batch->m_questionCount; i++)
  {
    DnsQuestionState_t* question_state = &batch->mp_questionStates[i];
    if (question_state->m_pendingPhase != DNS_PENDING_UDP_READ || question_state->m_udpResendAtMs > now_ms)
      continue;

    question_state->m_nameserverIndex = (question_state->m_nameserverIndex + 1) % batch->m_nameserverCount;
    static_sendUdp(question_state, &batch->mp_nameservers[question_state->m_nameserverIndex], now_ms);
  }
}

static bool static_tryFindNonPublicAddresses(DNSLOOKUPRecord_t* record)
{
  const DnsAnswer_t* address_answers[]    = { &record->ma_answers[DNS_RECORD_TYPE_A], &record->ma_answers[DNS_RECORD_TYPE_AAAA] };
  const int          address_answer_count = (int)(sizeof(address_answers) / sizeof(address_answers[0]));

  int address_count = 0;
  for (int i = 0; i < address_answer_count; i++)
    address_count += address_answers[i]->m_recordCount;
  if (address_count == 0)
    return true;

  record->mp_nonPublicAddresses = calloc((size_t)address_count, sizeof(const DnsRecordText_t*));
  if (record->mp_nonPublicAddresses == NULL)
    return false;

  for (int i = 0; i < address_answer_count; i++)
    for (int j = 0; j < address_answers[i]->m_recordCount; j++)
      if (!ipguard_isGloballyReachableIp(address_answers[i]->mp_texts[j].mp_bytes))
        record->mp_nonPublicAddresses[record->m_nonPublicAddressCount++] = &address_answers[i]->mp_texts[j];

  return true;
}

static void static_findTxtServices(DNSLOOKUPRecord_t* record)
{
  const DnsAnswer_t* txt_answer = &record->ma_answers[DNS_RECORD_TYPE_TXT];
  for (int i = 0; i < DNS_TXT_SERVICE_COUNT; i++)
  {
    const char* evidence = dns_txtServices[i].mp_evidence;
    for (int j = 0; j < txt_answer->m_recordCount; j++)
    {
      if (memmem(txt_answer->mp_texts[j].mp_bytes, txt_answer->mp_texts[j].m_byteCount, evidence, strlen(evidence)) != NULL)
      {
        record->ma_services[record->m_serviceCount++] = &dns_txtServices[i];
        break;
      }
    }
  }
}

static const DnsTakeoverSuffix_t* static_findTakeoverSuffix(const char* hostname)
{
  size_t hostname_len = strlen(hostname);
  for (int i = 0; i < DNS_TAKEOVER_SUFFIX_COUNT; i++)
  {
    if (bytes_isNameUnderSuffix(hostname, hostname_len, dns_takeoverSuffixes[i].mp_suffix))
      return &dns_takeoverSuffixes[i];
  }
  return NULL;
}

static bool static_tryWriteReverseName(const char* ip_address, char reverse_name_out[DNS_REVERSE_NAME_SIZE])
{
  struct sockaddr_in ipv4_address;
  memset(&ipv4_address, 0, sizeof(ipv4_address));
  if (inet_pton(AF_INET, ip_address, &ipv4_address.sin_addr) == 1)
  {
    ipv4_address.sin_family = AF_INET;
    if (!ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&ipv4_address, sizeof(ipv4_address)))
      return false;

    const uint8_t* bytes = (const uint8_t*)&ipv4_address.sin_addr;
    int reverse_name_len = snprintf(reverse_name_out, DNS_REVERSE_NAME_SIZE, "%u.%u.%u.%u.in-addr.arpa", bytes[3], bytes[2], bytes[1], bytes[0]);
    return reverse_name_len >= 0 && (size_t)reverse_name_len < DNS_REVERSE_NAME_SIZE;
  }

  struct sockaddr_in6 ipv6_address;
  memset(&ipv6_address, 0, sizeof(ipv6_address));
  if (inet_pton(AF_INET6, ip_address, &ipv6_address.sin6_addr) != 1)
    return false;

  ipv6_address.sin6_family = AF_INET6;
  if (!ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&ipv6_address, sizeof(ipv6_address)))
    return false;

  static const char HEX_DIGITS[] = "0123456789abcdef";
  char* cursor = reverse_name_out;
  for (int i = 15; i >= 0; i--)
  {
    uint8_t byte = ipv6_address.sin6_addr.s6_addr[i];
    *cursor++ = HEX_DIGITS[byte & 0x0F];
    *cursor++ = '.';
    *cursor++ = HEX_DIGITS[byte >> 4];
    *cursor++ = '.';
  }
  memcpy(cursor, "ip6.arpa", sizeof("ip6.arpa"));
  return true;
}
