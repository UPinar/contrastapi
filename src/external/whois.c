#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "whois.h"
#include "bytes.h"
#include "datetime.h"
#include "dns.h"
#include "ipguard.h"
#include "monotonic.h"
#include "netconnect.h"
#include "validate.h"

#define WHOIS_QUERY_END "\r\n"

#define WHOIS_IANA_REGISTRAR_ID_MAX_DIGITS 9

#define WHOIS_DAY_TEXT_LEN       10
#define WHOIS_DATE_TIME_TEXT_LEN 19

typedef struct {
  const char*   mp_eppCode;
  const char*   mp_rdapName;
} WhoisStatusName_t;

static const WhoisStatusName_t EPP_STATUS_NAMES[] = {
  { "addPeriod",                "add period"                 },
  { "autoRenewPeriod",          "auto renew period"          },
  { "clientDeleteProhibited",   "client delete prohibited"   },
  { "clientHold",               "client hold"                },
  { "clientRenewProhibited",    "client renew prohibited"    },
  { "clientTransferProhibited", "client transfer prohibited" },
  { "clientUpdateProhibited",   "client update prohibited"   },
  { "inactive",                 "inactive"                   },
  { "ok",                       "active"                     },
  { "pendingCreate",            "pending create"             },
  { "pendingDelete",            "pending delete"             },
  { "pendingRenew",             "pending renew"              },
  { "pendingRestore",           "pending restore"            },
  { "pendingTransfer",          "pending transfer"           },
  { "pendingUpdate",            "pending update"             },
  { "redemptionPeriod",         "redemption period"          },
  { "renewPeriod",              "renew period"               },
  { "serverDeleteProhibited",   "server delete prohibited"   },
  { "serverHold",               "server hold"                },
  { "serverRenewProhibited",    "server renew prohibited"    },
  { "serverTransferProhibited", "server transfer prohibited" },
  { "serverUpdateProhibited",   "server update prohibited"   },
  { "transferPeriod",           "transfer period"            },
};

typedef enum {
  WHOIS_NAME_NOT_SEEN,
  WHOIS_NAME_ASKED,
  WHOIS_NAME_OTHER,
} WhoisNameMatch_t;

static int                    static_compareTld          (const void* tld, const void* entry);
static void                   static_trimSpaces          (const char** bytes, size_t* byte_count);
static bool                   static_isCommentLine       (const char* line, size_t line_len);
static bool                   static_trySplitKeyValue    (const char* line, size_t line_len, const char** key_out, size_t* key_len_out, const char** value_out, size_t* value_len_out);
static void                   static_clearRegistration   (RdapRegistration_t* registration);
static const WhoisKey_t*      static_findKey             (const WhoisKeyMap_t* key_map, const char* key, size_t key_len);
static void                   static_readValue           (WhoisField_t field, const char* value, size_t value_len, RdapRegistration_t* registration);
static void                   static_copyFirstText       (const char* value, size_t value_len, char* field, size_t field_size);
static void                   static_readIanaId          (const char* value, size_t value_len, RdapRegistration_t* registration);
static void                   static_writeDate           (const char* value, size_t value_len, char* field, size_t field_size);
static bool                   static_tryReadDay          (const char* value, int* year_out, int* month_out, int* day_out);
static bool                   static_isUtcZone           (const char* rest, size_t rest_len);
static void                   static_addStatus           (const char* value, size_t value_len, RdapRegistration_t* registration);
static void                   static_addNameServer       (const char* value, size_t value_len, RdapRegistration_t* registration);
static RdapDelegationSigned_t static_readDelegationSigned(const char* value, size_t value_len);
static bool                   static_tryAskAddresses     (const DnsAnswer_t* address_answers, int address_answer_count, const char* query, size_t query_len, int64_t deadline_at, char* answer, size_t* answer_len);
static bool                   static_tryExchange         (int fd, const char* query, size_t query_len, int64_t deadline_at, char* answer, size_t* answer_len);

static int static_compareTld(const void* tld, const void* entry)
{
  return strcasecmp((const char*)tld, ((const WhoisServer_t*)entry)->mp_tld);
}

const WhoisServer_t* whois_findServer(const char* domain_name)
{
  assert(domain_name != NULL);

  const char* last_dot = strrchr(domain_name, '.');
  const char* tld      = last_dot != NULL ? last_dot + 1 : domain_name;

  return bsearch(tld, whois_servers, (size_t)whois_serverCount, sizeof(whois_servers[0]), static_compareTld);
}

WhoisStatus_t whois_readAnswer(const char* answer, size_t answer_len, const char* domain_name, const WhoisServer_t* server, RdapRegistration_t* registration_out)
{
  assert(answer           != NULL || answer_len == 0);
  assert(domain_name      != NULL);
  assert(server           != NULL);
  assert(registration_out != NULL);

  static_clearRegistration(registration_out);

  WhoisNameMatch_t name_match           = WHOIS_NAME_NOT_SEEN;
  bool             is_any_record_line   = false;
  bool             is_name_server_block = false;
  bool             is_not_registered    = false;
  size_t           line_start           = 0;
  while (line_start < answer_len && !is_not_registered)
  {
    const char* line     = answer + line_start;
    const char* line_end = memchr(line, '\n', answer_len - line_start);
    size_t      line_len = line_end != NULL ? (size_t)(line_end - line) : answer_len - line_start;
    line_start += line_len + 1;

    static_trimSpaces(&line, &line_len);
    if (memchr(line, '\0', line_len) != NULL || static_isCommentLine(line, line_len))
      continue;
    if (line_len == 0)
    {
      is_name_server_block = false;
      continue;
    }

    is_any_record_line = true;
    if (server->mp_notFoundMarker != NULL && memmem(line, line_len, server->mp_notFoundMarker, strlen(server->mp_notFoundMarker)) != NULL)
    {
      is_not_registered = true;
      continue;
    }

    const char* key       = NULL;
    size_t      key_len   = 0;
    const char* value     = NULL;
    size_t      value_len = 0;
    if (!static_trySplitKeyValue(line, line_len, &key, &key_len, &value, &value_len))
    {
      if (is_name_server_block)
        static_addNameServer(line, line_len, registration_out);
      continue;
    }

    is_name_server_block = false;
    const WhoisKey_t* known_key = static_findKey(server->mp_keyMap, key, key_len);
    if (known_key == NULL)
      continue;
    if (known_key->m_field == WHOIS_FIELD_NAME_SERVER && value_len == 0)
    {
      is_name_server_block = true;
      continue;
    }
    if (known_key->m_field == WHOIS_FIELD_DOMAIN_NAME)
    {
      if (value_len > 0 && name_match != WHOIS_NAME_OTHER)
        name_match = bytes_isEqual(value, value_len, domain_name, true) ? WHOIS_NAME_ASKED : WHOIS_NAME_OTHER;
      continue;
    }

    static_readValue(known_key->m_field, value, value_len, registration_out);
  }

  if (server->mp_notFoundMarker == NULL && !is_any_record_line)
    is_not_registered = true;

  if (is_not_registered || name_match != WHOIS_NAME_ASKED)
  {
    static_clearRegistration(registration_out);
    return is_not_registered ? WHOIS_NOT_REGISTERED : WHOIS_UPSTREAM_ERROR;
  }

  return WHOIS_OK;
}

static void static_trimSpaces(const char** bytes, size_t* byte_count)
{
  while (*byte_count > 0 && ((*bytes)[0] == ' ' || (*bytes)[0] == '\t' || (*bytes)[0] == '\r'))
  {
    (*bytes)++;
    (*byte_count)--;
  }
  while (*byte_count > 0 && ((*bytes)[*byte_count - 1] == ' ' || (*bytes)[*byte_count - 1] == '\t' || (*bytes)[*byte_count - 1] == '\r'))
    (*byte_count)--;
}

static bool static_isCommentLine(const char* line, size_t line_len)
{
  return line_len > 0 && (line[0] == '%' || line[0] == '#');
}

static bool static_trySplitKeyValue(const char* line, size_t line_len, const char** key_out, size_t* key_len_out, const char** value_out, size_t* value_len_out)
{
  const char* colon = memchr(line, ':', line_len);
  if (colon == NULL)
    return false;

  *key_out       = line;
  *key_len_out   = (size_t)(colon - line);
  *value_out     = colon + 1;
  *value_len_out = line_len - *key_len_out - 1;
  static_trimSpaces(key_out, key_len_out);
  static_trimSpaces(value_out, value_len_out);
  return true;
}

static void static_clearRegistration(RdapRegistration_t* registration)
{
  memset(registration, 0, sizeof(*registration));
  registration->m_registrarIanaId = -1;
}

static const WhoisKey_t* static_findKey(const WhoisKeyMap_t* key_map, const char* key, size_t key_len)
{
  for (int i = 0; i < key_map->m_keyCount; i++)
  {
    if (bytes_isEqual(key, key_len, key_map->mp_keys[i].mp_key, true))
      return &key_map->mp_keys[i];
  }
  return NULL;
}

static void static_readValue(WhoisField_t field, const char* value, size_t value_len, RdapRegistration_t* registration)
{
  switch (field)
  {
    case WHOIS_FIELD_DOMAIN_NAME:
      break;
    case WHOIS_FIELD_REGISTRAR_NAME:
      static_copyFirstText(value, value_len, registration->ma_registrarName, sizeof(registration->ma_registrarName));
      break;
    case WHOIS_FIELD_REGISTRAR_IANA_ID:
      static_readIanaId(value, value_len, registration);
      break;
    case WHOIS_FIELD_CREATED_AT:
      static_writeDate(value, value_len, registration->ma_createdAt, sizeof(registration->ma_createdAt));
      break;
    case WHOIS_FIELD_UPDATED_AT:
      static_writeDate(value, value_len, registration->ma_updatedAt, sizeof(registration->ma_updatedAt));
      break;
    case WHOIS_FIELD_EXPIRES_AT:
      static_writeDate(value, value_len, registration->ma_expiresAt, sizeof(registration->ma_expiresAt));
      break;
    case WHOIS_FIELD_STATUS:
      static_addStatus(value, value_len, registration);
      break;
    case WHOIS_FIELD_NAME_SERVER:
      static_addNameServer(value, value_len, registration);
      break;
    case WHOIS_FIELD_DNSSEC:
      if (registration->m_delegationSigned == RDAP_DELEGATION_SIGNED_UNKNOWN)
        registration->m_delegationSigned = static_readDelegationSigned(value, value_len);
      break;
  }
}

static void static_copyFirstText(const char* value, size_t value_len, char* field, size_t field_size)
{
  if (field[0] != '\0' || value_len == 0 || value_len >= field_size)
    return;
  memcpy(field, value, value_len);
  field[value_len] = '\0';
}

static void static_readIanaId(const char* value, size_t value_len, RdapRegistration_t* registration)
{
  if (registration->m_registrarIanaId >= 0 || value_len == 0 || value_len > WHOIS_IANA_REGISTRAR_ID_MAX_DIGITS)
    return;

  long iana_id = 0;
  for (size_t i = 0; i < value_len; i++)
  {
    if (!isdigit((unsigned char)value[i]))
      return;
    iana_id = iana_id * 10 + (value[i] - '0');
  }
  registration->m_registrarIanaId = iana_id;
}

static void static_writeDate(const char* value, size_t value_len, char* field, size_t field_size)
{
  int year = 0, month = 0, day = 0;
  if (field[0] != '\0' || value_len < WHOIS_DAY_TEXT_LEN || !static_tryReadDay(value, &year, &month, &day))
    return;

  if (value_len == WHOIS_DAY_TEXT_LEN)
  {
    snprintf(field, field_size, "%04d-%02d-%02d", year, month, day);
    return;
  }

  int hour = 0, minute = 0, second = 0;
  if (value_len < WHOIS_DATE_TIME_TEXT_LEN || (value[10] != 'T' && value[10] != ' ') || value[13] != ':' || value[16] != ':' ||
      !datetime_tryReadDigits(value + 11, 2, &hour) || !datetime_tryReadDigits(value + 14, 2, &minute) ||
      !datetime_tryReadDigits(value + 17, 2, &second) || hour > 23 || minute > 59 || second > 60)
    return;

  if (value[10] == 'T' && static_isUtcZone(value + WHOIS_DATE_TIME_TEXT_LEN, value_len - WHOIS_DATE_TIME_TEXT_LEN))
    snprintf(field, field_size, "%04d-%02d-%02dT%02d:%02d:%02dZ", year, month, day, hour, minute, second);
  else
    snprintf(field, field_size, "%04d-%02d-%02d", year, month, day);
}

static bool static_tryReadDay(const char* value, int* year_out, int* month_out, int* day_out)
{
  bool is_read = false;
  if (value[4] == '-' && value[7] == '-')
  {
    is_read = datetime_tryReadDigits(value, 4, year_out)      &&
              datetime_tryReadDigits(value + 5, 2, month_out) &&
              datetime_tryReadDigits(value + 8, 2, day_out);
  }
  else if ((value[2] == '-' || value[2] == '.') && value[5] == value[2])
  {
    is_read = datetime_tryReadDigits(value, 2, day_out)       &&
              datetime_tryReadDigits(value + 3, 2, month_out) &&
              datetime_tryReadDigits(value + 6, 4, year_out);
  }

  return is_read && *month_out >= 1 && *month_out <= 12 && *day_out >= 1 && *day_out <= 31;
}

static bool static_isUtcZone(const char* rest, size_t rest_len)
{
  if (rest_len == 0 || rest[rest_len - 1] != 'Z')
    return false;
  if (rest_len == 1)
    return true;
  if (rest[0] != '.' || rest_len == 2)
    return false;
  for (size_t i = 1; i < rest_len - 1; i++)
  {
    if (!isdigit((unsigned char)rest[i]))
      return false;
  }
  return true;
}

static void static_addStatus(const char* value, size_t value_len, RdapRegistration_t* registration)
{
  size_t word_len = 0;
  while (word_len < value_len && value[word_len] != ' ' && value[word_len] != '\t')
    word_len++;

  for (size_t i = 0; i < sizeof(EPP_STATUS_NAMES) / sizeof(EPP_STATUS_NAMES[0]); i++)
  {
    if (bytes_isEqual(value, word_len, EPP_STATUS_NAMES[i].mp_eppCode, true))
    {
      value     = EPP_STATUS_NAMES[i].mp_rdapName;
      value_len = strlen(value);
      break;
    }
  }

  if (value_len == 0 || value_len > RDAP_STATUS_MAX_LEN)
    return;
  if (registration->m_statusCount < RDAP_STATUS_MAX_COUNT)
  {
    memcpy(registration->ma_statuses[registration->m_statusCount], value, value_len);
    registration->ma_statuses[registration->m_statusCount][value_len] = '\0';
  }
  if (registration->m_statusCount < INT_MAX)
    registration->m_statusCount++;
}

static void static_addNameServer(const char* value, size_t value_len, RdapRegistration_t* registration)
{
  size_t name_len = 0;
  while (name_len < value_len && value[name_len] != ' ' && value[name_len] != '\t')
    name_len++;
  if (name_len > 0 && value[name_len - 1] == '.')
    name_len--;
  if (name_len == 0 || name_len > VALIDATE_DOMAIN_NAME_MAX_LEN)
    return;

  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  for (size_t i = 0; i < name_len; i++)
    name[i] = (char)tolower((unsigned char)value[i]);
  name[name_len] = '\0';
  if (!validate_domainName(name))
    return;

  if (registration->m_nameServerCount < RDAP_NAME_SERVER_MAX_COUNT)
    memcpy(registration->ma_nameServers[registration->m_nameServerCount], name, name_len + 1);
  if (registration->m_nameServerCount < INT_MAX)
    registration->m_nameServerCount++;
}

static RdapDelegationSigned_t static_readDelegationSigned(const char* value, size_t value_len)
{
  if (bytes_isEqual(value, value_len, "signedDelegation", true)  ||
      bytes_isEqual(value, value_len, "signed delegation", true) ||
      bytes_isEqual(value, value_len, "signed", true))
  {
    return RDAP_DELEGATION_SIGNED_YES;
  }

  if (bytes_isEqual(value, value_len, "unsigned", true) ||
      bytes_isEqual(value, value_len, "unsigned delegation", true))
  {
    return RDAP_DELEGATION_SIGNED_NO;
  }

  return RDAP_DELEGATION_SIGNED_UNKNOWN;
}

WhoisStatus_t whois_lookupDomain(const char* domain_name, const WhoisServer_t* server, RdapRegistration_t* registration_out)
{
  assert(domain_name      != NULL);
  assert(server           != NULL);
  assert(registration_out != NULL);

  static_clearRegistration(registration_out);

  if (!validate_domainName(domain_name))
    return WHOIS_INVALID_NAME;

  int64_t deadline_at = monotonic_nowMs() + WHOIS_DEADLINE_MS;

  char query[VALIDATE_DOMAIN_NAME_MAX_LEN + sizeof(WHOIS_QUERY_END)];
  int  query_len = snprintf(query, sizeof(query), "%s" WHOIS_QUERY_END, domain_name);
  if (query_len < 0 || (size_t)query_len >= sizeof(query))
    return WHOIS_INVALID_NAME;

  DnsQuestion_t questions[] = {
    { .mp_domainName = server->mp_host, .m_type = DNS_RECORD_TYPE_A    },
    { .mp_domainName = server->mp_host, .m_type = DNS_RECORD_TYPE_AAAA },
  };
  int question_count = (int)(sizeof(questions) / sizeof(questions[0]));
  DnsAnswer_t address_answers[sizeof(questions) / sizeof(questions[0])];
  dns_askQuestions(questions, question_count, WHOIS_RESOLVE_DEADLINE_MS, address_answers);

  WhoisStatus_t status     = WHOIS_UPSTREAM_ERROR;
  char*         answer     = malloc(WHOIS_MAX_ANSWER_BYTE_COUNT + 1);
  size_t        answer_len = 0;
  if (answer != NULL && static_tryAskAddresses(address_answers, question_count, query, (size_t)query_len, deadline_at, answer, &answer_len))
    status = whois_readAnswer(answer, answer_len, domain_name, server, registration_out);

  for (int i = 0; i < question_count; i++)
    dns_answerFree(&address_answers[i]);

  if (answer != NULL)
  {
    explicit_bzero(answer, answer_len);
    free(answer);
  }

  return status;
}

static bool static_tryAskAddresses(const DnsAnswer_t* address_answers, int address_answer_count, const char* query, size_t query_len, int64_t deadline_at, char* answer, size_t* answer_len)
{
  for (int i = 0; i < address_answer_count; i++)
  {
    for (int record = 0; record < address_answers[i].m_recordCount; record++)
    {
      if (monotonic_nowMs() >= deadline_at)
        return false;

      struct sockaddr_storage address = { 0 };
      socklen_t address_len = 0;
      if (!netconnect_tryBuildSockaddr(address_answers[i].mp_texts[record].mp_bytes, WHOIS_PORT, &address, &address_len) ||
          !ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&address, address_len))
        continue;

      int fd = netconnect_connectUntil((const struct sockaddr*)&address, address_len, WHOIS_CONNECT_DEADLINE_MS, deadline_at);
      if (fd < 0)
        continue;

      bool is_answered = static_tryExchange(fd, query, query_len, deadline_at, answer, answer_len);
      close(fd);
      return is_answered;
    }
  }
  return false;
}

static bool static_tryExchange(int fd, const char* query, size_t query_len, int64_t deadline_at, char* answer, size_t* answer_len)
{
  size_t sent_byte_count = 0;
  while (sent_byte_count < query_len)
  {
    if (!netconnect_waitForSocket(fd, POLLOUT, deadline_at))
      return false;
    ssize_t written = send(fd, query + sent_byte_count, query_len - sent_byte_count, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (written < 0 && errno != EAGAIN && errno != EINTR)
      return false;
    if (written > 0)
      sent_byte_count += (size_t)written;
  }

  for (;;)
  {
    if (!netconnect_waitForSocket(fd, POLLIN, deadline_at))
      return false;
    ssize_t read_count = recv(fd, answer + *answer_len, WHOIS_MAX_ANSWER_BYTE_COUNT + 1 - *answer_len, MSG_DONTWAIT);
    if (read_count == 0)
      return true;
    else if (read_count < 0 && errno != EAGAIN && errno != EINTR)
      return false;
    else if (read_count > 0)
      *answer_len += (size_t)read_count;
    if (*answer_len > WHOIS_MAX_ANSWER_BYTE_COUNT)
      return false;
  }
}
