#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "emailauth.h"
#include "bytes.h"

#define EMAILAUTH_SPF_VERSION     "v=spf1"
#define EMAILAUTH_SPF_VERSION_LEN (sizeof(EMAILAUTH_SPF_VERSION) - 1)

#define EMAILAUTH_SPF_MAX_IP4_PREFIX_LENGTH 32
#define EMAILAUTH_SPF_MAX_IP6_PREFIX_LENGTH 128

#define EMAILAUTH_DKIM_MAX_KEY_BASE64_LEN 2048

#define EMAILAUTH_DKIM_MAX_KEY_LEN (EMAILAUTH_DKIM_MAX_KEY_BASE64_LEN / 4 * 3)

#define EMAILAUTH_ED25519_KEY_LEN 32

static const unsigned char EMAILAUTH_RSA_ALGORITHM_DER[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

typedef enum {
  EMAILAUTH_SPF_ARGUMENT_NONE = 0,
  EMAILAUTH_SPF_ARGUMENT_REQUIRED,
  EMAILAUTH_SPF_ARGUMENT_OPTIONAL,
  EMAILAUTH_SPF_ARGUMENT_OPTIONAL_OR_CIDR,
} EmailAuthSpfArgument_t;

typedef struct {
  const char*            mp_name;
  EmailAuthSpfTermKind_t m_kind;
  EmailAuthSpfArgument_t m_argument;
} EmailAuthSpfMechanism_t;

static const EmailAuthSpfMechanism_t EMAILAUTH_SPF_MECHANISMS[] = {
  { "all",     EMAILAUTH_SPF_TERM_ALL,     EMAILAUTH_SPF_ARGUMENT_NONE },
  { "include", EMAILAUTH_SPF_TERM_INCLUDE, EMAILAUTH_SPF_ARGUMENT_REQUIRED },
  { "a",       EMAILAUTH_SPF_TERM_A,       EMAILAUTH_SPF_ARGUMENT_OPTIONAL_OR_CIDR },
  { "mx",      EMAILAUTH_SPF_TERM_MX,      EMAILAUTH_SPF_ARGUMENT_OPTIONAL_OR_CIDR },
  { "ptr",     EMAILAUTH_SPF_TERM_PTR,     EMAILAUTH_SPF_ARGUMENT_OPTIONAL },
  { "ip4",     EMAILAUTH_SPF_TERM_IP4,     EMAILAUTH_SPF_ARGUMENT_REQUIRED },
  { "ip6",     EMAILAUTH_SPF_TERM_IP6,     EMAILAUTH_SPF_ARGUMENT_REQUIRED },
  { "exists",  EMAILAUTH_SPF_TERM_EXISTS,  EMAILAUTH_SPF_ARGUMENT_REQUIRED },
};

static const int EMAILAUTH_SPF_MECHANISM_COUNT = (int)(sizeof(EMAILAUTH_SPF_MECHANISMS) / sizeof(EMAILAUTH_SPF_MECHANISMS[0]));

static const char EMAILAUTH_SPF_MACRO_LETTERS[]    = "slodiphv";
static const char EMAILAUTH_SPF_MACRO_DELIMITERS[] = ".-+,/_=";

typedef struct {
  EmailAuthSpan_t m_name;
  EmailAuthSpan_t m_value;
  bool            m_isWellFormed;
} EmailAuthTag_t;

typedef enum {
  EMAILAUTH_DMARC_TAG_POLICY = 0,
  EMAILAUTH_DMARC_TAG_SUBDOMAIN_POLICY,
  EMAILAUTH_DMARC_TAG_NONEXISTENT_SUBDOMAIN_POLICY,
  EMAILAUTH_DMARC_TAG_PERCENT,
  EMAILAUTH_DMARC_TAG_SPF_ALIGNMENT,
  EMAILAUTH_DMARC_TAG_DKIM_ALIGNMENT,
  EMAILAUTH_DMARC_TAG_TEST_MODE,
  EMAILAUTH_DMARC_TAG_DOMAIN_ROLE,
  EMAILAUTH_DMARC_TAG_FAILURE_OPTIONS,
  EMAILAUTH_DMARC_TAG_AGGREGATE_URIS,
  EMAILAUTH_DMARC_TAG_FAILURE_URIS,
  EMAILAUTH_DMARC_TAG_COUNT,
} EmailAuthDmarcTag_t;

static const char* const EMAILAUTH_DMARC_TAG_NAMES[EMAILAUTH_DMARC_TAG_COUNT] = {
  [EMAILAUTH_DMARC_TAG_POLICY]                       = "p",
  [EMAILAUTH_DMARC_TAG_SUBDOMAIN_POLICY]             = "sp",
  [EMAILAUTH_DMARC_TAG_NONEXISTENT_SUBDOMAIN_POLICY] = "np",
  [EMAILAUTH_DMARC_TAG_PERCENT]                      = "pct",
  [EMAILAUTH_DMARC_TAG_SPF_ALIGNMENT]                = "aspf",
  [EMAILAUTH_DMARC_TAG_DKIM_ALIGNMENT]               = "adkim",
  [EMAILAUTH_DMARC_TAG_TEST_MODE]                    = "t",
  [EMAILAUTH_DMARC_TAG_DOMAIN_ROLE]                  = "psd",
  [EMAILAUTH_DMARC_TAG_FAILURE_OPTIONS]              = "fo",
  [EMAILAUTH_DMARC_TAG_AGGREGATE_URIS]               = "rua",
  [EMAILAUTH_DMARC_TAG_FAILURE_URIS]                 = "ruf",
};

typedef enum {
  EMAILAUTH_DKIM_TAG_VERSION = 0,
  EMAILAUTH_DKIM_TAG_HASH_ALGORITHMS,
  EMAILAUTH_DKIM_TAG_KEY_TYPE,
  EMAILAUTH_DKIM_TAG_PUBLIC_KEY,
  EMAILAUTH_DKIM_TAG_SERVICE_TYPES,
  EMAILAUTH_DKIM_TAG_FLAGS,
  EMAILAUTH_DKIM_TAG_COUNT,
} EmailAuthDkimTag_t;

static const char* const EMAILAUTH_DKIM_TAG_NAMES[EMAILAUTH_DKIM_TAG_COUNT] = {
  [EMAILAUTH_DKIM_TAG_VERSION]         = "v",
  [EMAILAUTH_DKIM_TAG_HASH_ALGORITHMS] = "h",
  [EMAILAUTH_DKIM_TAG_KEY_TYPE]        = "k",
  [EMAILAUTH_DKIM_TAG_PUBLIC_KEY]      = "p",
  [EMAILAUTH_DKIM_TAG_SERVICE_TYPES]   = "s",
  [EMAILAUTH_DKIM_TAG_FLAGS]           = "t",
};

static EmailAuthRecordCount_t static_countRecords (const DnsRecordText_t* texts, int text_count, bool (*is_record_function)(const DnsRecordText_t*), int* first_index_out);

static EmailAuthSpfTerm_t static_readSpfTerm           (const char* term_start, const char* term_end);
static bool               static_isSpfModifierNamed    (const char* term_start, const char* term_end, const char* name);
static EmailAuthSpfTerm_t static_makeInvalidSpfTerm    (const char* term_start, const char* term_end);
static void               static_readSpfModifier       (const char* term_start, const char* name_end, const char* term_end, EmailAuthSpfTerm_t* term_out);
static void               static_readSpfDirective      (const char* term_start, const char* term_end, EmailAuthSpfTerm_t* term_out);
static bool               static_isDnsLookupTerm       (EmailAuthSpfTermKind_t kind);
static bool               static_isSpfArgumentAllowed  (EmailAuthSpfArgument_t argument, const char* rest, const char* term_end);
static bool               static_tryReadSpfValue       (EmailAuthSpfTermKind_t kind, EmailAuthSpan_t value, bool has_colon, int* ip4_prefix_length_out, int* ip6_prefix_length_out);
static bool               static_tryReadSpfIpNetwork   (EmailAuthSpan_t value, int address_family, int max_prefix_length, int* prefix_length_out);
static bool               static_tryCutPrefixLength    (const char* start, const char** end, int slash_count, int max_prefix_length, int* prefix_length_out);
static bool               static_isSpfDomainSpec       (const char* start, const char* end);
static bool               static_isSpfTopLabel         (const char* start, const char* end);
static bool               static_tryReadSpfMacroString (const char* start, const char* end, const char** last_macro_end_out);
static const char*        static_findSpfMacroEnd       (const char* cursor, const char* end);

static bool static_tryReadNextTag  (const char** cursor, const char* end, EmailAuthTag_t* tag_out);
static bool static_tryReadNextItem (const char** cursor, const char* end, char separator, EmailAuthSpan_t* item_out);
static bool static_isTagSpace      (char byte);
static bool static_isVisibleAscii  (char byte);
static void static_trimSpaces      (const char** start, const char** end);
static int  static_findTagIndex    (EmailAuthSpan_t name, const char* const* tag_names, int tag_count, bool is_case_ignored);
static bool static_isSpanEqual     (EmailAuthSpan_t span, const char* text, bool is_case_ignored);

static EmailAuthDmarcPolicy_t     static_readDmarcPolicy        (EmailAuthSpan_t value);
static EmailAuthAlignment_t       static_readAlignment          (EmailAuthSpan_t value);
static EmailAuthDmarcTestMode_t   static_readDmarcTestMode      (EmailAuthSpan_t value);
static EmailAuthDmarcDomainRole_t static_readDmarcDomainRole    (EmailAuthSpan_t value);
static bool                       static_tryReadPercent         (EmailAuthSpan_t value, int* percent_out);
static bool                       static_tryReadFailureOptions  (EmailAuthSpan_t value, unsigned int* failure_options_out);
static int                        static_readReportUris         (EmailAuthSpan_t value, EmailAuthDmarcUri_t* uris_out, int* uri_count, int* skipped_uri_count);
static EmailAuthDmarcUri_t        static_readReportUri          (const char* uri_start, const char* uri_end);
static bool                       static_isReportSizeLimit      (const char* start, const char* end);

static bool                   static_isTagNameListed    (EmailAuthSpan_t name, const EmailAuthSpan_t* tag_names, int tag_name_count);
static bool                   static_hasListItem        (EmailAuthSpan_t value, const char* item);
static EmailAuthDkimKeyType_t static_readDkimKeyType    (EmailAuthSpan_t key_type_name);
static void                   static_readDkimKey        (EmailAuthSpan_t public_key, EmailAuthDkim_t* dkim_out);
static int                    static_decodeBase64Key    (EmailAuthSpan_t public_key, unsigned char* key_out);
static int                    static_readRsaKeyBits     (EmailAuthSpan_t public_key, bool* is_bare_rsa_key_out, bool* is_rsa_modulus_negative_out);
static int                    static_readEd25519KeyBits (EmailAuthSpan_t public_key);
static void                   static_findRsaPublicKey   (const unsigned char** der, long* der_len);
static bool                   static_isRsaModulusNegative (const unsigned char* der, long der_len);

bool emailauth_isSpfRecord(const DnsRecordText_t* text)
{
  assert(text != NULL);

  if (!bytes_hasPrefix(text->mp_bytes, text->m_byteCount, EMAILAUTH_SPF_VERSION, EMAILAUTH_SPF_VERSION_LEN, true))
    return false;

  return text->m_byteCount == EMAILAUTH_SPF_VERSION_LEN || text->mp_bytes[EMAILAUTH_SPF_VERSION_LEN] == ' ';
}

bool emailauth_isDmarcRecord(const DnsRecordText_t* text)
{
  assert(text != NULL);

  const char* cursor = text->mp_bytes;
  EmailAuthTag_t tag = { 0 };
  if (!static_tryReadNextTag(&cursor, text->mp_bytes + text->m_byteCount, &tag))
    return false;

  return static_isSpanEqual(tag.m_name, "v", true) && static_isSpanEqual(tag.m_value, "DMARC1", false);
}

EmailAuthRecordCount_t emailauth_countSpfRecords(const DnsRecordText_t* texts, int text_count, int* first_index_out)
{
  return static_countRecords(texts, text_count, emailauth_isSpfRecord, first_index_out);
}

EmailAuthRecordCount_t emailauth_countDmarcRecords(const DnsRecordText_t* texts, int text_count, int* first_index_out)
{
  return static_countRecords(texts, text_count, emailauth_isDmarcRecord, first_index_out);
}

void emailauth_parseSpf(const DnsRecordText_t* record, EmailAuthSpf_t* spf_out)
{
  assert(record  != NULL);
  assert(spf_out != NULL);
  assert(emailauth_isSpfRecord(record));

  memset(spf_out, 0, sizeof(*spf_out));
  bool        is_redirect_seen = false;
  bool        is_exp_seen      = false;
  const char* cursor           = record->mp_bytes + EMAILAUTH_SPF_VERSION_LEN;
  const char* end              = record->mp_bytes + record->m_byteCount;
  while (cursor < end)
  {
    if (*cursor == ' ')
    {
      cursor++;
      continue;
    }

    const char* term_end = memchr(cursor, ' ', (size_t)(end - cursor));
    if (term_end == NULL)
      term_end = end;

    EmailAuthSpfTerm_t term        = static_readSpfTerm(cursor, term_end);
    bool               is_redirect = static_isSpfModifierNamed(cursor, term_end, "redirect");
    bool               is_exp      = static_isSpfModifierNamed(cursor, term_end, "exp");
    if (is_redirect || is_exp)
    {
      bool* is_modifier_seen = is_redirect ? &is_redirect_seen : &is_exp_seen;
      if (*is_modifier_seen)
        term = static_makeInvalidSpfTerm(cursor, term_end);

      *is_modifier_seen = true;
    }
    cursor = term_end;

    if (term.m_kind == EMAILAUTH_SPF_TERM_INVALID)
      spf_out->m_invalidTermCount++;
    if (static_isDnsLookupTerm(term.m_kind))
      spf_out->m_dnsLookupTermCount++;

    if (spf_out->m_termCount < EMAILAUTH_SPF_MAX_TERM_COUNT)
      spf_out->ma_terms[spf_out->m_termCount++] = term;
    else
      spf_out->m_unreadTermCount++;
  }
}

void emailauth_parseDmarc(const DnsRecordText_t* record, EmailAuthDmarc_t* dmarc_out)
{
  assert(record    != NULL);
  assert(dmarc_out != NULL);
  assert(emailauth_isDmarcRecord(record));

  memset(dmarc_out, 0, sizeof(*dmarc_out));
  dmarc_out->m_isPercentValid        = true;
  dmarc_out->m_percent               = 100;
  dmarc_out->m_isFailureOptionsValid = true;
  dmarc_out->m_failureOptions        = EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL;

  bool           is_tag_seen[EMAILAUTH_DMARC_TAG_COUNT] = { false };
  const char*    cursor = record->mp_bytes;
  const char*    end    = record->mp_bytes + record->m_byteCount;
  EmailAuthTag_t tag    = { 0 };

  (void)static_tryReadNextTag(&cursor, end, &tag);

  while (static_tryReadNextTag(&cursor, end, &tag))
  {
    if (!tag.m_isWellFormed)
    {
      dmarc_out->m_invalidTagCount++;
      continue;
    }

    int tag_index = static_findTagIndex(tag.m_name, EMAILAUTH_DMARC_TAG_NAMES, EMAILAUTH_DMARC_TAG_COUNT, true);
    if (tag_index < 0)
      continue;

    if (is_tag_seen[tag_index])
    {
      dmarc_out->m_repeatedTagCount++;
      continue;
    }
    is_tag_seen[tag_index] = true;

    switch ((EmailAuthDmarcTag_t)tag_index)
    {
      case EMAILAUTH_DMARC_TAG_POLICY:
        dmarc_out->m_policy = static_readDmarcPolicy(tag.m_value);
        break;
      case EMAILAUTH_DMARC_TAG_SUBDOMAIN_POLICY:
        dmarc_out->m_subdomainPolicy = static_readDmarcPolicy(tag.m_value);
        break;
      case EMAILAUTH_DMARC_TAG_NONEXISTENT_SUBDOMAIN_POLICY:
        dmarc_out->m_nonexistentSubdomainPolicy = static_readDmarcPolicy(tag.m_value);
        break;
      case EMAILAUTH_DMARC_TAG_PERCENT:
        dmarc_out->m_isPercentValid = static_tryReadPercent(tag.m_value, &dmarc_out->m_percent);
        break;
      case EMAILAUTH_DMARC_TAG_SPF_ALIGNMENT:
        dmarc_out->m_spfAlignment = static_readAlignment(tag.m_value);
        break;
      case EMAILAUTH_DMARC_TAG_DKIM_ALIGNMENT:
        dmarc_out->m_dkimAlignment = static_readAlignment(tag.m_value);
        break;
      case EMAILAUTH_DMARC_TAG_TEST_MODE:
        dmarc_out->m_testMode = static_readDmarcTestMode(tag.m_value);
        break;
      case EMAILAUTH_DMARC_TAG_DOMAIN_ROLE:
        dmarc_out->m_domainRole = static_readDmarcDomainRole(tag.m_value);
        break;
      case EMAILAUTH_DMARC_TAG_FAILURE_OPTIONS:
        dmarc_out->m_isFailureOptionsValid = static_tryReadFailureOptions(tag.m_value, &dmarc_out->m_failureOptions);
        break;
      case EMAILAUTH_DMARC_TAG_AGGREGATE_URIS:
        dmarc_out->m_validAggregateUriCount = static_readReportUris(tag.m_value, dmarc_out->ma_aggregateUris, &dmarc_out->m_aggregateUriCount, &dmarc_out->m_skippedUriCount);
        break;
      case EMAILAUTH_DMARC_TAG_FAILURE_URIS:
        (void)static_readReportUris(tag.m_value, dmarc_out->ma_failureUris, &dmarc_out->m_failureUriCount, &dmarc_out->m_skippedUriCount);
        break;
      case EMAILAUTH_DMARC_TAG_COUNT:
        break;
    }
  }
}

void emailauth_parseDkim(const DnsRecordText_t* record, EmailAuthDkim_t* dkim_out)
{
  assert(record   != NULL);
  assert(dkim_out != NULL);

  memset(dkim_out, 0, sizeof(*dkim_out));
  dkim_out->m_keyState              = EMAILAUTH_DKIM_KEY_ABSENT;
  dkim_out->m_keyTypeName           = (EmailAuthSpan_t){ "rsa", strlen("rsa") };
  dkim_out->m_isSha256Allowed       = true;
  dkim_out->m_isEmailServiceAllowed = true;

  EmailAuthSpan_t seen_tag_names[EMAILAUTH_DKIM_MAX_TAG_COUNT];
  int             seen_tag_name_count = 0;
  bool            is_malformed        = false;
  bool            is_version_first    = false;
  bool            has_public_key      = false;
  int             tag_position        = 0;
  EmailAuthSpan_t public_key          = { 0 };
  const char*     cursor              = record->mp_bytes;
  const char*     end                 = record->mp_bytes + record->m_byteCount;
  EmailAuthTag_t  tag                 = { 0 };
  while (static_tryReadNextTag(&cursor, end, &tag))
  {
    tag_position++;
    if (!tag.m_isWellFormed)
    {
      is_malformed = true;
      continue;
    }

    if (tag_position > EMAILAUTH_DKIM_MAX_TAG_COUNT)
      is_malformed = true;
    else if (static_isTagNameListed(tag.m_name, seen_tag_names, seen_tag_name_count))
    {
      is_malformed = true;
      continue;
    }
    else
      seen_tag_names[seen_tag_name_count++] = tag.m_name;

    int tag_index = static_findTagIndex(tag.m_name, EMAILAUTH_DKIM_TAG_NAMES, EMAILAUTH_DKIM_TAG_COUNT, false);
    if (tag_index < 0)
      continue;

    switch ((EmailAuthDkimTag_t)tag_index)
    {
      case EMAILAUTH_DKIM_TAG_VERSION:
      {
        bool is_version_dkim1 = static_isSpanEqual(tag.m_value, "DKIM1", false);
        if (tag_position == 1 && !is_version_dkim1)
          return;
        else if (tag_position == 1)
          is_version_first = true;
        else if (is_version_dkim1)
          dkim_out->m_isVersionMisplaced = true;
        else
          is_malformed = true;
        break;
      }
      case EMAILAUTH_DKIM_TAG_HASH_ALGORITHMS:
        if (tag.m_value.m_byteCount == 0)
          is_malformed = true;
        dkim_out->m_isSha256Allowed = static_hasListItem(tag.m_value, "sha256");
        break;
      case EMAILAUTH_DKIM_TAG_KEY_TYPE:
        dkim_out->m_keyTypeName = tag.m_value;
        break;
      case EMAILAUTH_DKIM_TAG_PUBLIC_KEY:
        has_public_key = true;
        public_key     = tag.m_value;
        break;
      case EMAILAUTH_DKIM_TAG_SERVICE_TYPES:
        if (tag.m_value.m_byteCount == 0)
          is_malformed = true;
        dkim_out->m_isEmailServiceAllowed = static_hasListItem(tag.m_value, "email") || static_hasListItem(tag.m_value, "*");
        break;
      case EMAILAUTH_DKIM_TAG_FLAGS:
        dkim_out->m_isTestMode = static_hasListItem(tag.m_value, "y");
        break;
      case EMAILAUTH_DKIM_TAG_COUNT:
        break;
    }
  }

  dkim_out->m_keyType = static_readDkimKeyType(dkim_out->m_keyTypeName);
  if (!has_public_key && !is_version_first)
    return;

  if (is_malformed || !has_public_key)
  {
    dkim_out->m_keyState = EMAILAUTH_DKIM_KEY_UNREADABLE;
    return;
  }

  static_readDkimKey(public_key, dkim_out);
}

static EmailAuthRecordCount_t static_countRecords(const DnsRecordText_t* texts, int text_count, bool (*is_record_function)(const DnsRecordText_t*), int* first_index_out)
{
  assert(texts != NULL || text_count == 0);
  assert(first_index_out != NULL);

  int found_count = 0;
  for (int i = 0; i < text_count; i++)
  {
    if (!is_record_function(&texts[i]))
      continue;
    if (found_count == 0)
      *first_index_out = i;

    found_count++;
  }

  if (found_count == 0)
    return EMAILAUTH_RECORD_NONE;
  else if (found_count == 1)
    return EMAILAUTH_RECORD_ONE;
  return EMAILAUTH_RECORD_MANY;
}

static EmailAuthSpfTerm_t static_readSpfTerm(const char* term_start, const char* term_end)
{
  EmailAuthSpfTerm_t term = static_makeInvalidSpfTerm(term_start, term_end);

  const char* name_end = term_start;
  while (name_end < term_end && (isalnum((unsigned char)*name_end) || *name_end == '-' || *name_end == '_' || *name_end == '.'))
    name_end++;

  if (name_end < term_end && *name_end == '=' && isalpha((unsigned char)*term_start))
    static_readSpfModifier(term_start, name_end, term_end, &term);
  else
    static_readSpfDirective(term_start, term_end, &term);

  return term;
}

static bool static_isSpfModifierNamed(const char* term_start, const char* term_end, const char* name)
{
  assert(term_start <= term_end);
  assert(name != NULL);

  size_t name_len = strlen(name);
  return (size_t)(term_end - term_start) > name_len && term_start[name_len] == '=' && strncasecmp(term_start, name, name_len) == 0;
}

static EmailAuthSpfTerm_t static_makeInvalidSpfTerm(const char* term_start, const char* term_end)
{
  EmailAuthSpfTerm_t term = { 0 };
  term.m_kind            = EMAILAUTH_SPF_TERM_INVALID;
  term.m_value           = (EmailAuthSpan_t){ term_start, (size_t)(term_end - term_start) };
  term.m_ip4PrefixLength = -1;
  term.m_ip6PrefixLength = -1;
  return term;
}

static void static_readSpfModifier(const char* term_start, const char* name_end, const char* term_end, EmailAuthSpfTerm_t* term_out)
{
  assert(name_end < term_end && *name_end == '=');
  assert(term_out != NULL);

  EmailAuthSpan_t        name  = { term_start, (size_t)(name_end - term_start) };
  EmailAuthSpan_t        value = { name_end + 1, (size_t)(term_end - name_end - 1) };
  EmailAuthSpfTermKind_t kind  = EMAILAUTH_SPF_TERM_UNKNOWN_MODIFIER;

  if (static_isSpanEqual(name, "redirect", true))
    kind = EMAILAUTH_SPF_TERM_REDIRECT;
  else if (static_isSpanEqual(name, "exp", true))
    kind = EMAILAUTH_SPF_TERM_EXP;

  const char* last_macro_end   = NULL;
  bool is_value_allowed = kind == EMAILAUTH_SPF_TERM_UNKNOWN_MODIFIER ? static_tryReadSpfMacroString(value.mp_bytes, term_end, &last_macro_end)
                                                                      : static_isSpfDomainSpec(value.mp_bytes, term_end);
  if (!is_value_allowed)
    return;

  term_out->m_kind  = kind;
  term_out->m_value = value;
}

static void static_readSpfDirective(const char* term_start, const char* term_end, EmailAuthSpfTerm_t* term_out)
{
  assert(term_start < term_end);
  assert(term_out != NULL);

  EmailAuthQualifier_t qualifier  = EMAILAUTH_QUALIFIER_PASS;
  const char*          name_start = term_start + 1;
  if (*term_start == '-')
    qualifier = EMAILAUTH_QUALIFIER_FAIL;
  else if (*term_start == '~')
    qualifier = EMAILAUTH_QUALIFIER_SOFTFAIL;
  else if (*term_start == '?')
    qualifier = EMAILAUTH_QUALIFIER_NEUTRAL;
  else if (*term_start != '+')
    name_start = term_start;

  const char* name_end = name_start;
  while (name_end < term_end && isalnum((unsigned char)*name_end))
    name_end++;

  EmailAuthSpan_t name = { name_start, (size_t)(name_end - name_start) };
  for (int i = 0; i < EMAILAUTH_SPF_MECHANISM_COUNT; i++)
  {
    const EmailAuthSpfMechanism_t* mechanism = &EMAILAUTH_SPF_MECHANISMS[i];
    if (!static_isSpanEqual(name, mechanism->mp_name, true))
      continue;
    if (!static_isSpfArgumentAllowed(mechanism->m_argument, name_end, term_end))
      return;

    bool            has_colon         = name_end < term_end && *name_end == ':';
    const char*     value_start       = has_colon ? name_end + 1 : name_end;
    EmailAuthSpan_t value             = { value_start, (size_t)(term_end - value_start) };
    int             ip4_prefix_length = -1;
    int             ip6_prefix_length = -1;
    if (!static_tryReadSpfValue(mechanism->m_kind, value, has_colon, &ip4_prefix_length, &ip6_prefix_length))
      return;

    term_out->m_kind            = mechanism->m_kind;
    term_out->m_qualifier       = qualifier;
    term_out->m_value           = value;
    term_out->m_ip4PrefixLength = ip4_prefix_length;
    term_out->m_ip6PrefixLength = ip6_prefix_length;
    return;
  }
}

static bool static_isSpfArgumentAllowed(EmailAuthSpfArgument_t argument, const char* rest, const char* term_end)
{
  bool is_empty      = rest == term_end;
  bool has_value     = !is_empty && *rest == ':' && term_end - rest > 1;
  bool has_cidr_only = !is_empty && *rest == '/';

  switch (argument)
  {
    case EMAILAUTH_SPF_ARGUMENT_NONE:
      return is_empty;
    case EMAILAUTH_SPF_ARGUMENT_REQUIRED:
      return has_value;
    case EMAILAUTH_SPF_ARGUMENT_OPTIONAL:
      return is_empty || has_value;
    case EMAILAUTH_SPF_ARGUMENT_OPTIONAL_OR_CIDR:
      return is_empty || has_value || has_cidr_only;
  }
  return false;
}

static bool static_tryReadSpfValue(EmailAuthSpfTermKind_t kind, EmailAuthSpan_t value, bool has_colon, int* ip4_prefix_length_out, int* ip6_prefix_length_out)
{
  const char* value_end = value.mp_bytes + value.m_byteCount;
  switch (kind)
  {
    case EMAILAUTH_SPF_TERM_IP4:
      return static_tryReadSpfIpNetwork(value, AF_INET, EMAILAUTH_SPF_MAX_IP4_PREFIX_LENGTH, ip4_prefix_length_out);
    case EMAILAUTH_SPF_TERM_IP6:
      return static_tryReadSpfIpNetwork(value, AF_INET6, EMAILAUTH_SPF_MAX_IP6_PREFIX_LENGTH, ip6_prefix_length_out);
    case EMAILAUTH_SPF_TERM_A:
    case EMAILAUTH_SPF_TERM_MX:
      if (!static_tryCutPrefixLength(value.mp_bytes, &value_end, 2, EMAILAUTH_SPF_MAX_IP6_PREFIX_LENGTH, ip6_prefix_length_out) ||
          !static_tryCutPrefixLength(value.mp_bytes, &value_end, 1, EMAILAUTH_SPF_MAX_IP4_PREFIX_LENGTH, ip4_prefix_length_out))
      {
        return false;
      }
      return has_colon ? static_isSpfDomainSpec(value.mp_bytes, value_end) : value_end == value.mp_bytes;
    case EMAILAUTH_SPF_TERM_ALL:
    case EMAILAUTH_SPF_TERM_INCLUDE:
    case EMAILAUTH_SPF_TERM_PTR:
    case EMAILAUTH_SPF_TERM_EXISTS:
      return !has_colon || static_isSpfDomainSpec(value.mp_bytes, value_end);
    case EMAILAUTH_SPF_TERM_REDIRECT:
    case EMAILAUTH_SPF_TERM_EXP:
    case EMAILAUTH_SPF_TERM_UNKNOWN_MODIFIER:
    case EMAILAUTH_SPF_TERM_INVALID:
      break;
  }
  return false;
}

static bool static_tryReadSpfIpNetwork(EmailAuthSpan_t value, int address_family, int max_prefix_length, int* prefix_length_out)
{
  const char* address_end = value.mp_bytes + value.m_byteCount;
  if (!static_tryCutPrefixLength(value.mp_bytes, &address_end, 1, max_prefix_length, prefix_length_out))
    return false;

  char   address_text[INET6_ADDRSTRLEN];
  size_t address_len = (size_t)(address_end - value.mp_bytes);
  if (address_len >= sizeof(address_text) || memchr(value.mp_bytes, '\0', address_len) != NULL)
    return false;

  memcpy(address_text, value.mp_bytes, address_len);
  address_text[address_len] = '\0';

  unsigned char address[sizeof(struct in6_addr)];
  return inet_pton(address_family, address_text, address) == 1;
}

static bool static_tryCutPrefixLength(const char* start, const char** end, int slash_count, int max_prefix_length, int* prefix_length_out)
{
  const char* digits = *end;
  while (digits > start && isdigit((unsigned char)digits[-1]))
    digits--;
  if (digits - start < slash_count)
    return true;
  for (int i = 1; i <= slash_count; i++)
    if (digits[-i] != '/')
      return true;

  if (digits == *end || (*digits == '0' && *end - digits > 1))
    return false;

  int prefix_length = 0;
  for (const char* digit = digits; digit < *end; digit++)
  {
    prefix_length = prefix_length * 10 + (*digit - '0');
    if (prefix_length > max_prefix_length)
      return false;
  }

  *prefix_length_out = prefix_length;
  *end               = digits - slash_count;
  return true;
}

static bool static_isSpfDomainSpec(const char* start, const char* end)
{
  const char* last_macro_end = NULL;
  if (!static_tryReadSpfMacroString(start, end, &last_macro_end))
    return false;
  if (last_macro_end == end)
    return true;

  if (end > start && end[-1] == '.')
    end--;
  const char* top_label_start = end;
  while (top_label_start > start && top_label_start[-1] != '.')
    top_label_start--;
  if (top_label_start == start)
    return false;

  return static_isSpfTopLabel(top_label_start, end);
}

static bool static_isSpfTopLabel(const char* start, const char* end)
{
  if (start == end || !isalnum((unsigned char)start[0]) || !isalnum((unsigned char)end[-1]))
    return false;

  bool has_letter_or_hyphen = false;
  for (const char* byte = start; byte < end; byte++)
  {
    if (!isalnum((unsigned char)*byte) && *byte != '-')
      return false;
    if (isalpha((unsigned char)*byte) || *byte == '-')
      has_letter_or_hyphen = true;
  }
  return has_letter_or_hyphen;
}

static bool static_tryReadSpfMacroString(const char* start, const char* end, const char** last_macro_end_out)
{
  *last_macro_end_out = NULL;
  const char* cursor = start;
  while (cursor < end)
  {
    if (*cursor != '%')
    {
      if (!static_isVisibleAscii(*cursor))
        return false;
      cursor++;
      continue;
    }

    if (end - cursor < 2)
      return false;
    else if (cursor[1] == '%' || cursor[1] == '_' || cursor[1] == '-')
      cursor += 2;
    else if (cursor[1] == '{')
      cursor = static_findSpfMacroEnd(cursor + 2, end);
    else
      return false;

    if (cursor == NULL)
      return false;
    *last_macro_end_out = cursor;
  }
  return true;
}

static const char* static_findSpfMacroEnd(const char* cursor, const char* end)
{
  if (cursor == end || memchr(EMAILAUTH_SPF_MACRO_LETTERS, tolower((unsigned char)*cursor), sizeof(EMAILAUTH_SPF_MACRO_LETTERS) - 1) == NULL)
    return NULL;
  cursor++;

  bool has_digit         = false;
  bool has_nonzero_digit = false;
  while (cursor < end && isdigit((unsigned char)*cursor))
  {
    has_digit = true;
    if (*cursor != '0')
      has_nonzero_digit = true;
    cursor++;
  }
  if (has_digit && !has_nonzero_digit)
    return NULL;
  if (cursor < end && tolower((unsigned char)*cursor) == 'r')
    cursor++;
  while (cursor < end && memchr(EMAILAUTH_SPF_MACRO_DELIMITERS, *cursor, sizeof(EMAILAUTH_SPF_MACRO_DELIMITERS) - 1) != NULL)
    cursor++;

  if (cursor == end || *cursor != '}')
    return NULL;
  return cursor + 1;
}

static bool static_isDnsLookupTerm(EmailAuthSpfTermKind_t kind)
{
  return  kind == EMAILAUTH_SPF_TERM_INCLUDE  ||
          kind == EMAILAUTH_SPF_TERM_A        ||
          kind == EMAILAUTH_SPF_TERM_MX       ||
          kind == EMAILAUTH_SPF_TERM_PTR      ||
          kind == EMAILAUTH_SPF_TERM_EXISTS   ||
          kind == EMAILAUTH_SPF_TERM_REDIRECT;
}

static bool static_tryReadNextTag(const char** cursor, const char* end, EmailAuthTag_t* tag_out)
{
  EmailAuthSpan_t tag_text = { 0 };
  if (!static_tryReadNextItem(cursor, end, ';', &tag_text))
    return false;

  const char* tag_start = tag_text.mp_bytes;
  const char* tag_end   = tag_text.mp_bytes + tag_text.m_byteCount;
  tag_out->m_isWellFormed = false;
  tag_out->m_name         = tag_text;
  tag_out->m_value        = (EmailAuthSpan_t){ tag_end, 0 };

  const char* equal_sign = memchr(tag_start, '=', (size_t)(tag_end - tag_start));
  if (equal_sign == NULL)
    return true;

  const char* name_start  = tag_start;
  const char* name_end    = equal_sign;
  const char* value_start = equal_sign + 1;
  const char* value_end   = tag_end;
  static_trimSpaces(&name_start, &name_end);
  static_trimSpaces(&value_start, &value_end);
  if (!isalpha((unsigned char)*name_start))
    return true;
  for (const char* byte = name_start; byte < name_end; byte++)
    if (!isalnum((unsigned char)*byte) && *byte != '_')
      return true;

  tag_out->m_isWellFormed = true;
  tag_out->m_name         = (EmailAuthSpan_t){ name_start, (size_t)(name_end - name_start) };
  tag_out->m_value        = (EmailAuthSpan_t){ value_start, (size_t)(value_end - value_start) };
  return true;
}

static bool static_tryReadNextItem(const char** cursor, const char* end, char separator, EmailAuthSpan_t* item_out)
{
  assert(cursor != NULL);
  assert(item_out != NULL);

  while (*cursor < end)
  {
    const char* item_start = *cursor;
    const char* item_end   = memchr(item_start, separator, (size_t)(end - item_start));
    if (item_end == NULL)
      item_end = end;
    *cursor = item_end < end ? item_end + 1 : end;

    static_trimSpaces(&item_start, &item_end);
    if (item_start == item_end)
      continue;

    *item_out = (EmailAuthSpan_t){ item_start, (size_t)(item_end - item_start) };
    return true;
  }

  return false;
}

static bool static_isTagSpace(char byte)
{
  return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n';
}

static bool static_isVisibleAscii(char byte)
{
  return (unsigned char)byte >= 0x21 && (unsigned char)byte <= 0x7e;
}

static void static_trimSpaces(const char** start, const char** end)
{
  while (*start < *end && static_isTagSpace(**start))
    (*start)++;
  while (*end > *start && static_isTagSpace((*end)[-1]))
    (*end)--;
}

static int static_findTagIndex(EmailAuthSpan_t name, const char* const* tag_names, int tag_count, bool is_case_ignored)
{
  for (int i = 0; i < tag_count; i++)
    if (static_isSpanEqual(name, tag_names[i], is_case_ignored))
      return i;

  return -1;
}

static bool static_isSpanEqual(EmailAuthSpan_t span, const char* text, bool is_case_ignored)
{
  return bytes_isEqual(span.mp_bytes, span.m_byteCount, text, is_case_ignored);
}

static EmailAuthDmarcPolicy_t static_readDmarcPolicy(EmailAuthSpan_t value)
{
  if (static_isSpanEqual(value, "none", true))
    return EMAILAUTH_DMARC_POLICY_NONE;
  else if (static_isSpanEqual(value, "quarantine", true))
    return EMAILAUTH_DMARC_POLICY_QUARANTINE;
  else if (static_isSpanEqual(value, "reject", true))
    return EMAILAUTH_DMARC_POLICY_REJECT;

  return EMAILAUTH_DMARC_POLICY_INVALID;
}

static EmailAuthAlignment_t static_readAlignment(EmailAuthSpan_t value)
{
  if (static_isSpanEqual(value, "r", true))
    return EMAILAUTH_ALIGNMENT_RELAXED;
  else if (static_isSpanEqual(value, "s", true))
    return EMAILAUTH_ALIGNMENT_STRICT;

  return EMAILAUTH_ALIGNMENT_INVALID;
}

static EmailAuthDmarcTestMode_t static_readDmarcTestMode(EmailAuthSpan_t value)
{
  if (static_isSpanEqual(value, "y", true))
    return EMAILAUTH_DMARC_TEST_MODE_ON;
  else if (static_isSpanEqual(value, "n", true))
    return EMAILAUTH_DMARC_TEST_MODE_OFF;

  return EMAILAUTH_DMARC_TEST_MODE_INVALID;
}

static EmailAuthDmarcDomainRole_t static_readDmarcDomainRole(EmailAuthSpan_t value)
{
  if (static_isSpanEqual(value, "y", true))
    return EMAILAUTH_DMARC_DOMAIN_ROLE_PUBLIC_SUFFIX;
  else if (static_isSpanEqual(value, "n", true))
    return EMAILAUTH_DMARC_DOMAIN_ROLE_ORGANIZATIONAL;
  else if (static_isSpanEqual(value, "u", true))
    return EMAILAUTH_DMARC_DOMAIN_ROLE_NOT_PUBLIC_SUFFIX;

  return EMAILAUTH_DMARC_DOMAIN_ROLE_INVALID;
}

static bool static_tryReadPercent(EmailAuthSpan_t value, int* percent_out)
{
  if (value.m_byteCount == 0 || value.m_byteCount > 3)
    return false;

  int percent = 0;
  for (size_t i = 0; i < value.m_byteCount; i++)
  {
    if (!isdigit((unsigned char)value.mp_bytes[i]))
      return false;
    percent = percent * 10 + (value.mp_bytes[i] - '0');
  }
  if (percent > 100)
    return false;

  *percent_out = percent;
  return true;
}

static bool static_tryReadFailureOptions(EmailAuthSpan_t value, unsigned int* failure_options_out)
{
  unsigned int failure_options = 0;
  for (size_t i = 0; i < value.m_byteCount; i += 2)
  {
    unsigned int option = 0;
    switch (tolower((unsigned char)value.mp_bytes[i]))
    {
      case '0':
        option = EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL;
        break;
      case '1':
        option = EMAILAUTH_DMARC_FAILURE_OPTION_ANY_FAIL;
        break;
      case 'd':
        option = EMAILAUTH_DMARC_FAILURE_OPTION_DKIM_FAIL;
        break;
      case 's':
        option = EMAILAUTH_DMARC_FAILURE_OPTION_SPF_FAIL;
        break;
      default:
        return false;
    }
    if ((failure_options & option) != 0)
      return false;
    failure_options |= option;

    if (i + 1 < value.m_byteCount && (value.mp_bytes[i + 1] != ':' || i + 2 == value.m_byteCount))
      return false;
  }

  if (failure_options == 0)
    return false;
  if ((failure_options & EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL) != 0 && (failure_options & EMAILAUTH_DMARC_FAILURE_OPTION_ANY_FAIL) != 0)
    return false;

  *failure_options_out = failure_options;
  return true;
}

static int static_readReportUris(EmailAuthSpan_t value, EmailAuthDmarcUri_t* uris_out, int* uri_count, int* skipped_uri_count)
{
  int             valid_uri_count = 0;
  const char*     cursor          = value.mp_bytes;
  const char*     end             = value.mp_bytes + value.m_byteCount;
  EmailAuthSpan_t uri_text        = { 0 };
  while (static_tryReadNextItem(&cursor, end, ',', &uri_text))
  {
    EmailAuthDmarcUri_t uri = static_readReportUri(uri_text.mp_bytes, uri_text.mp_bytes + uri_text.m_byteCount);
    if (uri.m_kind != EMAILAUTH_DMARC_URI_INVALID)
      valid_uri_count++;

    if (*uri_count < EMAILAUTH_DMARC_MAX_URI_COUNT)
      uris_out[(*uri_count)++] = uri;
    else
      (*skipped_uri_count)++;
  }
  return valid_uri_count;
}

static EmailAuthDmarcUri_t static_readReportUri(const char* uri_start, const char* uri_end)
{
  EmailAuthDmarcUri_t uri = { { uri_start, (size_t)(uri_end - uri_start) }, EMAILAUTH_DMARC_URI_INVALID, false };

  const char* size_start  = memchr(uri_start, '!', (size_t)(uri_end - uri_start));
  const char* address_end = size_start != NULL ? size_start : uri_end;
  if (size_start != NULL && !static_isReportSizeLimit(size_start + 1, uri_end))
    return uri;

  const char* colon = memchr(uri_start, ':', (size_t)(address_end - uri_start));
  if (colon == NULL || colon + 1 == address_end || !isalpha((unsigned char)*uri_start))
    return uri;
  for (const char* byte = uri_start; byte < colon; byte++)
    if (!isalnum((unsigned char)*byte) && *byte != '+' && *byte != '-' && *byte != '.')
      return uri;
  for (const char* byte = colon + 1; byte < address_end; byte++)
    if (!static_isVisibleAscii(*byte))
      return uri;

  EmailAuthSpan_t scheme = { uri_start, (size_t)(colon - uri_start) };
  if (static_isSpanEqual(scheme, "mailto", true))
  {
    const char* at_sign = memchr(colon + 1, '@', (size_t)(address_end - colon - 1));
    if (at_sign == NULL || at_sign == colon + 1 || at_sign + 1 == address_end)
      return uri;
    uri.m_kind = EMAILAUTH_DMARC_URI_MAILTO;
  }
  else
    uri.m_kind = EMAILAUTH_DMARC_URI_OTHER_SCHEME;

  uri.m_uri          = (EmailAuthSpan_t){ uri_start, (size_t)(address_end - uri_start) };
  uri.m_hasSizeLimit = size_start != NULL;
  return uri;
}

static bool static_isReportSizeLimit(const char* start, const char* end)
{
  static const char units[] = "kmgtKMGT";

  const char* cursor = start;
  while (cursor < end && isdigit((unsigned char)*cursor))
    cursor++;
  if (cursor == start)
    return false;

  if (cursor < end && memchr(units, *cursor, sizeof(units) - 1) != NULL)
    cursor++;
  return cursor == end;
}

static bool static_isTagNameListed(EmailAuthSpan_t name, const EmailAuthSpan_t* tag_names, int tag_name_count)
{
  for (int i = 0; i < tag_name_count; i++)
    if (tag_names[i].m_byteCount == name.m_byteCount && memcmp(tag_names[i].mp_bytes, name.mp_bytes, name.m_byteCount) == 0)
      return true;

  return false;
}

static bool static_hasListItem(EmailAuthSpan_t value, const char* item)
{
  const char*     cursor    = value.mp_bytes;
  const char*     end       = value.mp_bytes + value.m_byteCount;
  EmailAuthSpan_t list_item = { 0 };
  while (static_tryReadNextItem(&cursor, end, ':', &list_item))
    if (static_isSpanEqual(list_item, item, false))
      return true;
  return false;
}

static EmailAuthDkimKeyType_t static_readDkimKeyType(EmailAuthSpan_t key_type_name)
{
  if (static_isSpanEqual(key_type_name, "rsa", false))
    return EMAILAUTH_DKIM_KEY_TYPE_RSA;
  else if (static_isSpanEqual(key_type_name, "ed25519", false))
    return EMAILAUTH_DKIM_KEY_TYPE_ED25519;

  return EMAILAUTH_DKIM_KEY_TYPE_OTHER;
}

static void static_readDkimKey(EmailAuthSpan_t public_key, EmailAuthDkim_t* dkim_out)
{
  assert(dkim_out != NULL);

  if (public_key.m_byteCount == 0)
  {
    dkim_out->m_keyState = EMAILAUTH_DKIM_KEY_REVOKED;
    return;
  }

  bool is_bare_rsa_key         = false;
  bool is_rsa_modulus_negative = false;
  switch (dkim_out->m_keyType)
  {
    case EMAILAUTH_DKIM_KEY_TYPE_RSA:
      dkim_out->m_keyBits = static_readRsaKeyBits(public_key, &is_bare_rsa_key, &is_rsa_modulus_negative);
      break;
    case EMAILAUTH_DKIM_KEY_TYPE_ED25519:
      dkim_out->m_keyBits = static_readEd25519KeyBits(public_key);
      break;
    case EMAILAUTH_DKIM_KEY_TYPE_OTHER:
      dkim_out->m_keyState = EMAILAUTH_DKIM_KEY_UNKNOWN_TYPE;
      return;
  }

  if (dkim_out->m_keyBits == 0)
  {
    dkim_out->m_keyState = EMAILAUTH_DKIM_KEY_UNREADABLE;
    return;
  }

  dkim_out->m_isBareRsaKey         = is_bare_rsa_key;
  dkim_out->m_isRsaModulusNegative = is_rsa_modulus_negative;
  dkim_out->m_keyState             = EMAILAUTH_DKIM_KEY_PRESENT;
}

static int static_decodeBase64Key(EmailAuthSpan_t public_key, unsigned char* key_out)
{
  assert(key_out != NULL);

  char   base64_text[EMAILAUTH_DKIM_MAX_KEY_BASE64_LEN] = "";
  size_t base64_len = 0;
  for (size_t i = 0; i < public_key.m_byteCount; i++)
  {
    char byte = public_key.mp_bytes[i];
    if (static_isTagSpace(byte))
      continue;
    if (base64_len == EMAILAUTH_DKIM_MAX_KEY_BASE64_LEN)
      return -1;
    if (!isalnum((unsigned char)byte) && byte != '+' && byte != '/' && byte != '=')
      return -1;

    base64_text[base64_len++] = byte;
  }

  size_t padding_len = 0;
  while (padding_len < 2 && padding_len < base64_len && base64_text[base64_len - 1 - padding_len] == '=')
    padding_len++;
  if (memchr(base64_text, '=', base64_len - padding_len) != NULL)
    return -1;

  int key_len = EVP_DecodeBlock(key_out, (const unsigned char*)base64_text, (int)base64_len);
  if (key_len < 0)
    return -1;
  return key_len - (int)padding_len;
}

static int static_readRsaKeyBits(EmailAuthSpan_t public_key, bool* is_bare_rsa_key_out, bool* is_rsa_modulus_negative_out)
{
  unsigned char der[EMAILAUTH_DKIM_MAX_KEY_LEN];
  int           der_len = static_decodeBase64Key(public_key, der);
  if (der_len < 0)
    return 0;

  ERR_set_mark();

  const unsigned char* rsa_key_der     = der;
  long                 rsa_key_der_len = der_len;
  static_findRsaPublicKey(&rsa_key_der, &rsa_key_der_len);
  *is_bare_rsa_key_out         = rsa_key_der == der;
  *is_rsa_modulus_negative_out = static_isRsaModulusNegative(rsa_key_der, rsa_key_der_len);

  EVP_PKEY* key = d2i_PublicKey(EVP_PKEY_RSA, NULL, &rsa_key_der, rsa_key_der_len);
  int key_bits  = key != NULL ? EVP_PKEY_get_bits(key) : 0;

  EVP_PKEY_free(key);
  ERR_pop_to_mark();
  return key_bits;
}

static int static_readEd25519KeyBits(EmailAuthSpan_t public_key)
{
  unsigned char key[EMAILAUTH_DKIM_MAX_KEY_LEN];
  if (static_decodeBase64Key(public_key, key) != EMAILAUTH_ED25519_KEY_LEN)
    return 0;

  return EMAILAUTH_ED25519_KEY_LEN * 8;
}

static void static_findRsaPublicKey(const unsigned char** der, long* der_len)
{
  const unsigned char* cursor    = *der;
  long                 length    = 0;
  int                  tag       = 0;
  int                  tag_class = 0;
  if (ASN1_get_object(&cursor, &length, &tag, &tag_class, *der_len) != V_ASN1_CONSTRUCTED ||
      tag != V_ASN1_SEQUENCE                                                              ||
      tag_class != V_ASN1_UNIVERSAL)
  {
    return;
  }
  if (length < (long)sizeof(EMAILAUTH_RSA_ALGORITHM_DER)                                    ||
      memcmp(cursor, EMAILAUTH_RSA_ALGORITHM_DER, sizeof(EMAILAUTH_RSA_ALGORITHM_DER)) != 0)
  {
    return;
  }

  const unsigned char* end = cursor + length;
  cursor += sizeof(EMAILAUTH_RSA_ALGORITHM_DER);
  if (ASN1_get_object(&cursor, &length, &tag, &tag_class, end - cursor) != 0 || tag != V_ASN1_BIT_STRING || tag_class != V_ASN1_UNIVERSAL)
    return;
  if (cursor + length != end || length < 1 || cursor[0] != 0)
    return;

  *der     = cursor + 1;
  *der_len = length - 1;
}

static bool static_isRsaModulusNegative(const unsigned char* der, long der_len)
{
  const unsigned char* cursor    = der;
  long                 length    = 0;
  int                  tag       = 0;
  int                  tag_class = 0;
  if (ASN1_get_object(&cursor, &length, &tag, &tag_class, der_len) != V_ASN1_CONSTRUCTED ||
      tag != V_ASN1_SEQUENCE                                                             ||
      tag_class != V_ASN1_UNIVERSAL)
  {
    return false;
  }

  const unsigned char* end = cursor + length;
  if (ASN1_get_object(&cursor, &length, &tag, &tag_class, end - cursor) != 0 || tag != V_ASN1_INTEGER || tag_class != V_ASN1_UNIVERSAL)
    return false;

  return length > 0 && (cursor[0] & 0x80) != 0;
}
