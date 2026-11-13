#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "validate.h"
#include "ipguard.h"
#include "watchlist/watchlist.h"
#include "cve.h"
#include "attack.h"
#include "keyvault.h"

#define DATE_MIN_YEAR  1

#define SEARCH_QUERY_MIN_LEN  3

bool validate_searchString(const char* search_string)
{
  for (; *search_string; search_string++)
    if (*search_string == '%')
      return false;
  return true;
}

bool validate_searchQuery(const char* search_query)
{
  if (strlen(search_query) < SEARCH_QUERY_MIN_LEN)
    return false;

  for (; *search_query; search_query++)
    if (*search_query != ' ')
      return true;
  return false;
}

bool validate_date(const char* date_str)
{
  if (strlen(date_str) != 10)
    return false;

  for (int i = 0; i < 10; i++)
  {
    if (i == 4 || i == 7)
    {
      if (date_str[i] != '-')
        return false;
    }
    else
    {
      if (date_str[i] < '0' || date_str[i] > '9')
        return false;
    }
  }

  int year  = (date_str[0] - '0') * 1000 + (date_str[1] - '0') * 100 + (date_str[2] - '0') * 10 + (date_str[3] - '0');
  int month = (date_str[5] - '0') * 10 + (date_str[6] - '0');
  int day   = (date_str[8] - '0') * 10 + (date_str[9] - '0');

  if (year < DATE_MIN_YEAR || month < 1 || month > 12 || day < 1)
    return false;

  static const int days_in_month[13] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  bool is_leap_year = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
  int  month_length = (month == 2 && is_leap_year) ? days_in_month[month] + 1 : days_in_month[month];

  return day <= month_length;
}

bool validate_cveId(const char* cve_id)
{
  if (!cve_id || *cve_id == '\0' || strncmp(cve_id, "CVE-", CVELOOKUP_ID_TAG_LEN) != 0)
    return false;

  const char* cursor = cve_id + CVELOOKUP_ID_TAG_LEN;
  for (int i = 0; i < CVELOOKUP_ID_YEAR_DIGITS; i++, cursor++)
    if (!isdigit((unsigned char)*cursor))
      return false;

  if (*cursor++ != '-')
    return false;

  int seq_digits = 0;
  while (isdigit((unsigned char)*cursor))
  {
    cursor++;
    seq_digits++;
  }

  return (seq_digits >= CVELOOKUP_ID_SEQ_MIN_DIGITS && seq_digits <= CVELOOKUP_ID_SEQ_MAX_DIGITS && *cursor == '\0');
}

bool validate_cweId(const char* cwe_id)
{
  if (!cwe_id || *cwe_id == '\0' || strncmp(cwe_id, "CWE-", CWELOOKUP_ID_TAG_LEN) != 0)
    return false;

  const char* cursor = cwe_id + CWELOOKUP_ID_TAG_LEN;
  int id_digits = 0;
  while (isdigit((unsigned char)*cursor))
  {
    cursor++;
    id_digits++;
  }

  return (id_digits >= CWELOOKUP_ID_MIN_DIGITS && id_digits <= CWELOOKUP_ID_MAX_DIGITS && *cursor == '\0');
}

static bool static_isHexText(const char* text)
{
  for (; *text; text++)
    if (!isxdigit((unsigned char)*text))
      return false;

  return true;
}

bool validate_sha1Hex(const char* sha1_hex)
{
  return strlen(sha1_hex) == VALIDATE_SHA1_HEX_LEN && static_isHexText(sha1_hex);
}

bool validate_fileHashHex(const char* file_hash_hex)
{
  size_t len = strlen(file_hash_hex);
  if (len != VALIDATE_MD5_HEX_LEN && len != VALIDATE_SHA1_HEX_LEN && len != VALIDATE_SHA256_HEX_LEN)
    return false;

  return static_isHexText(file_hash_hex);
}

static bool static_isDomainLabelByte(char byte)
{
  return isalpha((unsigned char)byte) || isdigit((unsigned char)byte) || byte == '-';
}

static bool static_isDomainLabel(const char* domain_label, size_t domain_label_len, bool is_underscore_label_allowed)
{
  if (domain_label_len == 0 || domain_label_len > VALIDATE_DOMAIN_LABEL_MAX_LEN)
    return false;

  if (is_underscore_label_allowed && domain_label[0] == '_')
    return static_isDomainLabel(domain_label + 1, domain_label_len - 1, false);

  if (domain_label[0] == '-' || domain_label[domain_label_len - 1] == '-')
    return false;

  for (size_t i = 0; i < domain_label_len; i++)
    if (!static_isDomainLabelByte(domain_label[i]))
      return false;

  return true;
}

static bool static_isDomainName(const char* domain_name, bool is_underscore_label_allowed)
{
  size_t name_len = strlen(domain_name);
  if (name_len == 0 || name_len > VALIDATE_DOMAIN_NAME_MAX_LEN)
    return false;

  int         label_count  = 0;
  const char* domain_label = domain_name;
  const char* dot          = NULL;
  while ((dot = strchr(domain_label, '.')) != NULL)
  {
    if (!static_isDomainLabel(domain_label, (size_t)(dot - domain_label), is_underscore_label_allowed))
      return false;

    label_count++;
    domain_label = dot + 1;
  }

  if (!static_isDomainLabel(domain_label, strlen(domain_label), is_underscore_label_allowed))
    return false;

  label_count++;
  return label_count >= 2 && isalpha((unsigned char)*domain_label);
}

bool validate_domainName(const char* domain_name)
{
  return static_isDomainName(domain_name, false);
}

static const char* const VALIDATE_SPECIAL_USE_LAST_LABELS[] = {
  "alt",
  "arpa",
  "corp",
  "home",
  "internal",
  "intranet",
  "invalid",
  "lan",
  "local",
  "localdomain",
  "localhost",
  "onion",
  "private",
  "test",
};

static const size_t VALIDATE_SPECIAL_USE_LAST_LABEL_COUNT = sizeof(VALIDATE_SPECIAL_USE_LAST_LABELS) / sizeof(VALIDATE_SPECIAL_USE_LAST_LABELS[0]);

static bool static_hasSpecialUseLastLabel(const char* domain_name)
{
  const char* last_label = strrchr(domain_name, '.') + 1;
  
  for (size_t i = 0; i < VALIDATE_SPECIAL_USE_LAST_LABEL_COUNT; i++)
    if (strcasecmp(last_label, VALIDATE_SPECIAL_USE_LAST_LABELS[i]) == 0)
      return true;

  return false;
}

bool validate_publicDnsName(const char* domain_name)
{
  return validate_domainName(domain_name) && !static_hasSpecialUseLastLabel(domain_name);
}

bool validate_publicUnderscoredDnsName(const char* domain_name)
{
  return static_isDomainName(domain_name, true) && !static_hasSpecialUseLastLabel(domain_name);
}

bool validate_dkimSelector(const char* dkim_selector)
{
  if (strlen(dkim_selector) > VALIDATE_DKIM_SELECTOR_MAX_LEN)
    return false;

  const char* selector_label = dkim_selector;
  const char* dot            = NULL;
  while ((dot = strchr(selector_label, '.')) != NULL)
  {
    if (!static_isDomainLabel(selector_label, (size_t)(dot - selector_label), false))
      return false;

    selector_label = dot + 1;
  }

  return static_isDomainLabel(selector_label, strlen(selector_label), false);
}

bool validate_uuid(const char* uuid)
{
  if (strlen(uuid) != VALIDATE_UUID_LEN)
    return false;

  for (size_t i = 0; i < VALIDATE_UUID_LEN; i++)
  {
    if (i == 8 || i == 13 || i == 18 || i == 23)
    {
      if (uuid[i] != '-')
        return false;
    }
    else if (!isxdigit((unsigned char)uuid[i]) || isupper((unsigned char)uuid[i]))
    {
      return false;
    }
  }
  return true;
}

bool validate_watchlistCursor(const char* cursor)
{
  size_t cursor_len = strlen(cursor);
  if (cursor_len == 0 || cursor_len > WATCHLIST_CURSOR_MAX_LEN)
    return false;
  if (cursor[0] == '0')
    return cursor_len == 1;

  for (size_t i = 0; i < cursor_len; i++)
  {
    if (!isdigit((unsigned char)cursor[i]))
      return false;
  }
  return true;
}

bool validate_attackTechniqueId(const char* attack_technique_id)
{
  size_t id_len = strlen(attack_technique_id);
  if (id_len != ATTACK_TECHNIQUE_ID_MIN_LEN && id_len != ATTACK_TECHNIQUE_ID_MAX_LEN)
    return false;
  if (attack_technique_id[0] != 'T')
    return false;

  for (size_t i = 1; i < id_len; i++)
  {
    if (i == ATTACK_TECHNIQUE_ID_MIN_LEN)
    {
      if (attack_technique_id[i] != '.')
        return false;
    }
    else if (!isdigit((unsigned char)attack_technique_id[i]))
      return false;
  }
  return true;
}

static const char* const VALIDATE_PACKAGE_ECOSYSTEMS[] = { "npm", "PyPI", "Maven", "Go", "NuGet", "RubyGems", "crates.io", "Packagist", "SwiftURL" };

bool validate_packageEcosystem(const char* ecosystem)
{
  for (size_t i = 0; i < sizeof(VALIDATE_PACKAGE_ECOSYSTEMS) / sizeof(VALIDATE_PACKAGE_ECOSYSTEMS[0]); i++)
    if (strcasecmp(ecosystem, VALIDATE_PACKAGE_ECOSYSTEMS[i]) == 0)
      return true;
  return false;
}

bool validate_packageName(const char* package_name)
{
  return strchr(package_name, ' ') == NULL;
}

bool validate_packageVersion(const char* version)
{
  for (; *version; version++)
    if (*version < '!' || *version > '~')
      return false;
  return true;
}

bool validate_packageExactVersion(const char* version)
{
  if (*version == '\0' || !validate_packageVersion(version) || strpbrk(version, "^~<>=*|,") != NULL)
    return false;

  for (const char* part = version; ; )
  {
    size_t part_len = strcspn(part, ".");

    if (part_len == 1 && (part[0] == 'x' || part[0] == 'X'))
      return false;
    if (part[part_len] == '\0')
      return true;
    
    part += part_len + 1;
  }
}

bool validate_asn(const char* asn_text)
{
  const char* digits = asn_text;
  if (strncmp(asn_text, "AS", sizeof("AS") - 1) == 0 || strncmp(asn_text, "as", sizeof("as") - 1) == 0)
    digits += sizeof("AS") - 1;

  size_t digit_count = strlen(digits);
  if (digit_count == 0 || digit_count > VALIDATE_ASN_MAX_DIGITS || digits[0] == '0')
    return false;

  uint64_t as_value = 0;
  for (size_t i = 0; i < digit_count; i++)
  {
    if (!isdigit((unsigned char)digits[i]))
      return false;
    as_value = as_value * 10 + (uint64_t)(digits[i] - '0');
  }
  return as_value <= UINT32_MAX;
}

bool validate_asnLookupTarget(const char* target)
{
  return validate_asn(target) || ipguard_isGloballyReachableIp(target);
}

static const char VALIDATE_EMAIL_ATEXT_SYMBOLS[] = "!#$%&'*+-/=?^_`{|}~";

static bool static_isEmailAtextByte(char byte)
{
  assert(byte != '\0');
  return isalpha((unsigned char)byte) || isdigit((unsigned char)byte) || strchr(VALIDATE_EMAIL_ATEXT_SYMBOLS, byte) != NULL;
}

bool validate_emailAddress(const char* email)
{
  size_t email_len = strlen(email);
  if (email_len > VALIDATE_EMAIL_ADDRESS_MAX_LEN)
    return false;

  const char* at_sign = strchr(email, '@');
  if (at_sign == NULL)
    return false;

  size_t local_part_len = (size_t)(at_sign - email);
  if (local_part_len == 0 || local_part_len > VALIDATE_EMAIL_LOCAL_PART_MAX_LEN)
    return false;
  if (email[0] == '.' || email[local_part_len - 1] == '.')
    return false;

  for (size_t i = 0; i < local_part_len; i++)
  {
    if (email[i] == '.')
    {
      if (email[i + 1] == '.')
        return false;
    }
    else if (!static_isEmailAtextByte(email[i]))
      return false;
  }

  return validate_publicDnsName(at_sign + 1);
}

bool validate_vendorKeyLink(const char* link)
{
  if (strlen(link) != KEYVAULT_VENDOR_KEY_LINK_LEN)
    return false;

  for (size_t i = 0; i < KEYVAULT_VENDOR_KEY_LINK_LEN; i++)
  {
    if (!isxdigit((unsigned char)link[i]) || isupper((unsigned char)link[i]))
      return false;
  }
  return true;
}

bool validate_vendorKey(const char* vendor_key)
{
  size_t key_len = strlen(vendor_key);
  if (key_len == 0 || key_len > KEYVAULT_VENDOR_KEY_MAX_LEN)
    return false;

  for (size_t i = 0; i < key_len; i++)
  {
    unsigned char byte = (unsigned char)vendor_key[i];
    if (byte < ' ' || byte > '~')
      return false;
  }
  return true;
}
