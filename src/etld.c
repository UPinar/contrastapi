#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "etld.h"
#include "validate.h"

#define ETLD_RULE_KEY_SIZE (2 + VALIDATE_DOMAIN_NAME_MAX_LEN + 1)

static const char* static_parentName      (const char* domain_name);
static bool        static_isExceptionRule (const char* etld_candidate);
static bool        static_isPlainRule     (const char* etld_candidate);
static bool        static_isWildcardRule  (const char* parent_name);
static bool        static_isRuleListed    (const char* prefix, const char* rule_name);
static int         static_compareRule     (const void* rule_key, const void* rule_offset);

const char* etld_find(const char* domain_name)
{
  if (!validate_domainName(domain_name))
    return NULL;

  for (const char* etld_candidate = domain_name; etld_candidate != NULL; etld_candidate = static_parentName(etld_candidate))
    if (static_isExceptionRule(etld_candidate))
      return static_parentName(etld_candidate);

  for (const char* etld_candidate = domain_name; etld_candidate != NULL; etld_candidate = static_parentName(etld_candidate))
    if (static_isPlainRule(etld_candidate) || static_isWildcardRule(static_parentName(etld_candidate)))
      return etld_candidate;

  return strrchr(domain_name, '.') + 1;
}

const char* etld_findPlusOne(const char* domain_name)
{
  const char* etld = etld_find(domain_name);
  if (etld == NULL || etld == domain_name)
    return NULL;

  const char* etld_plus_one = etld - 1;
  while (etld_plus_one > domain_name && etld_plus_one[-1] != '.')
    etld_plus_one--;

  return etld_plus_one;
}

static const char* static_parentName(const char* domain_name)
{
  const char* dot = strchr(domain_name, '.');
  return dot != NULL ? dot + 1 : NULL;
}

static bool static_isExceptionRule(const char* etld_candidate)
{
  return static_isRuleListed("!", etld_candidate);
}

static bool static_isPlainRule(const char* etld_candidate)
{
  return static_isRuleListed("", etld_candidate);
}

static bool static_isWildcardRule(const char* parent_name)
{
  return parent_name != NULL && static_isRuleListed("*.", parent_name);
}

static bool static_isRuleListed(const char* prefix, const char* rule_name)
{
  char rule_key[ETLD_RULE_KEY_SIZE];
  int  rule_key_len = snprintf(rule_key, sizeof(rule_key), "%s%s", prefix, rule_name);
  if (rule_key_len < 0 || (size_t)rule_key_len >= sizeof(rule_key))
    return false;

  for (char* key_byte = rule_key; *key_byte != '\0'; key_byte++)
    *key_byte = (char)tolower((unsigned char)*key_byte);

  return bsearch(rule_key, etld_ruleOffsets, (size_t)etld_ruleCount, sizeof(etld_ruleOffsets[0]), static_compareRule) != NULL;
}

static int static_compareRule(const void* rule_key, const void* rule_offset)
{
  return strcmp((const char*)rule_key, etld_ruleText + *(const uint32_t*)rule_offset);
}
