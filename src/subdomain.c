/*
 * subdomain — the host names under one domain.
 *
 * subdomain_addName keeps a set of names under a domain. Each name carries the ways it was
 * found. certspotter_lookupSubdomainNames adds the names certificates hold.
 * subdomain_lookupDnsNames adds what DNS shows: the hosts the domain's own MX, NS and SPF
 * records name, and the wordlist guesses that resolve.
 *
 * A guess that resolves proves nothing when the domain answers every name under it. Two
 * random names are asked along with the guesses. A guess is kept only when the resolver
 * answers both, and neither answer holds a record.
 *
 * subdomain_wordlist mixes two public lists. The first is SecLists
 * Discovery/DNS/subdomains-top1million-5000.txt (MIT, commit fd02038d8b47), without
 * localhost. The second is assetnote commonspeak2-wordlists subdomains/subdomains.txt
 * (Apache-2.0, commit a514ff1becb4). The labels were taken one from each list in turn. A
 * repeat was skipped. The list keeps the first 94. Both lists were downloaded 2026-10-26.
 * On 12 domains this mix found 182 hosts. SecLists alone found 157, and commonspeak2 alone
 * found 151 (measured 2026-10-26).
 */

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>

#include "subdomain.h"
#include "dns.h"
#include "emailauth.h"
#include "monotonic.h"
#include "validate.h"

#define SUBDOMAIN_PROBE_COUNT 2

#define SUBDOMAIN_PROBE_LABEL_LEN 14

#define SUBDOMAIN_DOMAIN_QUESTION_COUNT 3

#define SUBDOMAIN_MAX_QUESTION_COUNT (SUBDOMAIN_PROBE_COUNT + SUBDOMAIN_DOMAIN_QUESTION_COUNT + SUBDOMAIN_WORDLIST_COUNT)

const char* const subdomain_wordlist[SUBDOMAIN_WORDLIST_COUNT] = {
  "www", "mail", "m", "ns2", "blog", "ns1", "forum", "ftp", "shop", "smtp", "support",
  "webmail", "my", "autodiscover", "help", "pop", "app", "ns3", "store", "imap", "portal",
  "test", "secure", "vpn", "jobs", "sip", "news", "api", "careers", "ns", "es", "dev",
  "mobile", "pop3", "www2", "cdn", "en", "ns4", "fr", "online", "login", "lyncdiscover",
  "forums", "speedtest", "cloud", "wiki", "de", "cpanel", "community", "it", "admin", "docs",
  "dns2", "web", "git", "info", "ru", "enterpriseenrollment", "library",
  "enterpriseregistration", "search", "dns1", "moodle", "autoconfig", "bbs", "ntp", "us",
  "mail2", "pt", "apps", "dns", "blogs", "email", "catalog", "zabbix", "go", "account", "new",
  "www1", "images", "uk", "old", "members", "nl", "demo", "id", "msoid", "sso", "amp", "proxy",
  "home", "monitor", "live", "mx"
};

SubdomainNameSet_t* subdomain_createNameSet(void)
{
  SubdomainNameSet_t* name_set = calloc(1, sizeof(*name_set));
  if (name_set == NULL)
    return NULL;

  name_set->mp_names   = calloc(SUBDOMAIN_MAX_NAME_COUNT, sizeof(name_set->mp_names[0]));
  name_set->mp_sources = calloc(SUBDOMAIN_MAX_NAME_COUNT, sizeof(name_set->mp_sources[0]));
  if (name_set->mp_names == NULL || name_set->mp_sources == NULL)
  {
    subdomain_destroyNameSet(name_set);
    return NULL;
  }
  return name_set;
}

void subdomain_destroyNameSet(SubdomainNameSet_t* name_set)
{
  if (name_set == NULL)
    return;

  free(name_set->mp_names);
  free(name_set->mp_sources);
  free(name_set);
}

void subdomain_addName(SubdomainNameSet_t* name_set, const char* name, const char* domain, unsigned int source)
{
  assert(name_set != NULL);
  assert(name     != NULL);
  assert(domain   != NULL);

  if (name[0] == '*' && name[1] == '.')
    name += 2;

  size_t name_len   = strlen(name);
  size_t domain_len = strlen(domain);
  if (name_len > VALIDATE_DOMAIN_NAME_MAX_LEN || name_len < domain_len + 2)
    return;

  char lower_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  for (size_t i = 0; i < name_len; i++)
    lower_name[i] = (char)tolower((unsigned char)name[i]);
  lower_name[name_len] = '\0';

  size_t suffix_start = name_len - domain_len;
  if (lower_name[suffix_start - 1] != '.' || memcmp(lower_name + suffix_start, domain, domain_len) != 0)
    return;
  if (!validate_publicDnsName(lower_name))
    return;

  for (int i = 0; i < name_set->m_count; i++)
  {
    if (strcmp(name_set->mp_names[i], lower_name) == 0)
    {
      name_set->mp_sources[i] |= source;
      return;
    }
  }

  if (name_set->m_count == SUBDOMAIN_MAX_NAME_COUNT)
    return;

  memcpy(name_set->mp_names[name_set->m_count], lower_name, name_len + 1);
  name_set->mp_sources[name_set->m_count] = source;
  name_set->m_count++;
}

static bool static_tryJoinName(char* name_out, const char* label, const char* domain)
{
  int written = snprintf(name_out, VALIDATE_DOMAIN_NAME_MAX_LEN + 1, "%s.%s", label, domain);
  return written >= 0 && written <= VALIDATE_DOMAIN_NAME_MAX_LEN;
}

static bool static_tryWriteProbeNames(const char* domain, char probe_names[SUBDOMAIN_PROBE_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1])
{
  for (int i = 0; i < SUBDOMAIN_PROBE_COUNT; i++)
  {
    unsigned char random_bytes[SUBDOMAIN_PROBE_LABEL_LEN];
    if (getrandom(random_bytes, sizeof(random_bytes), 0) != (ssize_t)sizeof(random_bytes))
      return false;

    char label[SUBDOMAIN_PROBE_LABEL_LEN + 1];
    for (int k = 0; k < SUBDOMAIN_PROBE_LABEL_LEN; k++)
      label[k] = (char)('a' + random_bytes[k] % 26);
    label[SUBDOMAIN_PROBE_LABEL_LEN] = '\0';

    if (!static_tryJoinName(probe_names[i], label, domain))
      return false;
  }
  return true;
}

static void static_askQuestionsInRounds(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out)
{
  int64_t start_ms = monotonic_nowMs();
  for (int first = 0; first < question_count; first += DNS_MAX_QUESTION_COUNT)
  {
    int round_count = question_count - first;
    if (round_count > DNS_MAX_QUESTION_COUNT)
      round_count = DNS_MAX_QUESTION_COUNT;

    int64_t left_ms = deadline_ms - (monotonic_nowMs() - start_ms);
    if (left_ms > 0)
    {
      dns_askQuestions(&questions[first], round_count, (int)left_ms, &answers_out[first]);
      continue;
    }

    for (int i = 0; i < round_count; i++)
      answers_out[first + i] = (DnsAnswer_t){ .m_status = DNS_ANSWER_TIMEOUT };
  }
}

static bool static_hasRecord(const DnsAnswer_t* answer)
{
  return answer->m_status == DNS_ANSWER_OK && answer->m_recordCount > 0;
}

static SubdomainWildcard_t static_readWildcard(const DnsAnswer_t* probe_answers, int probe_count)
{
  if (probe_count == 0)
    return SUBDOMAIN_WILDCARD_UNDETERMINED;

  int empty_count = 0;
  for (int i = 0; i < probe_count; i++)
  {
    if (static_hasRecord(&probe_answers[i]))
      return SUBDOMAIN_WILDCARD_PRESENT;
    if (probe_answers[i].m_status == DNS_ANSWER_NXDOMAIN || probe_answers[i].m_status == DNS_ANSWER_OK)
      empty_count++;
  }
  return empty_count == probe_count ? SUBDOMAIN_WILDCARD_ABSENT : SUBDOMAIN_WILDCARD_UNDETERMINED;
}

static bool static_isDomainSpfTerm(EmailAuthSpfTermKind_t kind)
{
  return  kind == EMAILAUTH_SPF_TERM_A        || 
          kind == EMAILAUTH_SPF_TERM_MX       ||
          kind == EMAILAUTH_SPF_TERM_INCLUDE  || 
          kind == EMAILAUTH_SPF_TERM_EXISTS   ||
          kind == EMAILAUTH_SPF_TERM_REDIRECT;
}

static void static_addSpfRecordNames(const DnsAnswer_t* txt_answer, const char* domain, SubdomainNameSet_t* name_set)
{
  int spf_index = 0;
  if (emailauth_countSpfRecords(txt_answer->mp_texts, txt_answer->m_recordCount, &spf_index) != EMAILAUTH_RECORD_ONE)
    return;

  EmailAuthSpf_t spf;
  emailauth_parseSpf(&txt_answer->mp_texts[spf_index], &spf);
  for (int i = 0; i < spf.m_termCount; i++)
  {
    const EmailAuthSpfTerm_t* term = &spf.ma_terms[i];
    if (!static_isDomainSpfTerm(term->m_kind))
      continue;

    size_t host_len   = term->m_value.m_byteCount;
    const char* slash = memchr(term->m_value.mp_bytes, '/', host_len);
    if (slash != NULL)
      host_len = (size_t)(slash - term->m_value.mp_bytes);
    if (host_len > VALIDATE_DOMAIN_NAME_MAX_LEN)
      continue;

    char host[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
    memcpy(host, term->m_value.mp_bytes, host_len);
    host[host_len] = '\0';
    subdomain_addName(name_set, host, domain, SUBDOMAIN_SOURCE_DNS_RECORDS);
  }
}

static void static_addDnsRecordNames(const DnsAnswer_t* domain_answers, const char* domain, SubdomainNameSet_t* name_set)
{
  const DnsAnswer_t* mx_answer  = &domain_answers[0];
  const DnsAnswer_t* ns_answer  = &domain_answers[1];
  const DnsAnswer_t* txt_answer = &domain_answers[2];

  for (int i = 0; i < mx_answer->m_recordCount; i++)
    subdomain_addName(name_set, mx_answer->mp_mxRecords[i].mp_hostname, domain, SUBDOMAIN_SOURCE_DNS_RECORDS);
  for (int i = 0; i < ns_answer->m_recordCount; i++)
    subdomain_addName(name_set, ns_answer->mp_texts[i].mp_bytes, domain, SUBDOMAIN_SOURCE_DNS_RECORDS);
  
  static_addSpfRecordNames(txt_answer, domain, name_set);
}

void subdomain_lookupDnsNames(const char* domain, SubdomainNameSet_t* name_set, SubdomainWildcard_t* wildcard_dns_out)
{
  assert(domain           != NULL);
  assert(name_set         != NULL);
  assert(wildcard_dns_out != NULL);

  char          probe_names[SUBDOMAIN_PROBE_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char          guess_names[SUBDOMAIN_WORDLIST_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  DnsQuestion_t questions[SUBDOMAIN_MAX_QUESTION_COUNT];
  DnsAnswer_t   answers[SUBDOMAIN_MAX_QUESTION_COUNT];
  int           question_count = 0;

  int probe_count = static_tryWriteProbeNames(domain, probe_names) ? SUBDOMAIN_PROBE_COUNT : 0;
  for (int i = 0; i < probe_count; i++)
    questions[question_count++] = (DnsQuestion_t){ probe_names[i], DNS_RECORD_TYPE_A };

  int domain_index = question_count;
  questions[question_count++] = (DnsQuestion_t){ domain, DNS_RECORD_TYPE_MX };
  questions[question_count++] = (DnsQuestion_t){ domain, DNS_RECORD_TYPE_NS };
  questions[question_count++] = (DnsQuestion_t){ domain, DNS_RECORD_TYPE_TXT };

  int guess_index = question_count;
  for (int i = 0; i < SUBDOMAIN_WORDLIST_COUNT; i++)
    if (static_tryJoinName(guess_names[i], subdomain_wordlist[i], domain))
      questions[question_count++] = (DnsQuestion_t){ guess_names[i], DNS_RECORD_TYPE_A };

  static_askQuestionsInRounds(questions, question_count, SUBDOMAIN_DNS_DEADLINE_MS, answers);

  *wildcard_dns_out = static_readWildcard(answers, probe_count);
  static_addDnsRecordNames(&answers[domain_index], domain, name_set);
  if (*wildcard_dns_out == SUBDOMAIN_WILDCARD_ABSENT)
  {
    for (int i = guess_index; i < question_count; i++)
      if (static_hasRecord(&answers[i]))
        subdomain_addName(name_set, questions[i].mp_domainName, domain, SUBDOMAIN_SOURCE_DNS_WORDLIST);
  }

  for (int i = 0; i < question_count; i++)
    dns_answerFree(&answers[i]);
}
