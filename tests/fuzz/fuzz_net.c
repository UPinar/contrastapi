#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cvss.h"
#include "dns.h"
#include "emailauth.h"
#include "external/rdap.h"
#include "external/whois.h"
#include "header_check.h"
#include "retryafter.h"
#include "robotstxt.h"
#include "securitytxt.h"

#define FUZZ_NET_PARSER_COUNT 8

#define FUZZ_NET_NOW_EPOCH 1800000000

static const char* const FUZZ_NET_WHOIS_DOMAINS[] = {
  "example.ac", "example.am", "example.dk", "example.il", "example.ls", "example.lt",
};
#define FUZZ_NET_WHOIS_DOMAIN_COUNT (sizeof(FUZZ_NET_WHOIS_DOMAINS) / sizeof(FUZZ_NET_WHOIS_DOMAINS[0]))

static void static_splitHeaderValues(char* text, size_t len, char** values_out)
{
  size_t part_start = 0;
  for (int i = 0; i < HEADER_CHECK_HEADER_COUNT; i++)
  {
    if (part_start > len)
    {
      values_out[i] = NULL;
      continue;
    }
    values_out[i] = text + part_start;
    part_start += strlen(text + part_start) + 1;
  }
}

static size_t static_countLines(const char* value)
{
  if (value == NULL)
    return 0;
  size_t line_count = 1;
  for (const char* byte = value; *byte != '\0'; byte++)
    if (*byte == '\n')
      line_count++;
  return line_count;
}

static void static_runParser(unsigned parser_index, const char* exact, char* text, size_t len)
{
  switch (parser_index)
  {
    case 0:
    {
      RobotsTxt_t robots;
      memset(&robots, 0, sizeof(robots));
      if (robotstxt_parse(exact, len, len % 2 == 1, "ContrastAPI", &robots))
      {
        (void)robotstxt_checkPath(&robots, exact, "/a/b?c", 6);
        robotstxt_free(&robots);
      }
      break;
    }
    case 1:
    {
      SecurityTxtReport_t report;
      securitytxt_parse(exact, len, len % 2 == 1, FUZZ_NET_NOW_EPOCH, &report);
      break;
    }
    case 2:
    {
      char* values[HEADER_CHECK_HEADER_COUNT];
      static_splitHeaderValues(text, len, values);
      size_t set_cookie_copy_count = static_countLines(values[HEADER_CHECK_HEADER_SET_COOKIE]) + len % 4;
      HeaderCheckReport_t report;
      header_check_evaluate(values, set_cookie_copy_count, &report);
      break;
    }
    case 3:
    {
      DnsRecordText_t record = { .mp_bytes = text, .m_byteCount = len };
      EmailAuthSpf_t   spf;
      EmailAuthDmarc_t dmarc;
      EmailAuthDkim_t  dkim;
      if (emailauth_isSpfRecord(&record))
        emailauth_parseSpf(&record, &spf);
      if (emailauth_isDmarcRecord(&record))
        emailauth_parseDmarc(&record, &dmarc);
      emailauth_parseDkim(&record, &dkim);
      break;
    }
    case 4:
    {
      CvssResult_t result;
      (void)cvss_parse(text, &result);
      break;
    }
    case 5:
      (void)retryafter_parseSeconds(text);
      break;
    case 6:
    {
      RdapRegistration_t registration;
      (void)rdap_tryReadDomain(exact, len, &registration);
      break;
    }
    case 7:
    {
      if (len < 1)
        break;
      const char* domain_name     = FUZZ_NET_WHOIS_DOMAINS[(unsigned char)exact[0] % FUZZ_NET_WHOIS_DOMAIN_COUNT];
      const WhoisServer_t* server = whois_findServer(domain_name);
      if (server == NULL)
        abort();
      RdapRegistration_t registration;
      (void)whois_readAnswer(exact + 1, len - 1, domain_name, server, &registration);
      break;
    }
    default:
      abort();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 1)
    return -1;

  unsigned parser_index = data[0] % FUZZ_NET_PARSER_COUNT;
  const uint8_t* bytes  = data + 1;
  size_t len            = size - 1;

  char* exact = malloc(len > 0 ? len : 1);
  char* text  = malloc(len + 1);
  if (exact == NULL || text == NULL)
    abort();
  memcpy(exact, bytes, len);
  memcpy(text, bytes, len);
  text[len] = '\0';

  static_runParser(parser_index, exact, text, len);

  free(exact);
  free(text);
  return 0;
}
