#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "unity/unity.h"
#include "external/whois.h"
#include "external/rdap.h"
#include "dns.h"
#include "validate.h"

static const char ICANN_ANSWER[] =
  "Domain Name: example.io\r\n"
  "Registry Domain ID: REDACTED\r\n"
  "Registrar WHOIS Server: whois.registrar.test\r\n"
  "Registrar URL: https://registrar.test\r\n"
  "Updated Date: 2026-08-12T09:08:04Z\r\n"
  "Creation Date: 2013-03-08T19:12:48Z\r\n"
  "Registry Expiry Date: 2027-03-08T19:12:47Z\r\n"
  "Registrar: Example Registrar Inc.\r\n"
  "Registrar IANA ID: 292\r\n"
  "Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\r\n"
  "Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\r\n"
  "Registrant Name: Registrant Person\r\n"
  "Registrant Organization: Registrant Company\r\n"
  "Name Server: NS-1.EXAMPLE-DNS.NET.\r\n"
  "Name Server: ns-2.example-dns.org\r\n"
  "DNSSEC: unsigned\r\n"
  "URL of the ICANN Whois Inaccuracy Complaint Form: https://icann.org/wicf/\r\n"
  ">>> Last update of WHOIS database: 2026-10-25T19:23:04Z <<<\r\n"
  "\r\n"
  "Terms of Use: Access to WHOIS information is provided to assist persons in\r\n"
  "determining the contents of a domain name registration record.\r\n";

static const char AM_ANSWER[] =
  "%\n"
  "%AM TLD whois server #2\n"
  "%\n"
  "\n"
  "   Domain name: example.am\n"
  "   Registrar:   exampledomain (Example Domain LLC)\n"
  "   Status:      active, registrar locked\n"
  "\n"
  "   Registrant:\n"
  "      Registrant Company\n"
  "      US\n"
  "\n"
  "   DNS servers:\n"
  "      ns1.example-dns.com\n"
  "      NS2.EXAMPLE-DNS.COM\n"
  "\n"
  "   Registered:    1999-06-05\n"
  "   Last modified: 2026-03-19\n"
  "   Expires:       2027-04-15\n";

static const char DK_ANSWER[] =
  "# Hello 192.0.2.1. Your session has been logged.\n"
  "#\n"
  "Domain:               example.dk\n"
  "DNS:                  example.dk\n"
  "Registered:           1998-03-11\n"
  "Expires:              2027-03-31\n"
  "Registration period:  1 year\n"
  "VID:                  no\n"
  "DNSSEC:               Signed delegation\n"
  "Status:               Active\n"
  "\n"
  "Nameservers\n"
  "Hostname:             a1.example-dns.net\n"
  "Hostname:             a2.example-dns.net\n";

static const char IL_ANSWER[] =
  "% The data in the WHOIS database of the .il registry is provided\n"
  "% by ISOC-IL for information purposes.\n"
  "\n"
  "query:        example.co.il\n"
  "\n"
  "reg-name:     example\n"
  "domain:       example.co.il\n"
  "\n"
  "registrant:   Registrant Company\n"
  "e-mail:       registrant AT example.co.il\n"
  "nserver:      ns1.example.co.il \n"
  "nserver:      ns2.example.co.il \n"
  "assigned:     11-01-1996\n"
  "validity:     12-02-2029\n"
  "DNSSEC:       signed\n"
  "status:       Transfer Locked\n"
  "changed:      registrar AT ns.il 19960111 (Assigned)\n"
  "\n"
  "registrar name: Example Registrar Ltd\n"
  "registrar info: www.registrar.test\n";

static const char LS_ANSWER[] =
  "domain:       example.ls\n"
  "registrant:   ADMIN-EXAMPLE\n"
  "nsset:        EXAMPLE-NSSET\n"
  "registrar:    REG-EXAMPLE\n"
  "registered:   24.04.2017 19:08:24\n"
  "expire:       25.05.2029\n"
  "\n"
  "contact:      ADMIN-EXAMPLE\n"
  "registrar:    REG-CONTACT\n"
  "created:      24.03.2017 12:11:38\n"
  "\n"
  "nsset:        EXAMPLE-NSSET\n"
  "nserver:      ns1.example.ls (192.0.2.1)\n"
  "nserver:      ns2.example.ls (192.0.2.2)\n"
  "registrar:    REG-NSSET\n"
  "\n"
  ">>> Terms: Data provided for information purposes only.\n";

static const char LT_ANSWER[] =
  "% Hello, this is the DOMREG whois service.\n"
  "%\n"
  "Domain:\t\t\texample.lt\n"
  "Status:\t\t\tregistered\n"
  "Registered:\t\t2012-11-02\n"
  "Expires:\t\t2026-11-03\n"
  "%\n"
  "Registrar:\t\tExample Registrar UAB\n"
  "Registrar website:\thttps://registrar.test\n"
  "%\n"
  "Nameserver:\t\tns1.example.lt\t\n"
  "Nameserver:\t\tns2.example.lt\t\n"
  "%\n"
  "DS:\t\t\t15857\t13 2 97F03D0935C60520\n";

static const char TC_ANSWER[] =
  "Domain Name: example.tc\n"
  "WHOIS Server: whois.nic.tc\n"
  "Creation Date: 1998-08-26T04:00:00.0Z\n"
  "Registry Expiry Date: 2035-01-01T05:00:00.0Z\n"
  "Sponsoring Registrar: Example TC Registrar\n"
  "Domain Status: ok\n"
  "Name Server: ns1.example.tc\n"
  "DNSSEC: signedDelegation\n"
  "Sponsoring Registrar URL: https://registrar.test\n";

static const WhoisServer_t* static_server(const char* tld)
{
  const WhoisServer_t* server = whois_findServer(tld);
  TEST_ASSERT_NOT_NULL_MESSAGE(server, tld);
  return server;
}

static WhoisStatus_t static_read(const char* text, const char* domain_name, const char* tld, RdapRegistration_t* registration_out)
{
  return whois_readAnswer(text, strlen(text), domain_name, static_server(tld), registration_out);
}

static void static_assertCleared(const RdapRegistration_t* registration)
{
  TEST_ASSERT_EQUAL_STRING("", registration->ma_registrarName);
  TEST_ASSERT_EQUAL_INT(-1, (int)registration->m_registrarIanaId);
  TEST_ASSERT_EQUAL_STRING("", registration->ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("", registration->ma_updatedAt);
  TEST_ASSERT_EQUAL_STRING("", registration->ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(0, registration->m_statusCount);
  TEST_ASSERT_EQUAL_INT(0, registration->m_nameServerCount);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_UNKNOWN, registration->m_delegationSigned);
}

static WhoisStatus_t static_readOneValue(const char* key, const char* value, RdapRegistration_t* registration_out)
{
  char text[1024];
  snprintf(text, sizeof(text), "Domain Name: example.io\r\n%s: %s\r\n", key, value);
  return static_read(text, "example.io", "io", registration_out);
}

static const char* static_readDate(const char* value)
{
  static RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT_MESSAGE(WHOIS_OK, static_readOneValue("Creation Date", value, &registration), value);
  return registration.ma_createdAt;
}

void test_servers_are_sorted_lower_case_tlds_with_a_host_and_a_key_map(void)
{
  TEST_ASSERT_EQUAL_INT(37, whois_serverCount);
  for (int i = 0; i < whois_serverCount; i++)
  {
    const WhoisServer_t* server = &whois_servers[i];
    TEST_ASSERT_TRUE_MESSAGE(server->mp_tld[0] >= 'a' && server->mp_tld[0] <= 'z', server->mp_tld);
    for (const char* byte = server->mp_tld; *byte != '\0'; byte++)
      TEST_ASSERT_TRUE_MESSAGE((*byte >= 'a' && *byte <= 'z') || (*byte >= '0' && *byte <= '9') || *byte == '-', server->mp_tld);
    if (i > 0)
      TEST_ASSERT_LESS_THAN_INT_MESSAGE(0, strcmp(whois_servers[i - 1].mp_tld, server->mp_tld), server->mp_tld);

    TEST_ASSERT_TRUE_MESSAGE(validate_domainName(server->mp_host), server->mp_tld);
    TEST_ASSERT_NOT_NULL_MESSAGE(server->mp_keyMap, server->mp_tld);
    bool has_domain_name_key = false;
    for (int k = 0; k < server->mp_keyMap->m_keyCount; k++)
      has_domain_name_key = has_domain_name_key || server->mp_keyMap->mp_keys[k].m_field == WHOIS_FIELD_DOMAIN_NAME;
    TEST_ASSERT_TRUE_MESSAGE(has_domain_name_key, server->mp_tld);
    TEST_ASSERT_TRUE_MESSAGE(server->mp_notFoundMarker == NULL || server->mp_notFoundMarker[0] != '\0', server->mp_tld);
  }
}

void test_no_listed_tld_has_an_rdap_server(void)
{
  for (int i = 0; i < whois_serverCount; i++)
  {
    for (int r = 0; r < rdap_serverCount; r++)
      TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(0, strcmp(whois_servers[i].mp_tld, rdap_servers[r].mp_tld), whois_servers[i].mp_tld);
  }
}

void test_each_server_has_a_terms_snapshot(void)
{
  for (int i = 0; i < whois_serverCount; i++)
  {
    char path[300];
    snprintf(path, sizeof(path), "tests/whois_terms/%s.txt", whois_servers[i].mp_host);
    FILE* file = fopen(path, "r");
    TEST_ASSERT_NOT_NULL_MESSAGE(file, path);
    fclose(file);
  }
}

void test_servers_that_share_a_host_share_its_key_map_and_not_found_text(void)
{
  for (int i = 0; i < whois_serverCount; i++)
    for (int j = i + 1; j < whois_serverCount; j++)
    {
      const WhoisServer_t* a = &whois_servers[i];
      const WhoisServer_t* b = &whois_servers[j];
      if (strcmp(a->mp_host, b->mp_host) != 0)
        continue;
      TEST_ASSERT_TRUE_MESSAGE(a->mp_keyMap == b->mp_keyMap, b->mp_tld);
      TEST_ASSERT_TRUE_MESSAGE((a->mp_notFoundMarker == NULL) == (b->mp_notFoundMarker == NULL), b->mp_tld);
      if (a->mp_notFoundMarker != NULL)
        TEST_ASSERT_EQUAL_STRING_MESSAGE(a->mp_notFoundMarker, b->mp_notFoundMarker, b->mp_tld);
    }
}

void test_findServer_reads_the_last_label_in_any_case(void)
{
  TEST_ASSERT_EQUAL_STRING("whois.nic.io", static_server("www.example.io")->mp_host);
  TEST_ASSERT_EQUAL_STRING("whois.nic.io", static_server("EXAMPLE.IO")->mp_host);
  TEST_ASSERT_EQUAL_STRING("whois.amnic.net", static_server("example.xn--y9a3aq")->mp_host);
  TEST_ASSERT_EQUAL_STRING("whois.nic.ac", static_server("ac")->mp_host);
  TEST_ASSERT_EQUAL_PTR(&whois_servers[0], whois_findServer(whois_servers[0].mp_tld));
  TEST_ASSERT_EQUAL_PTR(&whois_servers[whois_serverCount - 1], whois_findServer(whois_servers[whois_serverCount - 1].mp_tld));
  TEST_ASSERT_NULL(whois_findServer("example.com"));
  TEST_ASSERT_NULL(whois_findServer("example.de"));
}

void test_readAnswer_reads_every_field_of_an_icann_answer(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read(ICANN_ANSWER, "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_STRING("Example Registrar Inc.", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT(292, (int)registration.m_registrarIanaId);
  TEST_ASSERT_EQUAL_STRING("2013-03-08T19:12:48Z", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("2026-08-12T09:08:04Z", registration.ma_updatedAt);
  TEST_ASSERT_EQUAL_STRING("2027-03-08T19:12:47Z", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(2, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING("client delete prohibited", registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_STRING("server transfer prohibited", registration.ma_statuses[1]);
  TEST_ASSERT_EQUAL_INT(2, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns-1.example-dns.net", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_STRING("ns-2.example-dns.org", registration.ma_nameServers[1]);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_NO, registration.m_delegationSigned);
}

void test_readAnswer_reads_the_name_server_block_of_the_am_answer(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read(AM_ANSWER, "example.am", "am", &registration));
  TEST_ASSERT_EQUAL_STRING("exampledomain (Example Domain LLC)", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT(-1, (int)registration.m_registrarIanaId);
  TEST_ASSERT_EQUAL_STRING("1999-06-05", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("2026-03-19", registration.ma_updatedAt);
  TEST_ASSERT_EQUAL_STRING("2027-04-15", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(1, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING("active, registrar locked", registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_INT(2, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns1.example-dns.com", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_STRING("ns2.example-dns.com", registration.ma_nameServers[1]);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_UNKNOWN, registration.m_delegationSigned);
}

void test_readAnswer_reads_the_dk_answer(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read(DK_ANSWER, "example.dk", "dk", &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_STRING("1998-03-11", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("", registration.ma_updatedAt);
  TEST_ASSERT_EQUAL_STRING("2027-03-31", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(1, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING("Active", registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_INT(2, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("a1.example-dns.net", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_STRING("a2.example-dns.net", registration.ma_nameServers[1]);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_YES, registration.m_delegationSigned);
}

void test_readAnswer_reads_the_day_first_dates_of_the_il_answer(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read(IL_ANSWER, "example.co.il", "il", &registration));
  TEST_ASSERT_EQUAL_STRING("Example Registrar Ltd", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_STRING("1996-01-11", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("2029-02-12", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(1, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING("Transfer Locked", registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_INT(2, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns1.example.co.il", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_STRING("ns2.example.co.il", registration.ma_nameServers[1]);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_YES, registration.m_delegationSigned);
}

void test_readAnswer_keeps_the_domain_block_of_the_ls_answer(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read(LS_ANSWER, "example.ls", "ls", &registration));
  TEST_ASSERT_EQUAL_STRING("REG-EXAMPLE", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_STRING("2017-04-24", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("", registration.ma_updatedAt);
  TEST_ASSERT_EQUAL_STRING("2029-05-25", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(0, registration.m_statusCount);
  TEST_ASSERT_EQUAL_INT(2, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns1.example.ls", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_STRING("ns2.example.ls", registration.ma_nameServers[1]);
}

void test_readAnswer_reads_the_tab_separated_lt_answer(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read(LT_ANSWER, "example.lt", "lt", &registration));
  TEST_ASSERT_EQUAL_STRING("Example Registrar UAB", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_STRING("2012-11-02", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("2026-11-03", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(1, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING("registered", registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_INT(2, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns1.example.lt", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_STRING("ns2.example.lt", registration.ma_nameServers[1]);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_UNKNOWN, registration.m_delegationSigned);
}

void test_readAnswer_reads_the_sponsoring_registrar_of_the_tc_answer(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read(TC_ANSWER, "example.tc", "tc", &registration));
  TEST_ASSERT_EQUAL_STRING("Example TC Registrar", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_STRING("1998-08-26T04:00:00Z", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("2035-01-01T05:00:00Z", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(1, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING("active", registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_INT(1, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns1.example.tc", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_YES, registration.m_delegationSigned);
}

void test_readAnswer_not_found_line_of_each_server_is_not_registered(void)
{
  static const struct { const char* mp_tld; const char* mp_domain; const char* mp_text; } cases[] = {
    { "io", "example.io",          "Domain not found.\r\n>>> Last update of WHOIS database: 2026-10-25T19:23:04Z <<<\r\n" },
    { "dm", "example.dm",          "Domain Name: example.dm\r\n\r\n>>> This name is not available for registration:\r\n" },
    { "tc", "example.tc",          "Domain Name: example.tc\nDomain Status: No Object Found\n" },
    { "lt", "example.lt",          "% Hello\nDomain:\t\t\texample.lt\nStatus:\t\t\tavailable\n" },
    { "my", "example.my",          ">>> Domain example.my is available for registration\n" },
    { "ls", "example.ls",          "No record found for 'example.ls'.\n" },
    { "dk", "example.dk",          "# Hello\n\nNo entries found for the selected source.\n" },
    { "sa", "example.sa",          "No Match for domain: example.sa\n" },
    { "am", "example.am",          "%\n% AM TLD whois server #2\n%\n\nNo match\n" },
    { "il", "example.co.il",       "% The data in the WHOIS database of the .il registry\n%\n \n\n" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    RdapRegistration_t registration;
    TEST_ASSERT_EQUAL_INT_MESSAGE(WHOIS_NOT_REGISTERED, static_read(cases[i].mp_text, cases[i].mp_domain, cases[i].mp_tld, &registration), cases[i].mp_tld);
    static_assertCleared(&registration);
  }
}

void test_readAnswer_not_found_line_after_fields_clears_them(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_NOT_REGISTERED,
                        static_read("Domain Name: example.tc\nSponsoring Registrar: Kept Registrar\nCreation Date: 1998-08-26T04:00:00.0Z\n"
                                    "Name Server: ns1.example.tc\nDNSSEC: unsigned\nDomain Status: No Object Found\n", "example.tc", "tc", &registration));
  static_assertCleared(&registration);
}

void test_readAnswer_without_the_domain_is_an_upstream_error(void)
{
  static const struct { const char* mp_tld; const char* mp_domain; const char* mp_text; } cases[] = {
    { "io", "example.io",    "Query rate limit exceeded. Please try again later.\r\n" },
    { "io", "example.io",    "Domain Name: other.io\r\nRegistrar: Other Registrar\r\nCreation Date: 2001-02-03T04:05:06Z\r\nName Server: ns1.other.io\r\n" },
    { "io", "example.io",    "Domain Name: example.io.evil\r\nRegistrar: Other Registrar\r\n" },
    { "io", "example.io",    "Domain Name: example.i\r\nRegistrar: Other Registrar\r\n" },
    { "io", "example.io",    "Registrar: Other Registrar\r\nDomain Name:\r\n" },
    { "io", "example.io",    "Domain Name: other.io\r\nRegistrar: Other Registrar\r\nDomain Name: example.io\r\n" },
    { "io", "example.io",    "Domain Name: example.io\r\nRegistrar: Kept Registrar\r\nDomain Name: other.io\r\n" },
    { "il", "example.co.il", "% comment\nquery: example.co.il\nERROR: refused\n" },
    { "io", "example.io",    "" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    RdapRegistration_t registration;
    TEST_ASSERT_EQUAL_INT_MESSAGE(WHOIS_UPSTREAM_ERROR, static_read(cases[i].mp_text, cases[i].mp_domain, cases[i].mp_tld, &registration), cases[i].mp_text);
    static_assertCleared(&registration);
  }
}

void test_readAnswer_empty_domain_line_names_no_other_domain(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain Name: example.io\r\nRegistrar: Kept Registrar\r\nDomain Name:\r\n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_STRING("Kept Registrar", registration.ma_registrarName);
}

void test_readAnswer_compares_the_domain_and_the_keys_in_any_case(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("DOMAIN NAME: EXAMPLE.IO\nregistrar: Lower Case Registrar\n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_STRING("Lower Case Registrar", registration.ma_registrarName);
}

void test_readAnswer_skips_a_line_with_a_nul_byte_and_reads_the_last_line(void)
{
  static const char text[] = "Domain Name: example.io\nRegistrar: Hidden\0Registrar\nRegistrar: Shown Registrar\nDNSSEC: unsigned";
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, whois_readAnswer(text, sizeof(text) - 1, "example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_STRING("Shown Registrar", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_NO, registration.m_delegationSigned);

  static const char nul_domain[] = "Domain Name: example.io\0\nRegistrar: Some Registrar\n";
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_readAnswer(nul_domain, sizeof(nul_domain) - 1, "example.io", static_server("io"), &registration));
}

void test_readAnswer_first_text_and_date_win(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain Name: example.io\nRegistrar: First Registrar\nRegistrar: Second Registrar\n"
                                              "Creation Date: 2001-01-01\nCreation Date: 2002-02-02\nRegistrar IANA ID: 11\nRegistrar IANA ID: 22\n"
                                              "DNSSEC: signedDelegation\nDNSSEC: unsigned\n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_STRING("First Registrar", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_STRING("2001-01-01", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_INT(11, (int)registration.m_registrarIanaId);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_YES, registration.m_delegationSigned);
}

void test_readAnswer_registrar_name_bounds(void)
{
  char name[RDAP_REGISTRAR_NAME_MAX_LEN + 2];
  memset(name, 'r', sizeof(name) - 1);
  name[sizeof(name) - 1] = '\0';

  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Registrar", name, &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);

  name[RDAP_REGISTRAR_NAME_MAX_LEN] = '\0';
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Registrar", name, &registration));
  TEST_ASSERT_EQUAL_STRING(name, registration.ma_registrarName);

  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain Name: example.io\nRegistrar:\nRegistrar: Later Registrar\n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_STRING("Later Registrar", registration.ma_registrarName);
}

void test_readAnswer_iana_id_needs_one_to_nine_digits(void)
{
  static const struct { const char* mp_value; long m_ianaId; } cases[] = {
    { "292",        292       },
    { "1",          1         },
    { "123456789",  123456789 },
    { "1234567890", -1        },
    { "12a",        -1        },
    { "-5",         -1        },
    { "",           -1        },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    RdapRegistration_t registration;
    TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Registrar IANA ID", cases[i].mp_value, &registration));
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)cases[i].m_ianaId, (int)registration.m_registrarIanaId, cases[i].mp_value);
  }

  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain Name: example.io\nRegistrar IANA ID: 0\nRegistrar IANA ID: 22\n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_INT(0, (int)registration.m_registrarIanaId);
}

void test_readAnswer_writes_each_date_form_as_rfc_3339(void)
{
  static const struct { const char* mp_value; const char* mp_kept; } cases[] = {
    { "2026-08-12T11:01:42Z",      "2026-08-12T11:01:42Z" },
    { "2025-11-11T15:23:33.074Z",  "2025-11-11T15:23:33Z" },
    { "2035-01-01T05:00:00.0Z",    "2035-01-01T05:00:00Z" },
    { "2026-12-31T23:59:60Z",      "2026-12-31T23:59:60Z" },
    { "2002-01-08",                "2002-01-08"           },
    { "2026-08-12T11:01:42",       "2026-08-12"           },
    { "2026-08-12 11:01:42",       "2026-08-12"           },
    { "2026-08-12 11:01:42Z",      "2026-08-12"           },
    { "2026-08-12T11:01:42+03:00", "2026-08-12"           },
    { "2026-08-12T11:01:42.Z",     "2026-08-12"           },
    { "2026-08-12T11:01:42.5X",    "2026-08-12"           },
    { "2026-08-12T11:01:42x5Z",    "2026-08-12"           },
    { "2026-08-12T11:01:42.xZ",    "2026-08-12"           },
    { "11-01-1996",                "1996-01-11"           },
    { "24.04.2017",                "2017-04-24"           },
    { "24.04.2017 19:08:24",       "2017-04-24"           },
    { "24.04.2017T19:08:24Z",      "2017-04-24T19:08:24Z" },
    { "2026-01-31",                "2026-01-31"           },
    { "2026-12-01",                "2026-12-01"           },
    { "2001-Aug-23.",              ""                     },
    { "2026-13-01",                ""                     },
    { "2026-00-10",                ""                     },
    { "2026-01-32",                ""                     },
    { "2026-01-00",                ""                     },
    { "32-01-2026",                ""                     },
    { "24-04.2017",                ""                     },
    { "2026-01-01T24:00:00Z",      ""                     },
    { "2026-01-01T23:60:00Z",      ""                     },
    { "2026-01-01T23:59:61Z",      ""                     },
    { "2026-01-01T1:00:00Z",       ""                     },
    { "2026-01-01T10:00",          ""                     },
    { "2026-01-01X10:00:00Z",      ""                     },
    { "2026-01-01X",               ""                     },
    { "24.04.2017X",               ""                     },
    { "2026-01-0",                 ""                     },
    { "2026-01-01T10-00:00Z",      ""                     },
    { "2026-01-01T10:00-00Z",      ""                     },
    { "2026-01x01",                ""                     },
    { "2026x01-01",                ""                     },
    { "24.04.20x7",                ""                     },
    { "2a26-01-01",                ""                     },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_kept, static_readDate(cases[i].mp_value), cases[i].mp_value);
}

void test_readAnswer_writes_each_epp_code_as_its_rdap_name(void)
{
  static const struct { const char* mp_value; const char* mp_kept; } cases[] = {
    { "addPeriod",                "add period"                 },
    { "autoRenewPeriod",          "auto renew period"          },
    { "clientDeleteProhibited",   "client delete prohibited"   },
    { "clientHold",               "client hold"                },
    { "clientRenewProhibited",    "client renew prohibited"    },
    { "clientTransferProhibited", "client transfer prohibited" },
    { "clientUpdateProhibited",   "client update prohibited"   },
    { "inactive",                 "inactive"                   },
    { "ok https://icann.org/epp#ok", "active"                  },
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
    { "transferPeriod\thttps://icann.org/epp#transferPeriod", "transfer period" },
    { "OK",                       "active"                     },
    { "okay",                     "okay"                       },
    { "Transfer Locked",          "Transfer Locked"            },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    RdapRegistration_t registration;
    TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Domain Status", cases[i].mp_value, &registration));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, registration.m_statusCount, cases[i].mp_value);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_kept, registration.ma_statuses[0], cases[i].mp_value);
  }
}

void test_readAnswer_status_bounds(void)
{
  char text[4096];
  char long_status[RDAP_STATUS_MAX_LEN + 2];
  memset(long_status, 's', sizeof(long_status) - 1);
  long_status[sizeof(long_status) - 1] = '\0';
  RdapRegistration_t registration;

  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Domain Status", long_status, &registration));
  TEST_ASSERT_EQUAL_INT(0, registration.m_statusCount);
  long_status[RDAP_STATUS_MAX_LEN] = '\0';
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Domain Status", long_status, &registration));
  TEST_ASSERT_EQUAL_INT(1, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING(long_status, registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Domain Status", "", &registration));
  TEST_ASSERT_EQUAL_INT(0, registration.m_statusCount);

  size_t len = (size_t)snprintf(text, sizeof(text), "Domain Name: example.io\n");
  for (int i = 0; i <= RDAP_STATUS_MAX_COUNT; i++)
    len += (size_t)snprintf(text + len, sizeof(text) - len, "Domain Status: status %02d\n", i);
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read(text, "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_INT(RDAP_STATUS_MAX_COUNT + 1, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING("status 00", registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_STRING("status 15", registration.ma_statuses[RDAP_STATUS_MAX_COUNT - 1]);
}

void test_readAnswer_name_server_rules_and_bounds(void)
{
  static const struct { const char* mp_value; const char* mp_kept; } cases[] = {
    { "NS1.EXAMPLE.NET.",              "ns1.example.net" },
    { "ns1.example.net 192.0.2.1",     "ns1.example.net" },
    { "ns1.example.net\t2001:db8::1",  "ns1.example.net" },
    { "ns1.example.net (192.0.2.1)",   "ns1.example.net" },
    { "ns_1.example.net",              NULL              },
    { "-ns.example.net",               NULL              },
    { ".",                             NULL              },
    { "",                              NULL              },
  };
  RdapRegistration_t registration;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Name Server", cases[i].mp_value, &registration));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].mp_kept != NULL ? 1 : 0, registration.m_nameServerCount, cases[i].mp_value);
    if (cases[i].mp_kept != NULL)
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_kept, registration.ma_nameServers[0], cases[i].mp_value);
  }

  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 2];
  for (size_t i = 0; i < sizeof(name) - 1; i++)
    name[i] = (i % 50 == 49) ? '.' : 'n';
  name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  TEST_ASSERT_TRUE(validate_domainName(name));
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Name Server", name, &registration));
  TEST_ASSERT_EQUAL_INT(1, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING(name, registration.ma_nameServers[0]);
  name[VALIDATE_DOMAIN_NAME_MAX_LEN]     = 'n';
  name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = '\0';
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("Name Server", name, &registration));
  TEST_ASSERT_EQUAL_INT(0, registration.m_nameServerCount);

  char text[4096];
  size_t len = (size_t)snprintf(text, sizeof(text), "Domain Name: example.io\n");
  for (int i = 0; i <= RDAP_NAME_SERVER_MAX_COUNT; i++)
    len += (size_t)snprintf(text + len, sizeof(text) - len, "Name Server: ns%02d.example.net\n", i);
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read(text, "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_INT(RDAP_NAME_SERVER_MAX_COUNT + 1, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns00.example.net", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_STRING("ns15.example.net", registration.ma_nameServers[RDAP_NAME_SERVER_MAX_COUNT - 1]);
}

void test_readAnswer_name_server_block_ends_at_a_blank_line_or_a_key(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain name: example.am\nDNS servers:\n ns1.example.am\n\n not.a.name.server\n", "example.am", "am", &registration));
  TEST_ASSERT_EQUAL_INT(1, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns1.example.am", registration.ma_nameServers[0]);

  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain name: example.am\nDNS servers:\n ns1.example.am\nRegistered: 1999-06-05\n not.a.name.server\n", "example.am", "am", &registration));
  TEST_ASSERT_EQUAL_INT(1, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("1999-06-05", registration.ma_createdAt);

  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain name: example.am\n not.a.name.server\n", "example.am", "am", &registration));
  TEST_ASSERT_EQUAL_INT(0, registration.m_nameServerCount);

  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain name: example.am\nDNS servers:\n ns1.example.am\n \n not.a.name.server\n", "example.am", "am", &registration));
  TEST_ASSERT_EQUAL_INT(1, registration.m_nameServerCount);
}

void test_readAnswer_trims_blanks_and_matches_whole_keys(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("\rDomain Name: example.io\n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain Name: example.io \nRegistrar: Space Registrar  \n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_STRING("Space Registrar", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain Name: example.io\nRegistrar:\tTab Registrar\t\n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_STRING("Tab Registrar", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain Name: example.io\nRegistrar \t: Padded Registrar\n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_STRING("Padded Registrar", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_read("Domain Name: example.io\nCreation: 2001-01-01\n", "example.io", "io", &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_createdAt);
}

void test_readAnswer_hash_line_is_a_comment(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_NOT_REGISTERED, static_read("# comment\n#\n% another\n", "example.il", "il", &registration));
}

void test_readAnswer_reads_each_dnssec_value(void)
{
  static const struct { const char* mp_value; RdapDelegationSigned_t m_signed; } cases[] = {
    { "signedDelegation",     RDAP_DELEGATION_SIGNED_YES     },
    { "SIGNEDDELEGATION",     RDAP_DELEGATION_SIGNED_YES     },
    { "Signed delegation",    RDAP_DELEGATION_SIGNED_YES     },
    { "SIGNED",               RDAP_DELEGATION_SIGNED_YES     },
    { "unsigned",             RDAP_DELEGATION_SIGNED_NO      },
    { "UnSigned",             RDAP_DELEGATION_SIGNED_NO      },
    { "Unsigned Delegation",  RDAP_DELEGATION_SIGNED_NO      },
    { "yes",                  RDAP_DELEGATION_SIGNED_UNKNOWN },
    { "signedDelegationX",    RDAP_DELEGATION_SIGNED_UNKNOWN },
    { "Signed delegationX",   RDAP_DELEGATION_SIGNED_UNKNOWN },
    { "unsignedX",            RDAP_DELEGATION_SIGNED_UNKNOWN },
    { "Unsigned DelegationX", RDAP_DELEGATION_SIGNED_UNKNOWN },
    { "",                     RDAP_DELEGATION_SIGNED_UNKNOWN },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    RdapRegistration_t registration;
    TEST_ASSERT_EQUAL_INT(WHOIS_OK, static_readOneValue("DNSSEC", cases[i].mp_value, &registration));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_signed, registration.m_delegationSigned, cases[i].mp_value);
  }
}

typedef enum {
  FAKE_CONNECT_NOW,
  FAKE_CONNECT_REFUSED,
  FAKE_CONNECT_PENDING,
  FAKE_CONNECT_LATE,
  FAKE_CONNECT_LATE_REFUSED,
} FakeConnect_t;

typedef enum {
  FAKE_SERVER_ANSWERS,
  FAKE_SERVER_STALLS,
  FAKE_SERVER_RESETS,
} FakeServer_t;

typedef enum {
  FAKE_SEND_WHOLE,
  FAKE_SEND_ONE_BYTE,
  FAKE_SEND_FAILS_ONCE,
  FAKE_SEND_BLOCKED,
} FakeSend_t;

#define FAKE_MAX_BLOCKED_SEND_COUNT 1000

#define FAKE_MAX_ADDRESS_COUNT 4
#define FAKE_MAX_CONNECT_COUNT 8

static int64_t       g_nowMs;
static const char*   g_addresses[2][FAKE_MAX_ADDRESS_COUNT + 1];
static int           g_askCount;
static char          g_askNames[2][256];
static DnsRecordType_t g_askTypes[2];
static int           g_askDeadlineMs;
static int64_t       g_askAdvanceMs;
static FakeConnect_t g_connects[FAKE_MAX_CONNECT_COUNT];
static int           g_connectCount;
static unsigned short g_connectPorts[FAKE_MAX_CONNECT_COUNT];
static int           g_connectFamilies[FAKE_MAX_CONNECT_COUNT];
static int           g_socketCount;
static int           g_closeCount;
static FakeServer_t  g_server;
static const char*   g_answer;
static size_t        g_answerLen;
static int           g_peerFd = -1;
static int           g_clientFd = -1;
static char          g_query[512];
static size_t        g_queryLen;
static bool          g_isMallocFailing;
static FakeSend_t    g_sendMode;
static int           g_sendCount;
static bool          g_isPollFailingOnce;
static size_t        g_bzeroLen;
static int           g_bzeroCount;

int     __real_socket(int domain, int type, int protocol);
int     __real_close(int fd);
int     __real_poll(struct pollfd* fds, nfds_t nfds, int timeout);
ssize_t __real_send(int fd, const void* buf, size_t len, int flags);
void*   __real_malloc(size_t size);
void    __real_explicit_bzero(void* s, size_t n);

int64_t __wrap_monotonic_nowMs(void)
{
  return g_nowMs;
}

void __wrap_dns_askQuestions(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out)
{
  g_askCount++;
  g_nowMs += g_askAdvanceMs;
  g_askAdvanceMs = 0;
  g_askDeadlineMs = deadline_ms;
  for (int i = 0; i < question_count && i < 2; i++)
  {
    snprintf(g_askNames[i], sizeof(g_askNames[i]), "%s", questions[i].mp_domainName);
    g_askTypes[i] = questions[i].m_type;
    DnsAnswer_t* answer = &answers_out[i];
    memset(answer, 0, sizeof(*answer));
    int address_count = 0;
    while (address_count < FAKE_MAX_ADDRESS_COUNT && g_addresses[i][address_count] != NULL)
      address_count++;
    if (address_count == 0)
      continue;
    answer->mp_texts = calloc((size_t)address_count, sizeof(DnsRecordText_t));
    for (int record = 0; record < address_count; record++)
    {
      answer->mp_texts[record].mp_bytes    = strdup(g_addresses[i][record]);
      answer->mp_texts[record].m_byteCount = strlen(g_addresses[i][record]);
    }
    answer->m_recordCount = address_count;
  }
}

int __wrap_socket(int domain, int type, int protocol)
{
  (void)domain;
  (void)type;
  (void)protocol;
  g_socketCount++;
  int pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0)
    return -1;
  fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK);
  if (g_peerFd >= 0)
    __real_close(g_peerFd);
  g_clientFd = pair[0];
  g_peerFd   = pair[1];
  return pair[0];
}

int __wrap_connect(int fd, const struct sockaddr* address, socklen_t address_len)
{
  (void)fd;
  (void)address_len;
  int index = g_connectCount++;
  if (index >= FAKE_MAX_CONNECT_COUNT)
  {
    errno = ECONNREFUSED;
    return -1;
  }
  g_connectFamilies[index] = address->sa_family;
  g_connectPorts[index]    = address->sa_family == AF_INET ? ntohs(((const struct sockaddr_in*)address)->sin_port)
                                                           : ntohs(((const struct sockaddr_in6*)address)->sin6_port);
  switch (g_connects[index])
  {
    case FAKE_CONNECT_NOW:
      break;
    case FAKE_CONNECT_REFUSED:
      errno = ECONNREFUSED;
      return -1;
    case FAKE_CONNECT_PENDING:
    case FAKE_CONNECT_LATE:
    case FAKE_CONNECT_LATE_REFUSED:
      errno = EINPROGRESS;
      return -1;
  }

  if (g_answerLen > 0)
    __real_send(g_peerFd, g_answer, g_answerLen, MSG_NOSIGNAL);
  if (g_server == FAKE_SERVER_ANSWERS)
    shutdown(g_peerFd, SHUT_WR);
  return 0;
}

int __wrap_getsockopt(int fd, int level, int name, void* value, socklen_t* value_len)
{
  (void)fd;
  (void)level;
  (void)name;
  int index = g_connectCount - 1;
  bool is_refused = index >= 0 && index < FAKE_MAX_CONNECT_COUNT && g_connects[index] == FAKE_CONNECT_LATE_REFUSED;
  *(int*)value = is_refused ? ECONNREFUSED : 0;
  *value_len   = sizeof(int);
  if (is_refused)
    return 0;
  if (g_answerLen > 0)
    __real_send(g_peerFd, g_answer, g_answerLen, MSG_NOSIGNAL);
  if (g_server == FAKE_SERVER_ANSWERS)
    shutdown(g_peerFd, SHUT_WR);
  return 0;
}

int __wrap_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
  if (g_isPollFailingOnce)
  {
    g_isPollFailingOnce = false;
    errno = EBADF;
    return -1;
  }
  if (nfds == 1 && (fds[0].events & POLLOUT) != 0 && g_sendMode == FAKE_SEND_BLOCKED)
  {
    g_nowMs += timeout;
    return 0;
  }
  int index = g_connectCount - 1;
  if (nfds == 1 && (fds[0].events & POLLOUT) != 0 && index >= 0 && index < FAKE_MAX_CONNECT_COUNT && g_connects[index] == FAKE_CONNECT_PENDING)
  {
    g_nowMs += timeout;
    return 0;
  }
  if (nfds == 1 && (fds[0].events & POLLIN) != 0 && g_server == FAKE_SERVER_RESETS && g_peerFd >= 0)
  {
    __real_close(g_peerFd);
    g_peerFd = -1;
  }

  int ready_count = __real_poll(fds, nfds, 0);
  if (ready_count == 0)
    g_nowMs += timeout;
  return ready_count;
}

int __wrap___poll_chk(struct pollfd* fds, nfds_t nfds, int timeout, size_t fds_len)
{
  (void)fds_len;
  return __wrap_poll(fds, nfds, timeout);
}

ssize_t __wrap_send(int fd, const void* buf, size_t len, int flags)
{
  g_sendCount++;
  switch (g_sendMode)
  {
    case FAKE_SEND_WHOLE:
      break;
    case FAKE_SEND_ONE_BYTE:
      return __real_send(fd, buf, len > 0 ? 1 : 0, flags);
    case FAKE_SEND_FAILS_ONCE:
      if (g_sendCount == 1)
      {
        errno = EPIPE;
        return -1;
      }
      break;
    case FAKE_SEND_BLOCKED:
      errno = g_sendCount < FAKE_MAX_BLOCKED_SEND_COUNT ? EAGAIN : EPIPE;
      return -1;
  }
  return __real_send(fd, buf, len, flags);
}

int __wrap_close(int fd)
{
  if (fd == g_clientFd && g_peerFd >= 0)
  {
    ssize_t read_count = recv(g_peerFd, g_query, sizeof(g_query) - 1, MSG_DONTWAIT);
    g_queryLen = read_count > 0 ? (size_t)read_count : 0;
    g_query[g_queryLen] = '\0';
  }
  if (fd == g_clientFd)
  {
    g_closeCount++;
    g_clientFd = -1;
  }
  return __real_close(fd);
}

void* __wrap_malloc(size_t size)
{
  if (g_isMallocFailing && size == WHOIS_MAX_ANSWER_BYTE_COUNT + 1)
    return NULL;
  return __real_malloc(size);
}

void __wrap_explicit_bzero(void* s, size_t n)
{
  g_bzeroCount++;
  g_bzeroLen = n;
  __real_explicit_bzero(s, n);
}

void __wrap___explicit_bzero_chk(void* s, size_t n, size_t s_len)
{
  (void)s_len;
  __wrap_explicit_bzero(s, n);
}

static void static_answer(const char* text, size_t text_len, FakeServer_t server)
{
  g_answer    = text;
  g_answerLen = text_len;
  g_server    = server;
}

void setUp(void)
{
  g_nowMs = 1000000;
  memset(g_addresses, 0, sizeof(g_addresses));
  g_addresses[0][0] = "8.8.8.8";
  g_askCount        = 0;
  memset(g_askNames, 0, sizeof(g_askNames));
  g_askDeadlineMs   = 0;
  g_askAdvanceMs    = 0;
  memset(g_connects, 0, sizeof(g_connects));
  g_connectCount    = 0;
  memset(g_connectPorts, 0, sizeof(g_connectPorts));
  g_socketCount     = 0;
  g_closeCount      = 0;
  g_query[0]        = '\0';
  g_queryLen        = 0;
  g_isMallocFailing = false;
  g_sendMode        = FAKE_SEND_WHOLE;
  g_sendCount       = 0;
  g_isPollFailingOnce = false;
  g_bzeroLen        = 0;
  g_bzeroCount      = 0;
  static_answer(ICANN_ANSWER, strlen(ICANN_ANSWER), FAKE_SERVER_ANSWERS);
}

void tearDown(void)
{
  if (g_peerFd >= 0)
    __real_close(g_peerFd);
  g_peerFd = -1;
}

void test_lookupDomain_sends_the_name_and_reads_the_answer(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_STRING("Example Registrar Inc.", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_STRING("2013-03-08T19:12:48Z", registration.ma_createdAt);

  TEST_ASSERT_EQUAL_INT(1, g_askCount);
  TEST_ASSERT_EQUAL_STRING("whois.nic.io", g_askNames[0]);
  TEST_ASSERT_EQUAL_STRING("whois.nic.io", g_askNames[1]);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_A, g_askTypes[0]);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_AAAA, g_askTypes[1]);
  TEST_ASSERT_EQUAL_INT(WHOIS_RESOLVE_DEADLINE_MS, g_askDeadlineMs);
  TEST_ASSERT_EQUAL_INT(1, g_connectCount);
  TEST_ASSERT_EQUAL_INT(AF_INET, g_connectFamilies[0]);
  TEST_ASSERT_EQUAL_UINT(WHOIS_PORT, g_connectPorts[0]);
  TEST_ASSERT_EQUAL_UINT(43, WHOIS_PORT);
  TEST_ASSERT_EQUAL_STRING("example.io\r\n", g_query);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  TEST_ASSERT_EQUAL_INT(1, g_bzeroCount);
  TEST_ASSERT_EQUAL_size_t(strlen(ICANN_ANSWER), g_bzeroLen);
}

void test_lookupDomain_refuses_a_name_before_any_lookup(void)
{
  static const char* const names[] = { "example.io\r\nother.io", "exa mple.io", "", "-example.io" };
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  {
    RdapRegistration_t registration;
    TEST_ASSERT_EQUAL_INT_MESSAGE(WHOIS_INVALID_NAME, whois_lookupDomain(names[i], static_server("io"), &registration), names[i]);
    static_assertCleared(&registration);
  }
  TEST_ASSERT_EQUAL_INT(0, g_askCount);
  TEST_ASSERT_EQUAL_INT(0, g_socketCount);
}

void test_lookupDomain_skips_an_address_that_is_not_globally_reachable(void)
{
  g_addresses[0][0] = "127.0.0.1";
  g_addresses[0][1] = "10.0.0.1";
  g_addresses[1][0] = "::1";
  g_addresses[1][1] = "2001:4860:4860::8888";
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(1, g_connectCount);
  TEST_ASSERT_EQUAL_INT(AF_INET6, g_connectFamilies[0]);
  TEST_ASSERT_EQUAL_UINT(WHOIS_PORT, g_connectPorts[0]);

  setUp();
  g_addresses[0][0] = "127.0.0.1";
  g_addresses[1][0] = "fe80::1";
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(0, g_connectCount);
  TEST_ASSERT_EQUAL_INT(0, g_socketCount);
}

void test_lookupDomain_tries_the_next_address_after_a_refusal(void)
{
  g_addresses[0][1] = "8.8.4.4";
  g_connects[0]     = FAKE_CONNECT_REFUSED;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(2, g_connectCount);
  TEST_ASSERT_EQUAL_INT(2, g_closeCount);
  TEST_ASSERT_EQUAL_STRING("example.io\r\n", g_query);

  setUp();
  g_addresses[0][0] = NULL;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(0, g_connectCount);
}

void test_lookupDomain_bounds_each_connection_and_the_whole_lookup(void)
{
  g_connects[0] = FAKE_CONNECT_LATE;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(1, g_connectCount);
  TEST_ASSERT_EQUAL_STRING("example.io\r\n", g_query);

  setUp();
  g_addresses[0][1] = "8.8.4.4";
  g_connects[0]     = FAKE_CONNECT_PENDING;
  int64_t start_ms  = g_nowMs;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(2, g_connectCount);
  TEST_ASSERT_EQUAL_INT64(start_ms + WHOIS_CONNECT_DEADLINE_MS, g_nowMs);

  setUp();
  g_addresses[0][1] = "8.8.4.4";
  g_addresses[0][2] = "1.1.1.1";
  g_addresses[0][3] = "1.0.0.1";
  for (int i = 0; i < 4; i++)
    g_connects[i] = FAKE_CONNECT_PENDING;
  start_ms = g_nowMs;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(3, g_connectCount);
  TEST_ASSERT_EQUAL_INT64(start_ms + WHOIS_DEADLINE_MS, g_nowMs);
  TEST_ASSERT_EQUAL_INT(5000, WHOIS_DEADLINE_MS);
  TEST_ASSERT_EQUAL_INT(2000, WHOIS_CONNECT_DEADLINE_MS);
  TEST_ASSERT_EQUAL_INT(2000, WHOIS_RESOLVE_DEADLINE_MS);
}

void test_lookupDomain_deadline_counts_the_name_lookup(void)
{
  g_askAdvanceMs = 4000;
  g_connects[0]  = FAKE_CONNECT_PENDING;
  int64_t start_ms = g_nowMs;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT64(start_ms + WHOIS_DEADLINE_MS, g_nowMs);
}

void test_lookupDomain_server_that_never_closes_is_an_upstream_error(void)
{
  static_answer(ICANN_ANSWER, strlen(ICANN_ANSWER), FAKE_SERVER_STALLS);
  int64_t start_ms = g_nowMs;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  static_assertCleared(&registration);
  TEST_ASSERT_EQUAL_INT64(start_ms + WHOIS_DEADLINE_MS, g_nowMs);
  TEST_ASSERT_EQUAL_INT(1, g_bzeroCount);
  TEST_ASSERT_EQUAL_size_t(strlen(ICANN_ANSWER), g_bzeroLen);
}

void test_lookupDomain_connection_that_finishes_with_an_error_tries_the_next_address(void)
{
  g_addresses[0][1] = "8.8.4.4";
  g_connects[0]     = FAKE_CONNECT_LATE_REFUSED;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(2, g_connectCount);
  TEST_ASSERT_EQUAL_STRING("example.io\r\n", g_query);
}

void test_lookupDomain_sends_the_whole_query_in_small_parts(void)
{
  g_sendMode = FAKE_SEND_ONE_BYTE;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_STRING("example.io\r\n", g_query);
  TEST_ASSERT_EQUAL_INT(12, g_sendCount);
}

void test_lookupDomain_failed_send_is_an_upstream_error(void)
{
  g_sendMode = FAKE_SEND_FAILS_ONCE;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(1, g_connectCount);
  TEST_ASSERT_EQUAL_INT(1, g_sendCount);
}

void test_lookupDomain_socket_that_takes_no_query_waits_until_the_deadline(void)
{
  g_sendMode = FAKE_SEND_BLOCKED;
  int64_t start_ms = g_nowMs;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT64(start_ms + WHOIS_DEADLINE_MS, g_nowMs);
  TEST_ASSERT_EQUAL_INT(0, g_sendCount);
}

void test_lookupDomain_failed_poll_is_an_upstream_error(void)
{
  g_isPollFailingOnce = true;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(0, g_sendCount);
}

void test_lookupDomain_reset_connection_is_an_upstream_error(void)
{
  static_answer(ICANN_ANSWER, strlen(ICANN_ANSWER), FAKE_SERVER_RESETS);
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  static_assertCleared(&registration);
}

void test_lookupDomain_failed_exchange_tries_no_other_address(void)
{
  g_addresses[0][1] = "8.8.4.4";
  static_answer(ICANN_ANSWER, strlen(ICANN_ANSWER), FAKE_SERVER_RESETS);
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_INT(1, g_connectCount);
}

void test_lookupDomain_answer_bound(void)
{
  static char text[WHOIS_MAX_ANSWER_BYTE_COUNT + 1];
  memset(text, '%', sizeof(text));
  static const char head[] = "Domain Name: example.io\nRegistrar: Bound Registrar\n";
  memcpy(text, head, sizeof(head) - 1);
  for (size_t i = sizeof(head) - 1 + 79; i < sizeof(text); i += 80)
    text[i] = '\n';

  static_answer(text, WHOIS_MAX_ANSWER_BYTE_COUNT, FAKE_SERVER_ANSWERS);
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_OK, whois_lookupDomain("example.io", static_server("io"), &registration));
  TEST_ASSERT_EQUAL_STRING("Bound Registrar", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_size_t(WHOIS_MAX_ANSWER_BYTE_COUNT, g_bzeroLen);

  setUp();
  static_answer(text, WHOIS_MAX_ANSWER_BYTE_COUNT + 1, FAKE_SERVER_ANSWERS);
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  static_assertCleared(&registration);
  TEST_ASSERT_EQUAL_size_t(WHOIS_MAX_ANSWER_BYTE_COUNT + 1, g_bzeroLen);
  TEST_ASSERT_EQUAL_INT(65536, WHOIS_MAX_ANSWER_BYTE_COUNT);
}

void test_lookupDomain_not_found_answer_is_not_registered(void)
{
  static const char text[] = "Domain not found.\r\n";
  static_answer(text, sizeof(text) - 1, FAKE_SERVER_ANSWERS);
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_NOT_REGISTERED, whois_lookupDomain("example.io", static_server("io"), &registration));
}

void test_lookupDomain_without_a_buffer_is_an_upstream_error(void)
{
  g_isMallocFailing = true;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(WHOIS_UPSTREAM_ERROR, whois_lookupDomain("example.io", static_server("io"), &registration));
  static_assertCleared(&registration);
  TEST_ASSERT_EQUAL_INT(0, g_socketCount);
  TEST_ASSERT_EQUAL_INT(0, g_bzeroCount);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_servers_are_sorted_lower_case_tlds_with_a_host_and_a_key_map);
  RUN_TEST(test_no_listed_tld_has_an_rdap_server);
  RUN_TEST(test_each_server_has_a_terms_snapshot);
  RUN_TEST(test_servers_that_share_a_host_share_its_key_map_and_not_found_text);
  RUN_TEST(test_findServer_reads_the_last_label_in_any_case);
  RUN_TEST(test_readAnswer_reads_every_field_of_an_icann_answer);
  RUN_TEST(test_readAnswer_reads_the_name_server_block_of_the_am_answer);
  RUN_TEST(test_readAnswer_reads_the_dk_answer);
  RUN_TEST(test_readAnswer_reads_the_day_first_dates_of_the_il_answer);
  RUN_TEST(test_readAnswer_keeps_the_domain_block_of_the_ls_answer);
  RUN_TEST(test_readAnswer_reads_the_tab_separated_lt_answer);
  RUN_TEST(test_readAnswer_reads_the_sponsoring_registrar_of_the_tc_answer);
  RUN_TEST(test_readAnswer_not_found_line_of_each_server_is_not_registered);
  RUN_TEST(test_readAnswer_not_found_line_after_fields_clears_them);
  RUN_TEST(test_readAnswer_without_the_domain_is_an_upstream_error);
  RUN_TEST(test_readAnswer_empty_domain_line_names_no_other_domain);
  RUN_TEST(test_readAnswer_compares_the_domain_and_the_keys_in_any_case);
  RUN_TEST(test_readAnswer_skips_a_line_with_a_nul_byte_and_reads_the_last_line);
  RUN_TEST(test_readAnswer_first_text_and_date_win);
  RUN_TEST(test_readAnswer_registrar_name_bounds);
  RUN_TEST(test_readAnswer_iana_id_needs_one_to_nine_digits);
  RUN_TEST(test_readAnswer_writes_each_date_form_as_rfc_3339);
  RUN_TEST(test_readAnswer_writes_each_epp_code_as_its_rdap_name);
  RUN_TEST(test_readAnswer_status_bounds);
  RUN_TEST(test_readAnswer_name_server_rules_and_bounds);
  RUN_TEST(test_readAnswer_name_server_block_ends_at_a_blank_line_or_a_key);
  RUN_TEST(test_readAnswer_trims_blanks_and_matches_whole_keys);
  RUN_TEST(test_readAnswer_hash_line_is_a_comment);
  RUN_TEST(test_readAnswer_reads_each_dnssec_value);
  RUN_TEST(test_lookupDomain_sends_the_name_and_reads_the_answer);
  RUN_TEST(test_lookupDomain_refuses_a_name_before_any_lookup);
  RUN_TEST(test_lookupDomain_skips_an_address_that_is_not_globally_reachable);
  RUN_TEST(test_lookupDomain_tries_the_next_address_after_a_refusal);
  RUN_TEST(test_lookupDomain_bounds_each_connection_and_the_whole_lookup);
  RUN_TEST(test_lookupDomain_deadline_counts_the_name_lookup);
  RUN_TEST(test_lookupDomain_server_that_never_closes_is_an_upstream_error);
  RUN_TEST(test_lookupDomain_connection_that_finishes_with_an_error_tries_the_next_address);
  RUN_TEST(test_lookupDomain_sends_the_whole_query_in_small_parts);
  RUN_TEST(test_lookupDomain_failed_send_is_an_upstream_error);
  RUN_TEST(test_lookupDomain_socket_that_takes_no_query_waits_until_the_deadline);
  RUN_TEST(test_lookupDomain_failed_poll_is_an_upstream_error);
  RUN_TEST(test_lookupDomain_reset_connection_is_an_upstream_error);
  RUN_TEST(test_lookupDomain_failed_exchange_tries_no_other_address);
  RUN_TEST(test_lookupDomain_answer_bound);
  RUN_TEST(test_lookupDomain_not_found_answer_is_not_registered);
  RUN_TEST(test_lookupDomain_without_a_buffer_is_an_upstream_error);
  return UNITY_END();
}
