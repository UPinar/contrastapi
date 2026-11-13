#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/un.h>

#include "unity/unity.h"
#include "ipguard.h"

void setUp(void)    {}
void tearDown(void) {}

void test_isGloballyReachableIp_reachable_ipv4_addresses(void)
{
  static const char* const reachable_addresses[] = {
    "1.0.0.0", "8.8.8.8", "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0",
    "126.255.255.255", "128.0.0.0", "169.253.255.255", "169.255.0.0", "172.15.255.255",
    "172.32.0.0", "191.255.255.255", "192.0.0.9", "192.0.0.10", "192.0.1.0", "192.0.1.255",
    "192.0.3.0", "192.88.99.1", "192.88.99.3", "192.167.255.255", "192.169.0.0", "198.17.255.255",
    "198.20.0.0",
    "198.51.99.255", "198.51.101.0", "203.0.112.255", "203.0.114.0", "223.255.255.255",
  };
  for (size_t i = 0; i < sizeof(reachable_addresses) / sizeof(reachable_addresses[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(ipguard_isGloballyReachableIp(reachable_addresses[i]), reachable_addresses[i]);
}

void test_isGloballyReachableIp_unreachable_ipv4_addresses(void)
{
  static const char* const unreachable_addresses[] = {
    "0.0.0.0", "0.1.2.3", "0.255.255.255", "10.0.0.0", "10.255.255.255", "100.64.0.0",
    "100.127.255.255", "127.0.0.0", "127.0.0.1", "127.255.255.255", "169.254.0.0",
    "169.254.255.255",
    "172.16.0.0", "172.31.255.255", "192.0.0.0", "192.0.0.8", "192.0.0.11", "192.0.0.255",
    "192.0.2.0", "192.0.2.255", "192.168.0.0", "192.168.255.255", "198.18.0.0",
    "198.19.255.255", "198.51.100.0", "198.51.100.255", "203.0.113.0", "203.0.113.255",
    "224.0.0.0", "239.255.255.255", "240.0.0.0", "255.255.255.255",
  };
  for (size_t i = 0; i < sizeof(unreachable_addresses) / sizeof(unreachable_addresses[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(ipguard_isGloballyReachableIp(unreachable_addresses[i]), unreachable_addresses[i]);
}

void test_isGloballyReachableIp_reachable_ipv6_addresses(void)
{
  static const char* const reachable_addresses[] = {
    "2000::", "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:200::", "2001:4860:4860::8888",
    "2A00:1450:4001::200E",
    "2001:1::1", "2001:1::2", "2001:3::", "2001:3:ffff:ffff:ffff:ffff:ffff:ffff",
    "2001:4:112::", "2001:4:112:ffff:ffff:ffff:ffff:ffff", "2001:20::",
    "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff", "2001:30::",
    "2001:3f:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
    "2001:db9::", "2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2003::",
    "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "3fff:1000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
  };
  for (size_t i = 0; i < sizeof(reachable_addresses) / sizeof(reachable_addresses[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(ipguard_isGloballyReachableIp(reachable_addresses[i]), reachable_addresses[i]);
}

void test_isGloballyReachableIp_unreachable_ipv6_addresses(void)
{
  static const char* const unreachable_addresses[] = {
    "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "4000::", "::", "::1", "::ffff:8.8.8.8",
    "::8.8.8.8", "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "fc00::1", "fdff::1",
    "fe80::1", "ff02::1", "2001::", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:1::",
    "2001:1::4",
    "2001:2::1", "2001:2:ffff:ffff:ffff:ffff:ffff:ffff", "2001:4::",
    "2001:4:111:ffff:ffff:ffff:ffff:ffff", "2001:4:113::", "2001:10::1",
    "2001:1f:ffff:ffff:ffff:ffff:ffff:ffff", "2001:40::", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
    "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2002::", "2002:808:808::1",
    "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
  };
  for (size_t i = 0; i < sizeof(unreachable_addresses) / sizeof(unreachable_addresses[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(ipguard_isGloballyReachableIp(unreachable_addresses[i]), unreachable_addresses[i]);
}

void test_isGloballyReachableIp_refuses_what_the_python_service_accepted(void)
{
  static const char* const unreachable_addresses[] = {
    "192.88.99.2", "fec0::1", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "3fff::",
    "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:4860:4860::8888%eth0",
  };
  for (size_t i = 0; i < sizeof(unreachable_addresses) / sizeof(unreachable_addresses[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(ipguard_isGloballyReachableIp(unreachable_addresses[i]), unreachable_addresses[i]);
}

void test_isGloballyReachableIp_accepts_what_the_python_service_refused(void)
{
  TEST_ASSERT_TRUE(ipguard_isGloballyReachableIp("2001:1::3"));
}

void test_isGloballyReachableIp_refuses_text_that_is_not_an_address(void)
{
  static const char* const refused_texts[] = {
    "", "08.8.8.8", "010.0.0.1", "1.2.3", "127.1", "0x7f.0.0.1", "2130706433", " 8.8.8.8",
    "8.8.8.8 ", "8.8.8.8.", "[2001:4860:4860::8888]", "%1", "::ffff:08.8.8.8", "00000::1",
    "1::2::3", "not-an-ip", "example.com",
  };
  for (size_t i = 0; i < sizeof(refused_texts) / sizeof(refused_texts[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(ipguard_isGloballyReachableIp(refused_texts[i]), refused_texts[i]);
}

void test_tryWriteCanonicalIp_writes_one_form_per_address(void)
{
  static const struct { const char* mp_text; const char* mp_canonical; } addresses[] = {
    { "8.8.8.8",                                       "8.8.8.8" },
    { "2606:4700:0000::1111",                          "2606:4700::1111" },
    { "2606:4700:0:0:0:0:0:1111",                      "2606:4700::1111" },
    { "2001:4860:4860:0:0:0:0:8888",                   "2001:4860:4860::8888" },
    { "2001:DB8::A",                                   "2001:db8::a" },
    { "::ffff:8.8.8.8",                                "::ffff:8.8.8.8" },
    { "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" },
    { "0:0:0:0:0:ffff:808:808",                        "::ffff:8.8.8.8" },
  };
  for (size_t i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i++)
  {
    char canonical[INET6_ADDRSTRLEN];
    memset(canonical, 'x', sizeof(canonical));
    TEST_ASSERT_TRUE_MESSAGE(ipguard_tryWriteCanonicalIp(addresses[i].mp_text, canonical), addresses[i].mp_text);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(addresses[i].mp_canonical, canonical, addresses[i].mp_text);
  }
  TEST_ASSERT_EQUAL_size_t(INET6_ADDRSTRLEN - 1, strlen("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"));

  static const char* const refused_texts[] = { "", "1.2.3.0/24", "2001:db8::/32", "1.2.3", "[::1]", "example.com" };
  for (size_t i = 0; i < sizeof(refused_texts) / sizeof(refused_texts[0]); i++)
  {
    char canonical[INET6_ADDRSTRLEN];
    TEST_ASSERT_FALSE_MESSAGE(ipguard_tryWriteCanonicalIp(refused_texts[i], canonical), refused_texts[i]);
  }
}

static void static_writeIpv4Sockaddr(struct sockaddr_in* address_out, const char* ip_text)
{
  memset(address_out, 0, sizeof(*address_out));
  address_out->sin_family = AF_INET;
  TEST_ASSERT_EQUAL_INT(1, inet_pton(AF_INET, ip_text, &address_out->sin_addr));
}

static void static_writeIpv6Sockaddr(struct sockaddr_in6* address_out, const char* ip_text, uint32_t scope_id)
{
  memset(address_out, 0, sizeof(*address_out));
  address_out->sin6_family   = AF_INET6;
  address_out->sin6_scope_id = scope_id;
  TEST_ASSERT_EQUAL_INT(1, inet_pton(AF_INET6, ip_text, &address_out->sin6_addr));
}

void test_isGloballyReachableSockaddr_ipv4(void)
{
  struct sockaddr_in address;
  static_writeIpv4Sockaddr(&address, "8.8.8.8");
  TEST_ASSERT_TRUE(ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&address, sizeof(address)));
  static_writeIpv4Sockaddr(&address, "10.0.0.1");
  TEST_ASSERT_FALSE(ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&address, sizeof(address)));
}

void test_isGloballyReachableSockaddr_ipv6(void)
{
  struct sockaddr_in6 address;
  static_writeIpv6Sockaddr(&address, "2001:4860:4860::8888", 0);
  TEST_ASSERT_TRUE(ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&address, sizeof(address)));
  static_writeIpv6Sockaddr(&address, "fe80::1", 0);
  TEST_ASSERT_FALSE(ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&address, sizeof(address)));
}

void test_isGloballyReachableSockaddr_ipv6_scope_id_invalid(void)
{
  struct sockaddr_in6 address;
  static_writeIpv6Sockaddr(&address, "2001:4860:4860::8888", 1);
  TEST_ASSERT_FALSE(ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&address, sizeof(address)));
}

void test_isGloballyReachableSockaddr_short_length_invalid(void)
{
  struct sockaddr_in  ipv4_address;
  struct sockaddr_in6 ipv6_address;
  static_writeIpv4Sockaddr(&ipv4_address, "8.8.8.8");
  static_writeIpv6Sockaddr(&ipv6_address, "2001:4860:4860::8888", 0);
  TEST_ASSERT_FALSE(ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&ipv4_address, sizeof(ipv4_address) - 1));
  TEST_ASSERT_FALSE(ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&ipv6_address, sizeof(ipv6_address) - 1));
  TEST_ASSERT_FALSE(ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&ipv6_address, sizeof(struct sockaddr_in)));
}

void test_isGloballyReachableSockaddr_other_family_invalid(void)
{
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, "\0\0\x08\x08\x08\x08", 6);
  TEST_ASSERT_FALSE(ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&address, sizeof(address)));
}

void test_isGloballyReachableSockaddr_null_invalid(void)
{
  TEST_ASSERT_FALSE(ipguard_isGloballyReachableSockaddr(NULL, sizeof(struct sockaddr_in6)));
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_isGloballyReachableIp_reachable_ipv4_addresses);
  RUN_TEST(test_isGloballyReachableIp_unreachable_ipv4_addresses);
  RUN_TEST(test_isGloballyReachableIp_reachable_ipv6_addresses);
  RUN_TEST(test_isGloballyReachableIp_unreachable_ipv6_addresses);
  RUN_TEST(test_isGloballyReachableIp_refuses_what_the_python_service_accepted);
  RUN_TEST(test_isGloballyReachableIp_accepts_what_the_python_service_refused);
  RUN_TEST(test_isGloballyReachableIp_refuses_text_that_is_not_an_address);

  RUN_TEST(test_isGloballyReachableSockaddr_ipv4);
  RUN_TEST(test_isGloballyReachableSockaddr_ipv6);
  RUN_TEST(test_isGloballyReachableSockaddr_ipv6_scope_id_invalid);
  RUN_TEST(test_isGloballyReachableSockaddr_short_length_invalid);
  RUN_TEST(test_isGloballyReachableSockaddr_other_family_invalid);
  RUN_TEST(test_isGloballyReachableSockaddr_null_invalid);
  RUN_TEST(test_tryWriteCanonicalIp_writes_one_form_per_address);
  return UNITY_END();
}
