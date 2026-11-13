#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "unity/unity.h"
#include "keyvault.h"

#define SEALED_VECTOR_HEX "01cafebabefacedbaddecaf8889ee7e5a5ccb5b448aa1ea87d22871e5883d7162b83830b515240f03e0c034d5dee1a201f687d2d1d1e18f5f4d4f66539"

#define SEALED_EMPTY_HEX "01cafebabefacedbaddecaf8884b55ac958cea4d24e857844578409ffa"

#define SEALED_129_HEX "01cafebabefacedbaddecaf88894eeedaac2b8b84ba81fa87a24821a4399ce0e349d9e17424051ab64555b1203eb2d0e1f17ef82a77d98b550647b65f3ba94ec53c43f9dc260fcca5317bc6a6465b488208b21feaa2bb15e0b96bdbdea97bb9979afd5982ec9cd40abfa900d5b9482a5f0fd525aa7aba577d344ec2140cb94eef7b6c494227b1c21c640c94d9c199f06de9f90dab24a59fa2a72a804821d"

#define SEALED_VERSION_0_HEX "00cafebabefacedbaddecaf8889ee7e58452569c1aaff0a2a03bbb38ba05b96e"
#define SEALED_VERSION_2_HEX "02cafebabefacedbaddecaf8889ee7e58452569c1aaff0a2a03bbb38ba05b96e"

#define SEALED_UNSET_KEY_HEX "01cafebabefacedbaddecaf8884afc962b92cb501324da7d4986fd3ab484ec0c"

#define LINK_LOW       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define LINK_LOW_HASH  "6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b"
#define LINK_HIGH      "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
#define LINK_HIGH_HASH "5aff6ecf76db2f0a91619d938b755a4c516c90dae3833629cda3ecb4664fedec"

#define VECTOR_VENDOR_KEY "abcdefghijklmnopqrstuvwxyz012345"

static const unsigned char VECTOR_NONCE[] = {
  0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
};

static const unsigned char LINK_BYTES_LOW[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const unsigned char LINK_BYTES_HIGH[] = {
  0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

int             __real_RAND_bytes          (unsigned char* buf, int num);
EVP_CIPHER_CTX* __real_EVP_CIPHER_CTX_new  (void);
int             __real_EVP_Digest          (const void* data, size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, ENGINE* impl);

static const unsigned char* g_scriptedRandomBytes     = NULL;
static size_t               g_scriptedRandomByteCount = 0;
static bool                 g_isRandomFailing         = false;
static bool                 g_isCipherContextFailing  = false;
static bool                 g_isDigestFailing         = false;

int __wrap_RAND_bytes(unsigned char* buf, int num)
{
  if (g_isRandomFailing)
    return 0;
  if (g_scriptedRandomBytes == NULL)
    return __real_RAND_bytes(buf, num);

  TEST_ASSERT_EQUAL_INT((int)g_scriptedRandomByteCount, num);
  memcpy(buf, g_scriptedRandomBytes, (size_t)num);
  return 1;
}

EVP_CIPHER_CTX* __wrap_EVP_CIPHER_CTX_new(void)
{
  if (g_isCipherContextFailing)
    return NULL;
  return __real_EVP_CIPHER_CTX_new();
}

int __wrap_EVP_Digest(const void* data, size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, ENGINE* impl)
{
  if (g_isDigestFailing)
    return 0;
  return __real_EVP_Digest(data, count, md, size, type, impl);
}

void setUp(void)
{
  g_scriptedRandomBytes     = NULL;
  g_scriptedRandomByteCount = 0;
  g_isRandomFailing         = false;
  g_isCipherContextFailing  = false;
  g_isDigestFailing         = false;
}

void tearDown(void)
{
}

static KeyVaultMasterKey_t static_masterKey(unsigned char first_byte)
{
  KeyVaultMasterKey_t master_key;
  for (size_t i = 0; i < KEYVAULT_MASTER_KEY_BYTE_COUNT; i++)
    master_key.ma_key[i] = (unsigned char)(first_byte + i);
  return master_key;
}

static void static_setVectorMasterKey(void)
{
  KeyVaultMasterKey_t master_key = static_masterKey(0x00);
  TEST_ASSERT_TRUE(keyvault_trySetMasterKey(&master_key));
}

static void static_assertOutputCleared(const char* vendor_key, size_t vendor_key_len)
{
  TEST_ASSERT_EQUAL_size_t(0, vendor_key_len);
  for (size_t i = 0; i < KEYVAULT_VENDOR_KEY_MAX_LEN + 1; i++)
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, (unsigned char)vendor_key[i], "a refused open left a byte in its output");
}

void test_nothing_is_sealed_or_opened_before_the_master_key_is_set(void)
{
  char sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  memset(sealed_hex, 'X', sizeof(sealed_hex));
  TEST_ASSERT_FALSE(keyvault_trySeal(4242, "shodan", "abc", 3, sealed_hex));
  TEST_ASSERT_EQUAL_STRING("", sealed_hex);

  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 99;
  TEST_ASSERT_FALSE(keyvault_tryOpen(4242, "shodan", SEALED_VECTOR_HEX, vendor_key, &vendor_key_len));
  TEST_ASSERT_FALSE(keyvault_tryOpen(4242, "shodan", SEALED_UNSET_KEY_HEX, vendor_key, &vendor_key_len));

  char link[KEYVAULT_VENDOR_KEY_LINK_LEN + 1];
  TEST_ASSERT_TRUE(keyvault_tryWriteVendorKeyLink(link));
  TEST_ASSERT_EQUAL_size_t(KEYVAULT_VENDOR_KEY_LINK_LEN, strlen(link));

  char link_hash_hex[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 1];
  TEST_ASSERT_TRUE(keyvault_tryHashVendorKeyLink(LINK_LOW, link_hash_hex));
  TEST_ASSERT_EQUAL_STRING(LINK_LOW_HASH, link_hash_hex);
}

void test_seal_matches_an_independent_aes_256_gcm_vector(void)
{
  static_setVectorMasterKey();
  g_scriptedRandomBytes     = VECTOR_NONCE;
  g_scriptedRandomByteCount = sizeof(VECTOR_NONCE);

  char sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  TEST_ASSERT_TRUE(keyvault_trySeal(4242, "shodan", VECTOR_VENDOR_KEY, strlen(VECTOR_VENDOR_KEY), sealed_hex));

  TEST_ASSERT_EQUAL_STRING(SEALED_VECTOR_HEX, sealed_hex);
}

void test_open_reads_the_independent_vector(void)
{
  static_setVectorMasterKey();

  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 0;
  TEST_ASSERT_TRUE(keyvault_tryOpen(4242, "shodan", SEALED_VECTOR_HEX, vendor_key, &vendor_key_len));

  TEST_ASSERT_EQUAL_size_t(32, vendor_key_len);
  TEST_ASSERT_EQUAL_STRING(VECTOR_VENDOR_KEY, vendor_key);
}

void test_seal_takes_1_to_128_bytes(void)
{
  static_setVectorMasterKey();
  TEST_ASSERT_EQUAL_INT(128, KEYVAULT_VENDOR_KEY_MAX_LEN);

  char long_key[130];
  memset(long_key, 'k', sizeof(long_key));

  static const size_t lengths[] = { 1, 128 };
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
  {
    char sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
    TEST_ASSERT_TRUE(keyvault_trySeal(4242, "shodan", long_key, lengths[i], sealed_hex));
    TEST_ASSERT_EQUAL_size_t(2 * (1 + 12 + lengths[i] + 16), strlen(sealed_hex));

    char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
    size_t vendor_key_len = 0;
    TEST_ASSERT_TRUE(keyvault_tryOpen(4242, "shodan", sealed_hex, vendor_key, &vendor_key_len));
    TEST_ASSERT_EQUAL_size_t(lengths[i], vendor_key_len);
    TEST_ASSERT_EQUAL_MEMORY(long_key, vendor_key, lengths[i]);
    TEST_ASSERT_EQUAL_CHAR('\0', vendor_key[lengths[i]]);
  }

  static const size_t refused_lengths[] = { 0, 129 };
  for (size_t i = 0; i < sizeof(refused_lengths) / sizeof(refused_lengths[0]); i++)
  {
    char sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
    memset(sealed_hex, 'X', sizeof(sealed_hex));
    TEST_ASSERT_FALSE(keyvault_trySeal(4242, "shodan", long_key, refused_lengths[i], sealed_hex));
    TEST_ASSERT_EQUAL_STRING("", sealed_hex);
  }

  static const char* const refused_texts[] = { SEALED_EMPTY_HEX, SEALED_129_HEX };
  for (size_t i = 0; i < sizeof(refused_texts) / sizeof(refused_texts[0]); i++)
  {
    char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
    size_t vendor_key_len = 99;
    memset(vendor_key, 0xA5, sizeof(vendor_key));
    TEST_ASSERT_FALSE(keyvault_tryOpen(4242, "shodan", refused_texts[i], vendor_key, &vendor_key_len));
    static_assertOutputCleared(vendor_key, vendor_key_len);
  }
}

void test_two_seals_of_one_key_differ(void)
{
  static_setVectorMasterKey();

  char first_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  char second_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  TEST_ASSERT_TRUE(keyvault_trySeal(4242, "shodan", VECTOR_VENDOR_KEY, strlen(VECTOR_VENDOR_KEY), first_hex));
  TEST_ASSERT_TRUE(keyvault_trySeal(4242, "shodan", VECTOR_VENDOR_KEY, strlen(VECTOR_VENDOR_KEY), second_hex));

  TEST_ASSERT_TRUE(strcmp(first_hex, second_hex) != 0);

  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 0;
  TEST_ASSERT_TRUE(keyvault_tryOpen(4242, "shodan", second_hex, vendor_key, &vendor_key_len));
  TEST_ASSERT_EQUAL_STRING(VECTOR_VENDOR_KEY, vendor_key);
}

void test_open_refuses_each_changed_digit_and_clears_its_output(void)
{
  static_setVectorMasterKey();

  const size_t sealed_hex_len = strlen(SEALED_VECTOR_HEX);
  TEST_ASSERT_EQUAL_size_t(122, sealed_hex_len);
  for (size_t place = 0; place < sealed_hex_len; place++)
  {
    char changed_hex[sizeof(SEALED_VECTOR_HEX)];
    memcpy(changed_hex, SEALED_VECTOR_HEX, sizeof(SEALED_VECTOR_HEX));
    changed_hex[place] = changed_hex[place] == '0' ? '1' : '0';

    char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
    size_t vendor_key_len = 99;
    memset(vendor_key, 0xA5, sizeof(vendor_key));
    TEST_ASSERT_FALSE_MESSAGE(keyvault_tryOpen(4242, "shodan", changed_hex, vendor_key, &vendor_key_len),
                              "a sealed text with a changed digit opened");
    static_assertOutputCleared(vendor_key, vendor_key_len);
  }
}

void test_open_refuses_another_row_or_vendor(void)
{
  static_setVectorMasterKey();

  static const struct {
    int64_t     m_apiKeyId;
    const char* mp_vendorName;
  } cases[] = {
    { 4243, "shodan"    },
    { 4242, "abuseipdb" },
    { 4242, "shoda"     },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
    size_t vendor_key_len = 99;
    memset(vendor_key, 0xA5, sizeof(vendor_key));
    TEST_ASSERT_FALSE(keyvault_tryOpen(cases[i].m_apiKeyId, cases[i].mp_vendorName, SEALED_VECTOR_HEX, vendor_key, &vendor_key_len));
    static_assertOutputCleared(vendor_key, vendor_key_len);
  }
}

void test_open_refuses_a_malformed_text_or_another_format_version(void)
{
  static_setVectorMasterKey();

  char cut_hex[sizeof(SEALED_VECTOR_HEX)];
  memcpy(cut_hex, SEALED_VECTOR_HEX, sizeof(SEALED_VECTOR_HEX));
  cut_hex[sizeof(SEALED_VECTOR_HEX) - 2] = '\0';

  char last_g_hex[sizeof(SEALED_VECTOR_HEX)];
  memcpy(last_g_hex, SEALED_VECTOR_HEX, sizeof(SEALED_VECTOR_HEX));
  last_g_hex[sizeof(SEALED_VECTOR_HEX) - 2] = 'g';

  char first_x_hex[sizeof(SEALED_VECTOR_HEX)];
  memcpy(first_x_hex, SEALED_VECTOR_HEX, sizeof(SEALED_VECTOR_HEX));
  first_x_hex[0] = 'x';

  char long_hex[317];
  memset(long_hex, '0', 316);
  long_hex[316] = '\0';

  const char* const texts[] = { "", cut_hex, last_g_hex, first_x_hex, long_hex, SEALED_VERSION_0_HEX, SEALED_VERSION_2_HEX };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
  {
    char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
    size_t vendor_key_len = 99;
    memset(vendor_key, 0xA5, sizeof(vendor_key));
    TEST_ASSERT_FALSE(keyvault_tryOpen(4242, "shodan", texts[i], vendor_key, &vendor_key_len));
    static_assertOutputCleared(vendor_key, vendor_key_len);
  }
}

void test_seal_refuses_when_the_random_source_fails(void)
{
  static_setVectorMasterKey();
  g_isRandomFailing = true;

  char sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  memset(sealed_hex, 'X', sizeof(sealed_hex));
  TEST_ASSERT_FALSE(keyvault_trySeal(4242, "shodan", VECTOR_VENDOR_KEY, strlen(VECTOR_VENDOR_KEY), sealed_hex));
  TEST_ASSERT_EQUAL_STRING("", sealed_hex);
}

void test_seal_and_open_refuse_when_the_cipher_context_fails(void)
{
  static_setVectorMasterKey();
  g_isCipherContextFailing = true;

  char sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  memset(sealed_hex, 'X', sizeof(sealed_hex));
  TEST_ASSERT_FALSE(keyvault_trySeal(4242, "shodan", VECTOR_VENDOR_KEY, strlen(VECTOR_VENDOR_KEY), sealed_hex));
  TEST_ASSERT_EQUAL_STRING("", sealed_hex);

  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 99;
  memset(vendor_key, 0xA5, sizeof(vendor_key));
  TEST_ASSERT_FALSE(keyvault_tryOpen(4242, "shodan", SEALED_VECTOR_HEX, vendor_key, &vendor_key_len));
  static_assertOutputCleared(vendor_key, vendor_key_len);
}

void test_seal_and_open_take_row_ids_from_1(void)
{
  static_setVectorMasterKey();

  char row_1_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  TEST_ASSERT_TRUE(keyvault_trySeal(1, "shodan", VECTOR_VENDOR_KEY, strlen(VECTOR_VENDOR_KEY), row_1_hex));
  char   row_1_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t row_1_key_len = 0;
  TEST_ASSERT_TRUE(keyvault_tryOpen(1, "shodan", row_1_hex, row_1_key, &row_1_key_len));
  TEST_ASSERT_EQUAL_STRING(VECTOR_VENDOR_KEY, row_1_key);

  char sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  TEST_ASSERT_FALSE(keyvault_trySeal(0, "shodan", VECTOR_VENDOR_KEY, strlen(VECTOR_VENDOR_KEY), sealed_hex));
  TEST_ASSERT_FALSE(keyvault_trySeal(-1, "shodan", VECTOR_VENDOR_KEY, strlen(VECTOR_VENDOR_KEY), sealed_hex));

  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 99;
  memset(vendor_key, 0xA5, sizeof(vendor_key));
  TEST_ASSERT_FALSE(keyvault_tryOpen(0, "shodan", SEALED_VECTOR_HEX, vendor_key, &vendor_key_len));
  static_assertOutputCleared(vendor_key, vendor_key_len);
}

void test_another_master_key_opens_no_seal_of_the_old_one(void)
{
  KeyVaultMasterKey_t master_key = static_masterKey(0x20);
  TEST_ASSERT_TRUE(keyvault_trySetMasterKey(&master_key));

  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 99;
  memset(vendor_key, 0xA5, sizeof(vendor_key));
  TEST_ASSERT_FALSE(keyvault_tryOpen(4242, "shodan", SEALED_VECTOR_HEX, vendor_key, &vendor_key_len));
  static_assertOutputCleared(vendor_key, vendor_key_len);

  static_setVectorMasterKey();
  TEST_ASSERT_TRUE(keyvault_tryOpen(4242, "shodan", SEALED_VECTOR_HEX, vendor_key, &vendor_key_len));
  TEST_ASSERT_EQUAL_STRING(VECTOR_VENDOR_KEY, vendor_key);
}

void test_vendor_key_link_is_the_random_bytes_as_64_lower_case_hex_digits(void)
{
  TEST_ASSERT_EQUAL_INT(64, KEYVAULT_VENDOR_KEY_LINK_LEN);

  static const struct {
    const unsigned char* mp_bytes;
    const char*          mp_link;
  } cases[] = {
    { LINK_BYTES_LOW,  LINK_LOW  },
    { LINK_BYTES_HIGH, LINK_HIGH },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_scriptedRandomBytes     = cases[i].mp_bytes;
    g_scriptedRandomByteCount = 32;

    char link[KEYVAULT_VENDOR_KEY_LINK_LEN + 2];
    memset(link, 'X', sizeof(link));
    TEST_ASSERT_TRUE(keyvault_tryWriteVendorKeyLink(link));
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_link, link);
    TEST_ASSERT_EQUAL_CHAR('X', link[KEYVAULT_VENDOR_KEY_LINK_LEN + 1]);
  }
}

void test_two_vendor_key_links_differ(void)
{
  char first_link[KEYVAULT_VENDOR_KEY_LINK_LEN + 1];
  char second_link[KEYVAULT_VENDOR_KEY_LINK_LEN + 1];
  TEST_ASSERT_TRUE(keyvault_tryWriteVendorKeyLink(first_link));
  TEST_ASSERT_TRUE(keyvault_tryWriteVendorKeyLink(second_link));

  char link_hash_hex[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 1];
  TEST_ASSERT_TRUE(keyvault_tryHashVendorKeyLink(first_link, link_hash_hex));
  TEST_ASSERT_TRUE(keyvault_tryHashVendorKeyLink(second_link, link_hash_hex));
  TEST_ASSERT_TRUE(strcmp(first_link, second_link) != 0);
}

void test_vendor_key_link_refuses_when_the_random_source_fails(void)
{
  g_isRandomFailing = true;

  char link[KEYVAULT_VENDOR_KEY_LINK_LEN + 1];
  memset(link, 'X', sizeof(link));
  TEST_ASSERT_FALSE(keyvault_tryWriteVendorKeyLink(link));
  TEST_ASSERT_EQUAL_STRING("", link);
}

void test_vendor_key_link_hash_is_the_sha256_of_the_link_text(void)
{
  TEST_ASSERT_EQUAL_INT(64, KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN);

  static const struct {
    const char* mp_link;
    const char* mp_hash;
  } cases[] = {
    { LINK_LOW,  LINK_LOW_HASH  },
    { LINK_HIGH, LINK_HIGH_HASH },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char link_hash_hex[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 2];
    memset(link_hash_hex, 'X', sizeof(link_hash_hex));
    TEST_ASSERT_TRUE(keyvault_tryHashVendorKeyLink(cases[i].mp_link, link_hash_hex));
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_hash, link_hash_hex);
    TEST_ASSERT_EQUAL_CHAR('X', link_hash_hex[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 1]);
  }
}

void test_vendor_key_link_hash_refuses_a_link_that_is_not_64_lower_case_hex_digits(void)
{
  static const struct {
    const char* mp_link;
    bool        m_isHashed;
  } cases[] = {
    { "00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",   false },
    { LINK_LOW "0",                                                       false },
    { "",                                                                 false },
    { "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",  false },
    { "g00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",  false },
    { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1g",  false },
    { "/00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",  false },
    { ":00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",  false },
    { "`00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",  false },
    { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1G",  false },
    { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e19",  true  },
    { "900102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",  true  },
    { "a00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e10",  true  },
    { "f00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1a",  true  },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char link_hash_hex[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 1];
    memset(link_hash_hex, 'X', sizeof(link_hash_hex));
    TEST_ASSERT_EQUAL_MESSAGE(cases[i].m_isHashed, keyvault_tryHashVendorKeyLink(cases[i].mp_link, link_hash_hex), cases[i].mp_link);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(cases[i].m_isHashed ? KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN : 0, strlen(link_hash_hex), cases[i].mp_link);
  }
}

void test_vendor_key_link_hash_refuses_when_the_digest_fails(void)
{
  g_isDigestFailing = true;

  char link_hash_hex[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 1];
  memset(link_hash_hex, 'X', sizeof(link_hash_hex));
  TEST_ASSERT_FALSE(keyvault_tryHashVendorKeyLink(LINK_LOW, link_hash_hex));
  TEST_ASSERT_EQUAL_STRING("", link_hash_hex);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(19, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_nothing_is_sealed_or_opened_before_the_master_key_is_set);
  RUN_TEST(test_seal_matches_an_independent_aes_256_gcm_vector);
  RUN_TEST(test_open_reads_the_independent_vector);
  RUN_TEST(test_seal_takes_1_to_128_bytes);
  RUN_TEST(test_two_seals_of_one_key_differ);
  RUN_TEST(test_open_refuses_each_changed_digit_and_clears_its_output);
  RUN_TEST(test_open_refuses_another_row_or_vendor);
  RUN_TEST(test_open_refuses_a_malformed_text_or_another_format_version);
  RUN_TEST(test_seal_refuses_when_the_random_source_fails);
  RUN_TEST(test_seal_and_open_refuse_when_the_cipher_context_fails);
  RUN_TEST(test_seal_and_open_take_row_ids_from_1);
  RUN_TEST(test_another_master_key_opens_no_seal_of_the_old_one);
  RUN_TEST(test_vendor_key_link_is_the_random_bytes_as_64_lower_case_hex_digits);
  RUN_TEST(test_two_vendor_key_links_differ);
  RUN_TEST(test_vendor_key_link_refuses_when_the_random_source_fails);
  RUN_TEST(test_vendor_key_link_hash_is_the_sha256_of_the_link_text);
  RUN_TEST(test_vendor_key_link_hash_refuses_a_link_that_is_not_64_lower_case_hex_digits);
  RUN_TEST(test_vendor_key_link_hash_refuses_when_the_digest_fails);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
