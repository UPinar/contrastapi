#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity/unity.h"
#include "config.h"
#include "billing.h"
#include "keyvault.h"

#define MASTER_KEY_HEX "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

#define X402_VARIABLE_COUNT 6

static const char* const  X402_NAMES[X402_VARIABLE_COUNT] = {
  "CONTRASTAPI_X402_NETWORK",                /* gitleaks:allow */
  "CONTRASTAPI_X402_USDC_MINT",              /* gitleaks:allow */
  "CONTRASTAPI_X402_PAY_TO",
  "CONTRASTAPI_X402_PAY_TO_TOKEN_ACCOUNT",   /* gitleaks:allow */
  "CONTRASTAPI_X402_FEE_PAYER",
  "CONTRASTAPI_X402_SOLANA_RPC_URL",
};
static const char* const  X402_VALUES[X402_VARIABLE_COUNT] = {
  "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
  "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9",
  "https://rpc.example.com/v1/sample",
};
static const size_t       X402_BUF_SIZES[X402_VARIABLE_COUNT] = { 64, 48, 48, 48, 48, 512 };

static void static_setAllX402(void)
{
  for (size_t i = 0; i < X402_VARIABLE_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(0, setenv(X402_NAMES[i], X402_VALUES[i], 1));
}

static void static_unsetAllX402(void)
{
  for (size_t i = 0; i < X402_VARIABLE_COUNT; i++)
    unsetenv(X402_NAMES[i]);
}

static void static_assertX402Cleared(const ConfigX402_t* config)
{
  const unsigned char* bytes = (const unsigned char*)config;
  for (size_t i = 0; i < sizeof(*config); i++)
    TEST_ASSERT_EQUAL_HEX8(0x00, bytes[i]);
}

static void static_assertX402Refused(ConfigX402Status_t expected_status, const char* expected_name, const char* message)
{
  ConfigX402_t config;
  memset(&config, 0xA5, sizeof(config));
  const char* bad_name = "stale";
  TEST_ASSERT_EQUAL_INT_MESSAGE(expected_status, config_readX402(&config, &bad_name), message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(expected_name, bad_name, message);
  static_assertX402Cleared(&config);
}

static void static_writeLongValue(size_t i, size_t value_len, char* out)
{
  size_t usable_len = strlen(X402_VALUES[i]);
  TEST_ASSERT_TRUE(value_len >= usable_len);
  memcpy(out, X402_VALUES[i], usable_len);
  memset(out + usable_len, 'x', value_len - usable_len);
  out[value_len] = '\0';
}

void setUp(void)
{
  unsetenv("CONTRASTAPI_WORKER_THREAD_COUNT");
  unsetenv("CONTRASTAPI_UPSTREAM_THREAD_COUNT");
  unsetenv("CONTRASTAPI_RAW_BODY_THREAD_COUNT");
  unsetenv("CONTRASTAPI_IP_SECRET");
  unsetenv("CONTRASTAPI_LEMONSQUEEZY_WEBHOOK_SECRET");
  unsetenv("CONTRASTAPI_NOWPAYMENTS_IPN_SECRET");
  unsetenv("CONTRASTAPI_NOWPAYMENTS_API_KEY");
  unsetenv("CONTRASTAPI_USAGE_LOG_PATH");
  unsetenv("CONTRASTAPI_CERTSPOTTER_API_KEY");
  unsetenv("CONTRASTAPI_KEYVAULT_MASTER_KEY");
  static_unsetAllX402();
}

void tearDown(void)
{
  unsetenv("CONTRASTAPI_WORKER_THREAD_COUNT");
  unsetenv("CONTRASTAPI_UPSTREAM_THREAD_COUNT");
  unsetenv("CONTRASTAPI_RAW_BODY_THREAD_COUNT");
  unsetenv("CONTRASTAPI_IP_SECRET");
  unsetenv("CONTRASTAPI_LEMONSQUEEZY_WEBHOOK_SECRET");
  unsetenv("CONTRASTAPI_NOWPAYMENTS_IPN_SECRET");
  unsetenv("CONTRASTAPI_NOWPAYMENTS_API_KEY");
  unsetenv("CONTRASTAPI_USAGE_LOG_PATH");
  unsetenv("CONTRASTAPI_CERTSPOTTER_API_KEY");
  unsetenv("CONTRASTAPI_KEYVAULT_MASTER_KEY");
  static_unsetAllX402();
}

void test_port_is_a_whole_number_from_1_to_the_max(void)
{
  static const struct {
    const char* mp_text;
    int         m_port;
  } accepted[] = { { "1", 1 }, { "65535", CONFIG_MAX_PORT_NUMBER }, { "8080", 8080 }, { " 8080", 8080 }, { "8080 \n", 8080 }, { "+80", 80 } };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(accepted[i].m_port, config_readPortNumber(accepted[i].mp_text), accepted[i].mp_text);
  }

  static const char* const refused[] = { "0", "65536", "-1", "", " ", "abc", "8080abc", "80 x", "0x50", "99999999999999999999" };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, config_readPortNumber(refused[i]), refused[i]);
  }
}

void test_worker_thread_count_falls_back_to_the_default(void)
{
  TEST_ASSERT_EQUAL_INT(CONFIG_DEFAULT_WORKER_THREAD_COUNT, config_readWorkerThreadCount());
  TEST_ASSERT_EQUAL_INT(8, config_readWorkerThreadCount());

  static const struct {
    const char* mp_env;
    int         m_count;
  } cases[] = {
    { "4",   4 },
    { "1",   1 },
    { "512", CONFIG_MAX_WORKER_THREAD_COUNT },
    { "4\n", 4 },
    { "0",   CONFIG_DEFAULT_WORKER_THREAD_COUNT },
    { "513", CONFIG_DEFAULT_WORKER_THREAD_COUNT },
    { "abc", CONFIG_DEFAULT_WORKER_THREAD_COUNT },
    { "",    CONFIG_DEFAULT_WORKER_THREAD_COUNT },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_WORKER_THREAD_COUNT", cases[i].mp_env, 1));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_count, config_readWorkerThreadCount(), cases[i].mp_env);
  }
}

void test_upstream_thread_count_defaults_to_half_of_the_workers(void)
{
  TEST_ASSERT_EQUAL_INT(1, config_readUpstreamThreadCount(1));
  TEST_ASSERT_EQUAL_INT(1, config_readUpstreamThreadCount(2));
  TEST_ASSERT_EQUAL_INT(1, config_readUpstreamThreadCount(3));
  TEST_ASSERT_EQUAL_INT(4, config_readUpstreamThreadCount(8));
}

void test_upstream_thread_count_takes_0_to_the_worker_count(void)
{
  static const struct {
    const char* mp_env;
    int         m_count;
  } cases[] = {
    { "0",  0 },
    { "0 ", 0 },
    { "3",  3 },
    { "8",  8 },
    { "9",  4 },
    { "-1", 4 },
    { "abc", 4 },
    { "",   4 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_UPSTREAM_THREAD_COUNT", cases[i].mp_env, 1));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_count, config_readUpstreamThreadCount(8), cases[i].mp_env);
  }
}

void test_raw_body_thread_count_defaults_to_a_quarter_of_the_workers(void)
{
  TEST_ASSERT_EQUAL_INT(1,   config_readRawBodyThreadCount(1));
  TEST_ASSERT_EQUAL_INT(1,   config_readRawBodyThreadCount(3));
  TEST_ASSERT_EQUAL_INT(1,   config_readRawBodyThreadCount(4));
  TEST_ASSERT_EQUAL_INT(1,   config_readRawBodyThreadCount(7));
  TEST_ASSERT_EQUAL_INT(2,   config_readRawBodyThreadCount(8));
  TEST_ASSERT_EQUAL_INT(2,   config_readRawBodyThreadCount(9));
  TEST_ASSERT_EQUAL_INT(128, config_readRawBodyThreadCount(512));
}

void test_raw_body_thread_count_takes_0_to_the_worker_count(void)
{
  static const struct {
    const char* mp_env;
    int         m_count;
  } cases[] = {
    { "0",  0 },
    { "3 ", 3 },
    { "8",  8 },
    { "9",  2 },
    { "-1", 2 },
    { "abc", 2 },
    { "",   2 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_RAW_BODY_THREAD_COUNT", cases[i].mp_env, 1));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_count, config_readRawBodyThreadCount(8), cases[i].mp_env);
  }
}

void test_each_thread_count_reads_its_own_variable(void)
{
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_UPSTREAM_THREAD_COUNT", "5", 1));
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_RAW_BODY_THREAD_COUNT", "3", 1));
  TEST_ASSERT_EQUAL_INT(5, config_readUpstreamThreadCount(8));
  TEST_ASSERT_EQUAL_INT(3, config_readRawBodyThreadCount(8));
}

void test_ip_secret_unset_or_empty_is_refused(void)
{
  TEST_ASSERT_NULL(config_readIpSecret());

  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_IP_SECRET", "", 1));
  TEST_ASSERT_NULL(config_readIpSecret());
}

void test_ip_secret_needs_at_least_32_bytes(void)
{
  TEST_ASSERT_EQUAL_INT(32, CONFIG_MIN_IP_SECRET_LEN);

  char secret[65];
  memset(secret, 'a', 64);

  secret[31] = '\0';
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_IP_SECRET", secret, 1));
  TEST_ASSERT_NULL(config_readIpSecret());

  memset(secret, 'a', 64);
  secret[32] = '\0';
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_IP_SECRET", secret, 1));
  TEST_ASSERT_EQUAL_STRING(secret, config_readIpSecret());

  memset(secret, 'a', 64);
  secret[64] = '\0';
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_IP_SECRET", secret, 1));
  TEST_ASSERT_EQUAL_STRING(secret, config_readIpSecret());
}

void test_ip_secret_counts_a_trailing_space_and_keeps_it(void)
{
  static const char* const accepted[] = {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
  };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++)
  {
    TEST_ASSERT_EQUAL_size_t(32, strlen(accepted[i]));
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_IP_SECRET", accepted[i], 1));
    const char* ip_secret = config_readIpSecret();
    TEST_ASSERT_NOT_NULL(ip_secret);
    TEST_ASSERT_EQUAL_STRING(accepted[i], ip_secret);
  }

  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_IP_SECRET", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", 1));
  TEST_ASSERT_NULL(config_readIpSecret());
}

void test_ip_secret_length_counts_bytes_not_characters(void)
{
  char secret[40] = "";
  for (int i = 0; i < 16; i++)
    strcat(secret, "\xc3\xa9");
  TEST_ASSERT_EQUAL_size_t(32, strlen(secret));
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_IP_SECRET", secret, 1));
  TEST_ASSERT_EQUAL_STRING(secret, config_readIpSecret());

  secret[30] = 'a';
  secret[31] = '\0';
  TEST_ASSERT_EQUAL_size_t(31, strlen(secret));
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_IP_SECRET", secret, 1));
  TEST_ASSERT_NULL(config_readIpSecret());
}

void test_usage_log_path_unset_turns_the_log_off(void)
{
  const char* usage_log_path = "stale";
  TEST_ASSERT_EQUAL_INT(CONFIG_USAGE_LOG_OFF, config_readUsageLogPath(&usage_log_path));
  TEST_ASSERT_NULL(usage_log_path);
}

void test_usage_log_path_that_is_absolute_turns_the_log_on(void)
{
  static const char* const accepted[] = { "/var/log/contrastapi-usage/usage.jsonl", "/" };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_USAGE_LOG_PATH", accepted[i], 1));
    const char* usage_log_path = NULL;
    TEST_ASSERT_EQUAL_INT(CONFIG_USAGE_LOG_ON, config_readUsageLogPath(&usage_log_path));
    TEST_ASSERT_EQUAL_STRING(accepted[i], usage_log_path);
  }
}

void test_usage_log_path_that_is_not_absolute_is_refused(void)
{
  static const char* const refused[] = { "", "usage.jsonl", "./usage.jsonl", " /usage.jsonl" };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_USAGE_LOG_PATH", refused[i], 1));
    const char* usage_log_path = "stale";
    TEST_ASSERT_EQUAL_INT(CONFIG_USAGE_LOG_PATH_NOT_ABSOLUTE, config_readUsageLogPath(&usage_log_path));
    TEST_ASSERT_NULL(usage_log_path);
  }
}

void test_certspotter_api_key_unset_is_off(void)
{
  const char* api_key = "stale";
  TEST_ASSERT_EQUAL_INT(CONFIG_CERTSPOTTER_API_KEY_OFF, config_readCertSpotterApiKey(&api_key));
  TEST_ASSERT_NULL(api_key);
}

void test_certspotter_api_key_empty_is_refused(void)
{
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_CERTSPOTTER_API_KEY", "", 1));
  const char* api_key = "stale";
  TEST_ASSERT_EQUAL_INT(CONFIG_CERTSPOTTER_API_KEY_INVALID, config_readCertSpotterApiKey(&api_key));
  TEST_ASSERT_NULL(api_key);
}

void test_certspotter_api_key_may_hold_up_to_the_max_length(void)
{
  char key_text[CONFIG_CERTSPOTTER_API_KEY_MAX_LEN + 2];
  memset(key_text, 'k', sizeof(key_text) - 1);
  key_text[sizeof(key_text) - 1] = '\0';

  const char* api_key = "stale";
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_CERTSPOTTER_API_KEY", key_text, 1));
  TEST_ASSERT_EQUAL_INT(CONFIG_CERTSPOTTER_API_KEY_INVALID, config_readCertSpotterApiKey(&api_key));
  TEST_ASSERT_NULL(api_key);

  key_text[CONFIG_CERTSPOTTER_API_KEY_MAX_LEN] = '\0';
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_CERTSPOTTER_API_KEY", key_text, 1));
  TEST_ASSERT_EQUAL_INT(CONFIG_CERTSPOTTER_API_KEY_ON, config_readCertSpotterApiKey(&api_key));
  TEST_ASSERT_EQUAL_STRING(key_text, api_key);
}

void test_certspotter_api_key_holds_only_visible_ascii(void)
{
  static const char* const accepted[] = { "123_sampleapikey", "!", "~", "!azAZ09_-~" };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_CERTSPOTTER_API_KEY", accepted[i], 1));
    const char* api_key = NULL;
    TEST_ASSERT_EQUAL_INT(CONFIG_CERTSPOTTER_API_KEY_ON, config_readCertSpotterApiKey(&api_key));
    TEST_ASSERT_EQUAL_STRING(accepted[i], api_key);
  }

  static const char* const refused[] = { "123 key", "123\tkey", "123\rkey", "123\nX-Other: 1", "123\x7fkey", "123\xc3\xa7key", "key ",
                                         " key", "\tkey", "\r\nX-Other: 1", "\x7fkey", "\xc3\xa7key" };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_CERTSPOTTER_API_KEY", refused[i], 1));
    const char* api_key = "stale";
    TEST_ASSERT_EQUAL_INT(CONFIG_CERTSPOTTER_API_KEY_INVALID, config_readCertSpotterApiKey(&api_key));
    TEST_ASSERT_NULL(api_key);
  }
}

void test_lemonsqueezy_webhook_secret_needs_at_least_32_bytes(void)
{
  TEST_ASSERT_EQUAL_INT(32, BILLING_LEMONSQUEEZY_SECRET_MIN_LEN);
  TEST_ASSERT_NULL(config_readLemonSqueezyWebhookSecret());

  static const size_t lengths[]     = { 31, 32, 40 };
  static const bool   is_accepted[] = { false, true, true };
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
  {
    char secret[41];
    memset(secret, 'a', sizeof(secret));
    secret[lengths[i]] = '\0';
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_LEMONSQUEEZY_WEBHOOK_SECRET", secret, 1));
    if (is_accepted[i])
      TEST_ASSERT_EQUAL_STRING(secret, config_readLemonSqueezyWebhookSecret());
    else
      TEST_ASSERT_NULL(config_readLemonSqueezyWebhookSecret());
  }
}

static void static_assertMasterKeyCleared(const KeyVaultMasterKey_t* master_key)
{
  for (size_t i = 0; i < KEYVAULT_MASTER_KEY_BYTE_COUNT; i++)
    TEST_ASSERT_EQUAL_HEX8(0x00, master_key->ma_key[i]);
}

void test_keyvault_master_key_unset_is_off(void)
{
  KeyVaultMasterKey_t master_key;
  memset(&master_key, 0xA5, sizeof(master_key));

  TEST_ASSERT_EQUAL_INT(CONFIG_KEYVAULT_MASTER_KEY_OFF, config_readKeyVaultMasterKey(&master_key));
  static_assertMasterKeyCleared(&master_key);
}

void test_keyvault_master_key_reads_64_hex_digits_of_either_case(void)
{
  static const char* const texts[] = {
    MASTER_KEY_HEX,
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
  };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
  {
    setenv("CONTRASTAPI_KEYVAULT_MASTER_KEY", texts[i], 1);
    KeyVaultMasterKey_t master_key;
    memset(&master_key, 0xA5, sizeof(master_key));

    TEST_ASSERT_EQUAL_INT_MESSAGE(CONFIG_KEYVAULT_MASTER_KEY_ON, config_readKeyVaultMasterKey(&master_key), texts[i]);
    for (size_t b = 0; b < KEYVAULT_MASTER_KEY_BYTE_COUNT; b++)
      TEST_ASSERT_EQUAL_HEX8((unsigned char)b, master_key.ma_key[b]);
  }
}

void test_keyvault_master_key_refuses_any_other_form(void)
{
  static const char* const texts[] = {
    "",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1",
    MASTER_KEY_HEX "0",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1g",
    " " MASTER_KEY_HEX,
    MASTER_KEY_HEX "\n",
    "7:" MASTER_KEY_HEX,
  };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
  {
    setenv("CONTRASTAPI_KEYVAULT_MASTER_KEY", texts[i], 1);
    KeyVaultMasterKey_t master_key;
    memset(&master_key, 0xA5, sizeof(master_key));

    TEST_ASSERT_EQUAL_INT_MESSAGE(CONFIG_KEYVAULT_MASTER_KEY_INVALID, config_readKeyVaultMasterKey(&master_key), texts[i]);
    static_assertMasterKeyCleared(&master_key);
  }
}

void test_x402_all_unset_is_off(void)
{
  ConfigX402_t config;
  memset(&config, 0xA5, sizeof(config));
  const char* bad_name = "stale";
  TEST_ASSERT_EQUAL_INT(CONFIG_X402_OFF, config_readX402(&config, &bad_name));
  TEST_ASSERT_NULL(bad_name);
  static_assertX402Cleared(&config);
}

void test_x402_all_set_is_on_and_copies_each_value(void)
{
  static_setAllX402();
  ConfigX402_t config;
  memset(&config, 0xA5, sizeof(config));
  const char* bad_name = "stale";
  TEST_ASSERT_EQUAL_INT(CONFIG_X402_ON, config_readX402(&config, &bad_name));
  TEST_ASSERT_NULL(bad_name);
  static_unsetAllX402();

  TEST_ASSERT_EQUAL_STRING("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", config.ma_network);
  TEST_ASSERT_EQUAL_STRING("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", config.ma_usdcMint);
  TEST_ASSERT_EQUAL_STRING("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", config.ma_payTo);
  TEST_ASSERT_EQUAL_STRING("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", config.ma_payToTokenAccount);
  TEST_ASSERT_EQUAL_STRING("2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9", config.ma_feePayer);
  TEST_ASSERT_EQUAL_STRING("https://rpc.example.com/v1/sample", config.ma_solanaRpcUrl);
}

void test_x402_some_unset_is_partial_and_names_the_first_unset(void)
{
  for (size_t i = 0; i < X402_VARIABLE_COUNT; i++)
  {
    static_setAllX402();
    unsetenv(X402_NAMES[i]);
    static_assertX402Refused(CONFIG_X402_PARTIAL, X402_NAMES[i], X402_NAMES[i]);
  }

  static_unsetAllX402();
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_X402_NETWORK", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", 1));
  static_assertX402Refused(CONFIG_X402_PARTIAL, "CONTRASTAPI_X402_USDC_MINT", "only the network set");
}

void test_x402_partial_is_named_before_an_invalid_value(void)
{
  static_setAllX402();
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_X402_NETWORK", "", 1));
  unsetenv("CONTRASTAPI_X402_FEE_PAYER");
  static_assertX402Refused(CONFIG_X402_PARTIAL, "CONTRASTAPI_X402_FEE_PAYER", "empty network, fee payer unset");
}

void test_x402_empty_value_is_invalid(void)
{
  for (size_t i = 0; i < X402_VARIABLE_COUNT; i++)
  {
    static_setAllX402();
    TEST_ASSERT_EQUAL_INT(0, setenv(X402_NAMES[i], "", 1));
    static_assertX402Refused(CONFIG_X402_INVALID, X402_NAMES[i], X402_NAMES[i]);
  }
}

void test_x402_value_must_fit_its_buffer(void)
{
  for (size_t i = 0; i < X402_VARIABLE_COUNT; i++)
  {
    char long_value[512 + 1];
    static_setAllX402();
    static_writeLongValue(i, X402_BUF_SIZES[i], long_value);
    TEST_ASSERT_EQUAL_INT(0, setenv(X402_NAMES[i], long_value, 1));
    static_assertX402Refused(CONFIG_X402_INVALID, X402_NAMES[i], X402_NAMES[i]);

    static_writeLongValue(i, X402_BUF_SIZES[i] - 1, long_value);
    TEST_ASSERT_EQUAL_INT(0, setenv(X402_NAMES[i], long_value, 1));
    ConfigX402_t config;
    const char*  bad_name = "stale";
    TEST_ASSERT_EQUAL_INT_MESSAGE(CONFIG_X402_ON, config_readX402(&config, &bad_name), X402_NAMES[i]);
    TEST_ASSERT_NULL(bad_name);
    const char* const fields[X402_VARIABLE_COUNT] = { config.ma_network, config.ma_usdcMint, config.ma_payTo, config.ma_payToTokenAccount, config.ma_feePayer, config.ma_solanaRpcUrl };
    TEST_ASSERT_EQUAL_STRING_MESSAGE(long_value, fields[i], X402_NAMES[i]);
  }
}

void test_x402_byte_outside_visible_ascii_is_invalid(void)
{
  static const char* const suffixes[] = { "\x01", " ", "\t", "\nX", "\x7f", "\xc3\xa7" };
  for (size_t i = 0; i < X402_VARIABLE_COUNT; i++)
  {
    for (size_t k = 0; k < sizeof(suffixes) / sizeof(suffixes[0]); k++)
    {
      char value[128];
      snprintf(value, sizeof(value), "%.20s%s", X402_VALUES[i], suffixes[k]);
      static_setAllX402();
      TEST_ASSERT_EQUAL_INT(0, setenv(X402_NAMES[i], value, 1));
      static_assertX402Refused(CONFIG_X402_INVALID, X402_NAMES[i], X402_NAMES[i]);
    }
  }
}

void test_x402_rpc_url_must_start_with_https(void)
{
  static const char* const refused[] = { "http://rpc.example.com/", "HTTPS://rpc.example.com/", "https:/rpc.example.com/", "ftp://rpc.example.com/" };
  for (size_t k = 0; k < sizeof(refused) / sizeof(refused[0]); k++)
  {
    static_setAllX402();
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_X402_SOLANA_RPC_URL", refused[k], 1));
    static_assertX402Refused(CONFIG_X402_INVALID, "CONTRASTAPI_X402_SOLANA_RPC_URL", refused[k]);
  }

  static_setAllX402();
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_X402_SOLANA_RPC_URL", "https://", 1));
  ConfigX402_t config;
  const char*  bad_name = "stale";
  TEST_ASSERT_EQUAL_INT(CONFIG_X402_ON, config_readX402(&config, &bad_name));
  TEST_ASSERT_EQUAL_STRING("https://", config.ma_solanaRpcUrl);
}

void test_x402_invalid_names_the_first_bad_variable(void)
{
  static_setAllX402();
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_X402_PAY_TO", "", 1));
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_X402_SOLANA_RPC_URL", "http://rpc.example.com/", 1));
  static_assertX402Refused(CONFIG_X402_INVALID, "CONTRASTAPI_X402_PAY_TO", "pay to and rpc url bad");
}

void test_nowpayments_ipn_secret_needs_at_least_32_bytes(void)
{
  TEST_ASSERT_EQUAL_INT(32, BILLING_NOWPAYMENTS_SECRET_MIN_LEN);
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_LEMONSQUEEZY_WEBHOOK_SECRET", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1));
  TEST_ASSERT_NULL(config_readNowPaymentsIpnSecret());

  static const size_t lengths[] = { 31, 32, 40 };
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
  {
    char secret[64];
    memset(secret, 'a', lengths[i]);
    secret[lengths[i]] = '\0';
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_NOWPAYMENTS_IPN_SECRET", secret, 1));
    if (lengths[i] < 32)
      TEST_ASSERT_NULL(config_readNowPaymentsIpnSecret());
    else
      TEST_ASSERT_EQUAL_STRING(secret, config_readNowPaymentsIpnSecret());
  }
}

void test_nowpayments_api_key_unset_or_empty_is_refused(void)
{
  TEST_ASSERT_NULL(config_readNowPaymentsApiKey());
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_NOWPAYMENTS_API_KEY", "", 1));
  TEST_ASSERT_NULL(config_readNowPaymentsApiKey());
}

void test_nowpayments_api_key_takes_visible_ascii_up_to_128_bytes(void)
{
  static const char* const good_keys[] = { "a", "AB-CD_ef01234567890abcdefghijkl", "!", "~" };
  for (size_t i = 0; i < sizeof(good_keys) / sizeof(good_keys[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_NOWPAYMENTS_API_KEY", good_keys[i], 1));
    TEST_ASSERT_EQUAL_STRING(good_keys[i], config_readNowPaymentsApiKey());
    TEST_ASSERT_TRUE(config_readNowPaymentsApiKey() == getenv("CONTRASTAPI_NOWPAYMENTS_API_KEY"));
  }

  char key[130];
  memset(key, 'k', sizeof(key));
  key[128] = '\0';
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_NOWPAYMENTS_API_KEY", key, 1));
  TEST_ASSERT_EQUAL_STRING(key, config_readNowPaymentsApiKey());
  key[128] = 'k';
  key[129] = '\0';
  TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_NOWPAYMENTS_API_KEY", key, 1));
  TEST_ASSERT_NULL(config_readNowPaymentsApiKey());
}

void test_nowpayments_api_key_refuses_any_other_byte(void)
{
  static const char* const bad_keys[] = {
    "ab cd", "abcd\r", "\nabcd", "ab\tcd", "ab\x7f" "cd", "ab\x80" "cd",
  };
  for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(0, setenv("CONTRASTAPI_NOWPAYMENTS_API_KEY", bad_keys[i], 1));
    TEST_ASSERT_NULL_MESSAGE(config_readNowPaymentsApiKey(), bad_keys[i]);
  }
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_port_is_a_whole_number_from_1_to_the_max);
  RUN_TEST(test_worker_thread_count_falls_back_to_the_default);
  RUN_TEST(test_upstream_thread_count_defaults_to_half_of_the_workers);
  RUN_TEST(test_upstream_thread_count_takes_0_to_the_worker_count);
  RUN_TEST(test_raw_body_thread_count_defaults_to_a_quarter_of_the_workers);
  RUN_TEST(test_raw_body_thread_count_takes_0_to_the_worker_count);
  RUN_TEST(test_each_thread_count_reads_its_own_variable);
  RUN_TEST(test_ip_secret_unset_or_empty_is_refused);
  RUN_TEST(test_ip_secret_needs_at_least_32_bytes);
  RUN_TEST(test_ip_secret_counts_a_trailing_space_and_keeps_it);
  RUN_TEST(test_ip_secret_length_counts_bytes_not_characters);
  RUN_TEST(test_usage_log_path_unset_turns_the_log_off);
  RUN_TEST(test_usage_log_path_that_is_absolute_turns_the_log_on);
  RUN_TEST(test_usage_log_path_that_is_not_absolute_is_refused);
  RUN_TEST(test_certspotter_api_key_unset_is_off);
  RUN_TEST(test_certspotter_api_key_empty_is_refused);
  RUN_TEST(test_certspotter_api_key_may_hold_up_to_the_max_length);
  RUN_TEST(test_certspotter_api_key_holds_only_visible_ascii);
  RUN_TEST(test_lemonsqueezy_webhook_secret_needs_at_least_32_bytes);
  RUN_TEST(test_nowpayments_ipn_secret_needs_at_least_32_bytes);
  RUN_TEST(test_nowpayments_api_key_unset_or_empty_is_refused);
  RUN_TEST(test_nowpayments_api_key_takes_visible_ascii_up_to_128_bytes);
  RUN_TEST(test_nowpayments_api_key_refuses_any_other_byte);
  RUN_TEST(test_keyvault_master_key_unset_is_off);
  RUN_TEST(test_keyvault_master_key_reads_64_hex_digits_of_either_case);
  RUN_TEST(test_keyvault_master_key_refuses_any_other_form);
  RUN_TEST(test_x402_all_unset_is_off);
  RUN_TEST(test_x402_all_set_is_on_and_copies_each_value);
  RUN_TEST(test_x402_some_unset_is_partial_and_names_the_first_unset);
  RUN_TEST(test_x402_partial_is_named_before_an_invalid_value);
  RUN_TEST(test_x402_empty_value_is_invalid);
  RUN_TEST(test_x402_value_must_fit_its_buffer);
  RUN_TEST(test_x402_byte_outside_visible_ascii_is_invalid);
  RUN_TEST(test_x402_rpc_url_must_start_with_https);
  RUN_TEST(test_x402_invalid_names_the_first_bad_variable);
  return UNITY_END();
}
