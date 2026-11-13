#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "billing.h"
#include "external/nowpayments.h"
#include "bytes.h"

#define CONFIG_X402_VARIABLE_COUNT 6

#define CONFIG_X402_RPC_URL_START "https://"

typedef struct {
  const char* mp_name;
  char*       mp_field;
  size_t      m_fieldSize;
  bool        m_isHttpsRequired;
} ConfigX402Variable_t;

static bool static_tryParseIntInRange (const char* text, int min_value, int max_value, int* value_out);
static int  static_readThreadCount    (const char* env_name, int default_thread_count, int max_thread_count);
static bool static_isX402ValueUsable  (const char* value, const ConfigX402Variable_t* variable);

static bool static_tryParseIntInRange(const char* text, int min_value, int max_value, int* value_out)
{
  assert(text != NULL);
  assert(value_out != NULL);

  char* parse_end; errno = 0;
  long parsed_value = strtol(text, &parse_end, 10);
  if (parse_end == text || errno != 0)
    return false;
  while (isspace((unsigned char)*parse_end))
    parse_end++;
  if (*parse_end != '\0')
    return false;
  if (parsed_value < min_value || parsed_value > max_value)
    return false;

  *value_out = (int)parsed_value;
  return true;
}

int config_readPortNumber(const char* port_text)
{
  int port_number = 0;
  if (!static_tryParseIntInRange(port_text, 1, CONFIG_MAX_PORT_NUMBER, &port_number))
    return 0;
  return port_number;
}

int config_readWorkerThreadCount(void)
{
  int worker_thread_count = CONFIG_DEFAULT_WORKER_THREAD_COUNT;

  const char* worker_count_env = getenv("CONTRASTAPI_WORKER_THREAD_COUNT");
  if (worker_count_env)
  {
    int requested_thread_count;
    if (static_tryParseIntInRange(worker_count_env, 1, CONFIG_MAX_WORKER_THREAD_COUNT, &requested_thread_count))
      worker_thread_count = requested_thread_count;
  }
  return worker_thread_count;
}

int config_readUpstreamThreadCount(int worker_thread_count)
{
  assert(worker_thread_count >= 1);

  int default_thread_count = worker_thread_count / 2 > 0 ? worker_thread_count / 2 : 1;
  return static_readThreadCount("CONTRASTAPI_UPSTREAM_THREAD_COUNT", default_thread_count, worker_thread_count);
}

int config_readRawBodyThreadCount(int worker_thread_count)
{
  assert(worker_thread_count >= 1);

  int default_thread_count = worker_thread_count / 4 > 0 ? worker_thread_count / 4 : 1;
  return static_readThreadCount("CONTRASTAPI_RAW_BODY_THREAD_COUNT", default_thread_count, worker_thread_count);
}

const char* config_readIpSecret(void)
{
  const char* ip_secret = getenv("CONTRASTAPI_IP_SECRET");
  if (!ip_secret || strlen(ip_secret) < CONFIG_MIN_IP_SECRET_LEN)
    return NULL;
  return ip_secret;
}

const char* config_readLemonSqueezyWebhookSecret(void)
{
  const char* secret = getenv("CONTRASTAPI_LEMONSQUEEZY_WEBHOOK_SECRET");
  if (!secret || strlen(secret) < BILLING_LEMONSQUEEZY_SECRET_MIN_LEN)
    return NULL;

  return secret;
}

const char* config_readNowPaymentsIpnSecret(void)
{
  const char* secret = getenv("CONTRASTAPI_NOWPAYMENTS_IPN_SECRET");
  if (!secret || strlen(secret) < BILLING_NOWPAYMENTS_SECRET_MIN_LEN)
    return NULL;

  return secret;
}

const char* config_readNowPaymentsApiKey(void)
{
  const char* api_key = getenv("CONTRASTAPI_NOWPAYMENTS_API_KEY");
  if (!api_key)
    return NULL;

  size_t api_key_len = strlen(api_key);
  if (api_key_len == 0 || api_key_len > NOWPAYMENTS_API_KEY_MAX_LEN)
    return NULL;

  for (size_t i = 0; i < api_key_len; i++)
  {
    if (api_key[i] < '!' || api_key[i] > '~')
      return NULL;
  }
  return api_key;
}

ConfigUsageLogStatus_t config_readUsageLogPath(const char** usage_log_path_out)
{
  assert(usage_log_path_out != NULL);

  *usage_log_path_out = NULL;
  const char* usage_log_path = getenv("CONTRASTAPI_USAGE_LOG_PATH");
  if (!usage_log_path)
    return CONFIG_USAGE_LOG_OFF;
  if (usage_log_path[0] != '/')
    return CONFIG_USAGE_LOG_PATH_NOT_ABSOLUTE;

  *usage_log_path_out = usage_log_path;
  return CONFIG_USAGE_LOG_ON;
}

ConfigCertSpotterApiKeyStatus_t config_readCertSpotterApiKey(const char** api_key_out)
{
  assert(api_key_out != NULL);

  *api_key_out = NULL;
  const char* api_key = getenv("CONTRASTAPI_CERTSPOTTER_API_KEY");
  if (!api_key)
    return CONFIG_CERTSPOTTER_API_KEY_OFF;

  size_t api_key_len = strlen(api_key);
  if (api_key_len == 0 || api_key_len > CONFIG_CERTSPOTTER_API_KEY_MAX_LEN)
    return CONFIG_CERTSPOTTER_API_KEY_INVALID;

  for (size_t i = 0; i < api_key_len; i++)
  {
    if (api_key[i] < '!' || api_key[i] > '~')
      return CONFIG_CERTSPOTTER_API_KEY_INVALID;
  }

  *api_key_out = api_key;
  return CONFIG_CERTSPOTTER_API_KEY_ON;
}

ConfigKeyVaultMasterKeyStatus_t config_readKeyVaultMasterKey(KeyVaultMasterKey_t* master_key_out)
{
  assert(master_key_out != NULL);

  explicit_bzero(master_key_out, sizeof(*master_key_out));
  const char* key_hex = getenv("CONTRASTAPI_KEYVAULT_MASTER_KEY");
  if (!key_hex)
    return CONFIG_KEYVAULT_MASTER_KEY_OFF;

  if (strlen(key_hex) != 2 * KEYVAULT_MASTER_KEY_BYTE_COUNT ||
      !bytes_tryReadHex(key_hex, 2 * KEYVAULT_MASTER_KEY_BYTE_COUNT, master_key_out->ma_key))
  {
    explicit_bzero(master_key_out, sizeof(*master_key_out));
    return CONFIG_KEYVAULT_MASTER_KEY_INVALID;
  }
  return CONFIG_KEYVAULT_MASTER_KEY_ON;
}

static int static_readThreadCount(const char* env_name, int default_thread_count, int max_thread_count)
{
  int thread_count = default_thread_count;

  const char* thread_count_env = getenv(env_name);
  if (thread_count_env)
  {
    int requested_thread_count;
    if (static_tryParseIntInRange(thread_count_env, 0, max_thread_count, &requested_thread_count))
      thread_count = requested_thread_count;
  }

  return thread_count;
}

ConfigX402Status_t config_readX402(ConfigX402_t* config_out, const char** bad_variable_name_out)
{
  assert(config_out            != NULL);
  assert(bad_variable_name_out != NULL);

  explicit_bzero(config_out, sizeof(*config_out));
  *bad_variable_name_out = NULL;

  const ConfigX402Variable_t variables[CONFIG_X402_VARIABLE_COUNT] = {
    { "CONTRASTAPI_X402_NETWORK",              config_out->ma_network,           sizeof(config_out->ma_network),           false },
    { "CONTRASTAPI_X402_USDC_MINT",            config_out->ma_usdcMint,          sizeof(config_out->ma_usdcMint),          false },
    { "CONTRASTAPI_X402_PAY_TO",               config_out->ma_payTo,             sizeof(config_out->ma_payTo),             false },
    { "CONTRASTAPI_X402_PAY_TO_TOKEN_ACCOUNT", config_out->ma_payToTokenAccount, sizeof(config_out->ma_payToTokenAccount), false },
    { "CONTRASTAPI_X402_FEE_PAYER",            config_out->ma_feePayer,          sizeof(config_out->ma_feePayer),          false },
    { "CONTRASTAPI_X402_SOLANA_RPC_URL",       config_out->ma_solanaRpcUrl,      sizeof(config_out->ma_solanaRpcUrl),      true  },
  };

  const char* values[CONFIG_X402_VARIABLE_COUNT];
  const char* first_unset_name = NULL;
  int set_count = 0;
  for (int i = 0; i < CONFIG_X402_VARIABLE_COUNT; i++)
  {
    values[i] = getenv(variables[i].mp_name);
    if (values[i])
      set_count++;
    else if (!first_unset_name)
      first_unset_name = variables[i].mp_name;
  }

  if (set_count == 0)
    return CONFIG_X402_OFF;
  if (set_count < CONFIG_X402_VARIABLE_COUNT)
  {
    *bad_variable_name_out = first_unset_name;
    return CONFIG_X402_PARTIAL;
  }

  for (int i = 0; i < CONFIG_X402_VARIABLE_COUNT; i++)
  {
    if (!static_isX402ValueUsable(values[i], &variables[i]))
    {
      *bad_variable_name_out = variables[i].mp_name;
      return CONFIG_X402_INVALID;
    }
  }

  for (int i = 0; i < CONFIG_X402_VARIABLE_COUNT; i++)
    memcpy(variables[i].mp_field, values[i], strlen(values[i]) + 1);

  return CONFIG_X402_ON;
}

static bool static_isX402ValueUsable(const char* value, const ConfigX402Variable_t* variable)
{
  assert(value    != NULL);
  assert(variable != NULL);

  size_t value_len = strlen(value);
  if (value_len == 0 || value_len >= variable->m_fieldSize)
    return false;

  for (size_t i = 0; i < value_len; i++)
  {
    if (value[i] < '!' || value[i] > '~')
      return false;
  }

  return !variable->m_isHttpsRequired || strncmp(value, CONFIG_X402_RPC_URL_START, strlen(CONFIG_X402_RPC_URL_START)) == 0;
}
