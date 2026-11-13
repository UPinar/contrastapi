#ifndef CONFIG_H
#define CONFIG_H

#include "keyvault.h"

#define CONFIG_MAX_PORT_NUMBER                65535
#define CONFIG_DEFAULT_WORKER_THREAD_COUNT        8
#define CONFIG_MAX_WORKER_THREAD_COUNT          512
#define CONFIG_MIN_IP_SECRET_LEN                 32

#define CONFIG_CERTSPOTTER_API_KEY_MAX_LEN      128

typedef enum {
  CONFIG_USAGE_LOG_OFF = 0,
  CONFIG_USAGE_LOG_ON,
  CONFIG_USAGE_LOG_PATH_NOT_ABSOLUTE
} ConfigUsageLogStatus_t;

typedef enum {
  CONFIG_CERTSPOTTER_API_KEY_OFF = 0,
  CONFIG_CERTSPOTTER_API_KEY_ON,
  CONFIG_CERTSPOTTER_API_KEY_INVALID
} ConfigCertSpotterApiKeyStatus_t;

typedef enum {
  CONFIG_KEYVAULT_MASTER_KEY_OFF = 0,
  CONFIG_KEYVAULT_MASTER_KEY_ON,
  CONFIG_KEYVAULT_MASTER_KEY_INVALID
} ConfigKeyVaultMasterKeyStatus_t;

#define CONFIG_X402_SOLANA_RPC_URL_BUF_SIZE     512

typedef struct {
  char  ma_network[64];
  char  ma_usdcMint[48];
  char  ma_payTo[48];
  char  ma_payToTokenAccount[48];
  char  ma_feePayer[48];
  char  ma_solanaRpcUrl[CONFIG_X402_SOLANA_RPC_URL_BUF_SIZE];
} ConfigX402_t;

typedef enum {
  CONFIG_X402_OFF = 0,
  CONFIG_X402_ON,
  CONFIG_X402_PARTIAL,
  CONFIG_X402_INVALID
} ConfigX402Status_t;

int                             config_readPortNumber                 (const char* port_text);
int                             config_readWorkerThreadCount          (void);
int                             config_readUpstreamThreadCount        (int worker_thread_count);
int                             config_readRawBodyThreadCount         (int worker_thread_count);
const char*                     config_readIpSecret                   (void);
const char*                     config_readLemonSqueezyWebhookSecret  (void);
const char*                     config_readNowPaymentsIpnSecret       (void);
const char*                     config_readNowPaymentsApiKey          (void);
ConfigUsageLogStatus_t          config_readUsageLogPath               (const char** usage_log_path_out);
ConfigCertSpotterApiKeyStatus_t config_readCertSpotterApiKey          (const char** api_key_out);
ConfigKeyVaultMasterKeyStatus_t config_readKeyVaultMasterKey          (KeyVaultMasterKey_t* master_key_out);
ConfigX402Status_t              config_readX402                       (ConfigX402_t* config_out, const char** bad_variable_name_out);

#endif
