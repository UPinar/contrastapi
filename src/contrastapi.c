#define _GNU_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <arpa/inet.h>

#include "connection.h"
#include "db.h"
#include "ratelimit.h"
#include "worker.h"
#include "acceptor.h"
#include "maintenance.h"
#include "watchlist/endpoint/watchlist_cert_search.h"
#include "watchlist/endpoint/watchlist_dns_lookup.h"
#include "watchlist/watchlist_domain_scan.h"
#include "watchlist/endpoint/watchlist_headers_check.h"
#include "watchlist/endpoint/watchlist_ssl_check.h"
#include "watchlist/endpoint/watchlist_whois_lookup.h"
#include "cache.h"
#include "quota.h"
#include "throttle.h"
#include "x402_ledger.h"
#include "x402_request.h"
#include "http.h"
#include "upstream.h"
#include "rawbody.h"
#include "external/certspotter.h"
#include "billing.h"
#include "external/nowpayments.h"
#include "keyvault.h"
#include "config.h"
#include "endpoint.h"
#include "pages.h"
#include "usagelog.h"

#define CONTRASTAPI_LISTEN_BACKLOG 128

static const char*    g_ipSecret  = NULL;

static const MaintenanceJob_t g_maintenanceJobs[] = {
  { "credit_budget_purge",                 ratelimit_dbPurgeExpiredCreditBudgetRows   },
  { "cve_change_event_purge",              db_purgeExpiredCveChangeEvents             },
  { "watchlist_purge",                     db_purgeExpiredWatchlists                  },
  { "upstream_cache_purge",                cache_dbPurgeExpiredRows                   },
  { "upstream_quota_purge",                quota_dbPurgeExpiredRows                   },
  { "target_throttle_purge",               throttle_dbPurgeExpiredRows                },
  { "domain_change_event_purge",           db_purgeExpiredDomainChangeEvents          },
  { "package_advisory_change_event_purge", db_purgeExpiredPackageAdvisoryChangeEvents },
  { "eol_change_event_purge",              db_purgeExpiredEolChangeEvents             },
  { "domain_watch_purge",                  db_purgeUnwatchedDomains                   },
  { "ip_watch_write",                      db_writeWatchedIpValues                    },
  { "ip_change_event_purge",               db_purgeExpiredIpChangeEvents              },
  { "vendor_key_purge",                    db_purgeExpiredVendorKeys                  },
  { "vendor_key_link_purge",               db_purgeExpiredVendorKeyLinks              },
  { "x402_payment_purge",                  x402_ledger_dbPurgeExpiredRows             },
  { "billing_event_purge",                 db_purgeExpiredBillingEvents               },
};

static const MaintenanceJob_t g_domainScanJobs[] = {
  { "domain_scan_dns",        watchlist_dns_lookup_scanNextDomains    },
  { "domain_scan_tls",        watchlist_ssl_check_scanNextDomains     },
  { "domain_scan_rdap_whois", watchlist_whois_lookup_scanNextDomains  },
  { "domain_scan_headers",    watchlist_headers_check_scanNextDomains },
  { "domain_scan_ct",         watchlist_cert_search_scanNextDomains   },
};

static void         static_ignoreSigpipe          (void);
static int          static_openListenSocket       (int port_number);
static void         static_boundDatabaseWaits     (void);
static void         static_blockShutdownSignals   (sigset_t* shutdown_signals_out);
static bool         static_isDatabaseReady        (const char* db_conninfo);
static void         static_serveRequest           (const WorkerJob_t* worker_job, PGconn* conn);
static bool         static_isX402Ready            (void);
static const char*  static_x402StartStatusName    (X402RequestStartStatus_t start_status);

int main(int argc, const char* argv[])
{
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
  {
    perror("prctl(PR_SET_DUMPABLE)");
    return EXIT_FAILURE;
  }

  if (argc != 2)
  {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    return EXIT_FAILURE;
  }

  static_boundDatabaseWaits();

  int port_number = config_readPortNumber(argv[1]);
  if (port_number == 0)
  {
    fprintf(stderr, "invalid port number: %s\n", argv[1]);
    return EXIT_FAILURE;
  }

  g_ipSecret = config_readIpSecret();
  if (!g_ipSecret)
  {
    fprintf(stderr, "CONTRASTAPI_IP_SECRET is not set or is shorter than %d bytes\n", CONFIG_MIN_IP_SECRET_LEN);
    return EXIT_FAILURE;
  }

  const char* lemonsqueezy_webhook_secret = config_readLemonSqueezyWebhookSecret();
  if (!lemonsqueezy_webhook_secret)
  {
    fprintf(stderr, "CONTRASTAPI_LEMONSQUEEZY_WEBHOOK_SECRET is not set or is shorter than %d bytes\n", BILLING_LEMONSQUEEZY_SECRET_MIN_LEN);
    return EXIT_FAILURE;
  }
  billing_setLemonSqueezySecret(lemonsqueezy_webhook_secret);

  const char* nowpayments_ipn_secret = config_readNowPaymentsIpnSecret();
  if (!nowpayments_ipn_secret)
  {
    fprintf(stderr, "CONTRASTAPI_NOWPAYMENTS_IPN_SECRET is not set or is shorter than %d bytes\n", BILLING_NOWPAYMENTS_SECRET_MIN_LEN);
    return EXIT_FAILURE;
  }
  billing_setNowPaymentsSecret(nowpayments_ipn_secret);

  const char* nowpayments_api_key = config_readNowPaymentsApiKey();
  if (!nowpayments_api_key)
  {
    fprintf(stderr, "CONTRASTAPI_NOWPAYMENTS_API_KEY is not set, is longer than %d bytes or holds a byte outside '!' to '~'\n", NOWPAYMENTS_API_KEY_MAX_LEN);
    return EXIT_FAILURE;
  }
  nowpayments_setApiKey(nowpayments_api_key);

  KeyVaultMasterKey_t master_key;
  if (config_readKeyVaultMasterKey(&master_key) != CONFIG_KEYVAULT_MASTER_KEY_ON)
  {
    fprintf(stderr, "CONTRASTAPI_KEYVAULT_MASTER_KEY is not set or is not 64 hex digits\n");
    return EXIT_FAILURE;
  }
  bool is_master_key_set = keyvault_trySetMasterKey(&master_key);
  explicit_bzero(&master_key, sizeof(master_key));
  if (!is_master_key_set)
  {
    fprintf(stderr, "the key vault master key could not be set: a key could not be derived from it\n");
    return EXIT_FAILURE;
  }

  const char* usage_log_path = NULL;
  if (config_readUsageLogPath(&usage_log_path) == CONFIG_USAGE_LOG_PATH_NOT_ABSOLUTE)
  {
    fprintf(stderr, "CONTRASTAPI_USAGE_LOG_PATH is set but is not an absolute path\n");
    return EXIT_FAILURE;
  }

  const char* certspotter_api_key = NULL;
  switch (config_readCertSpotterApiKey(&certspotter_api_key))
  {
    case CONFIG_CERTSPOTTER_API_KEY_ON:
      break;
    case CONFIG_CERTSPOTTER_API_KEY_OFF:
      fprintf(stderr, "CONTRASTAPI_CERTSPOTTER_API_KEY is not set; cert_search and subdomain_enum send no request to Cert Spotter\n");
      break;
    case CONFIG_CERTSPOTTER_API_KEY_INVALID:
      fprintf(stderr, "CONTRASTAPI_CERTSPOTTER_API_KEY is set but is not 1 to %d visible ASCII bytes\n", CONFIG_CERTSPOTTER_API_KEY_MAX_LEN);
      return EXIT_FAILURE;
  }
  certspotter_setApiKey(certspotter_api_key);

  if (!pages_init(endpoint_mcpToolCount()))
    return EXIT_FAILURE;

  static_ignoreSigpipe();

  int server_fd = static_openListenSocket(port_number);
  if (server_fd < 0)
    return EXIT_FAILURE;

  const char* db_conninfo = getenv("DATABASE_URL");
  if (!db_conninfo)
    db_conninfo = "dbname=contrastapi";

  if (!static_isDatabaseReady(db_conninfo))
  {
    close(server_fd);
    return EXIT_FAILURE;
  }

  int worker_thread_count = config_readWorkerThreadCount();
  upstream_setThreadCount(config_readUpstreamThreadCount(worker_thread_count));
  rawbody_setThreadCount(config_readRawBodyThreadCount(worker_thread_count));

  sigset_t shutdown_signals;
  static_blockShutdownSignals(&shutdown_signals);

  http_globalInit();

  if (!static_isX402Ready())
  {
    http_globalCleanup();
    close(server_fd);
    return EXIT_FAILURE;
  }

  if (usage_log_path)
  {
    usagelog_start(port_number);
    usagelog_writeEvent(USAGELOG_EVENT_START);
  }

  WorkerPool_t* worker_pool = worker_createPool(worker_thread_count, db_conninfo, static_serveRequest);
  if (!worker_pool)
  {
    fprintf(stderr, "failed to start worker pool\n");
    http_globalCleanup();
    close(server_fd);
    return EXIT_FAILURE;
  }

  int maintenance_job_count = (int)(sizeof(g_maintenanceJobs) / sizeof(g_maintenanceJobs[0]));
  MaintenanceThread_t* maintenance_thread = maintenance_start(db_conninfo, MAINTENANCE_INTERVAL_SECONDS * 1000u, g_maintenanceJobs, maintenance_job_count);
  if (!maintenance_thread)
  {
    fprintf(stderr, "failed to start the maintenance thread\n");
    worker_shutdown(worker_pool);
    http_globalCleanup();
    close(server_fd);
    return EXIT_FAILURE;
  }

  int domain_scan_job_count = (int)(sizeof(g_domainScanJobs) / sizeof(g_domainScanJobs[0]));
  MaintenanceThread_t* domain_scan_thread = maintenance_start(db_conninfo, WATCHLIST_DOMAIN_SCAN_INTERVAL_SECONDS * 1000u, g_domainScanJobs, domain_scan_job_count);
  if (!domain_scan_thread)
  {
    fprintf(stderr, "failed to start the domain scan thread\n");
    maintenance_stop(maintenance_thread);
    worker_shutdown(worker_pool);
    http_globalCleanup();
    close(server_fd);
    return EXIT_FAILURE;
  }

  int wake_fd = eventfd(0, EFD_CLOEXEC);
  AcceptorShutdownSignalThread_t* signal_thread = wake_fd >= 0 ? acceptor_startShutdownSignalThread(&shutdown_signals, wake_fd, worker_pool) : NULL;
  if (!signal_thread)
  {
    fprintf(stderr, "failed to start the signal thread\n");
    if (wake_fd >= 0)
      close(wake_fd);
    maintenance_stop(domain_scan_thread);
    maintenance_stop(maintenance_thread);
    worker_shutdown(worker_pool);
    http_globalCleanup();
    close(server_fd);
    return EXIT_FAILURE;
  }

  if (usage_log_path && !usagelog_startFileWriter(usage_log_path, USAGELOG_WRITE_INTERVAL_MS))
  {
    fprintf(stderr, "failed to start the usage log writer\n");
    close(server_fd);
    acceptor_stopShutdownSignalThread(signal_thread);
    maintenance_stop(domain_scan_thread);
    maintenance_stop(maintenance_thread);
    worker_shutdown(worker_pool);
    http_globalCleanup();
    close(wake_fd);
    return EXIT_FAILURE;
  }

  acceptor_acceptUntilShutdown(server_fd, wake_fd, worker_pool);

  close(server_fd);
  acceptor_stopShutdownSignalThread(signal_thread);
  maintenance_stop(domain_scan_thread);
  maintenance_stop(maintenance_thread);
  worker_shutdown(worker_pool);
  usagelog_writeEvent(USAGELOG_EVENT_STOP);
  usagelog_stopFileWriter();
  http_globalCleanup();
  close(wake_fd);
  return 0;
}

static void static_ignoreSigpipe(void)
{
  struct sigaction sa_pipe;
  memset(&sa_pipe, 0, sizeof(sa_pipe));
  sa_pipe.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa_pipe, NULL);
}

static int static_openListenSocket(int port_number)
{
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0)
  {
    perror("socket");
    return -1;
  }

  int reuse_addr_enable = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr_enable, sizeof(reuse_addr_enable)) < 0)
  {
    perror("setsockopt SO_REUSEADDR");
    close(server_fd);
    return -1;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  server_addr.sin_port        = htons((uint16_t)port_number);
  if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
  {
    perror("bind");
    close(server_fd);
    return -1;
  }

  if (listen(server_fd, CONTRASTAPI_LISTEN_BACKLOG) < 0)
  {
    perror("listen");
    close(server_fd);
    return -1;
  }

  int listen_flags = fcntl(server_fd, F_GETFL, 0);
  if (listen_flags < 0 || fcntl(server_fd, F_SETFL, listen_flags | O_NONBLOCK) < 0)
  {
    perror("fcntl O_NONBLOCK");
    close(server_fd);
    return -1;
  }
  return server_fd;
}

static void static_boundDatabaseWaits(void)
{
  setenv("PGCONNECT_TIMEOUT", DB_CONNECT_TIMEOUT_SEC, 0);

  setenv("PGOPTIONS", "-c statement_timeout=" DB_STATEMENT_TIMEOUT_MS, 0);
}

static void static_blockShutdownSignals(sigset_t* shutdown_signals_out)
{
  sigemptyset(shutdown_signals_out);
  sigaddset(shutdown_signals_out, SIGINT);
  sigaddset(shutdown_signals_out, SIGTERM);
  pthread_sigmask(SIG_BLOCK, shutdown_signals_out, NULL);
}

static bool static_isDatabaseReady(const char* db_conninfo)
{
  PGconn* probe_conn = db_open(db_conninfo);
  if (!probe_conn)
  {
    fprintf(stderr, "failed to open db\n");
    return false;
  }

  bool is_ready       = false;
  int  schema_version = 0;
  if (db_readSchemaVersion(probe_conn, &schema_version) != DB_OK)
  {
    fprintf(stderr, "cannot read the schema version; run make db-apply\n");
    goto done;
  }
  if (schema_version != DB_REQUIRED_SCHEMA_VERSION)
  {
    fprintf(stderr, "schema version %d, this binary needs %d; run make db-apply\n",
            schema_version, DB_REQUIRED_SCHEMA_VERSION);
    goto done;
  }

  DbConnectionRoleState_t role_state = { 0 };
  if (db_readConnectionRoleState(probe_conn, &role_state) != DB_OK)
  {
    fprintf(stderr, "cannot read the database role; run make db-apply\n");
    goto done;
  }
  if (role_state.m_isSuperuser)
  {
    fprintf(stderr, "the database role is a superuser; connect as the server's own role\n");
    goto done;
  }
  if (role_state.m_isOwnerMember)
  {
    fprintf(stderr, "the database role is contrastapi-owner or a member of it; connect as the server's own role\n");
    goto done;
  }

  if (!ratelimit_isStartupCreditBudgetProbePassed(probe_conn))
  {
    fprintf(stderr, "credit budget check failed\n");
    goto done;
  }

  if (!ratelimit_dbPurgeExpiredCreditBudgetRows(probe_conn))
  {
    fprintf(stderr, "credit budget purge failed\n");
    goto done;
  }

  if (!db_purgeExpiredCveChangeEvents(probe_conn))
  {
    fprintf(stderr, "change event purge failed\n");
    goto done;
  }

  if (!db_purgeExpiredDomainChangeEvents(probe_conn))
  {
    fprintf(stderr, "domain change event purge failed\n");
    goto done;
  }

  if (!db_purgeExpiredPackageAdvisoryChangeEvents(probe_conn))
  {
    fprintf(stderr, "package advisory change event purge failed\n");
    goto done;
  }

  if (!db_purgeExpiredEolChangeEvents(probe_conn))
  {
    fprintf(stderr, "EOL change event purge failed\n");
    goto done;
  }

  if (!db_purgeExpiredIpChangeEvents(probe_conn))
  {
    fprintf(stderr, "ip change event purge failed\n");
    goto done;
  }
  is_ready = true;

done:
  db_close(probe_conn);
  return is_ready;
}

static void static_serveRequest(const WorkerJob_t* worker_job, PGconn* conn)
{
  assert(worker_job != NULL);

  connection_serveRequest(worker_job->m_fd, worker_job->ma_clientIp, g_ipSecret, conn);
}

static bool static_isX402Ready(void)
{
  ConfigX402_t x402_config;
  const char*  x402_bad_variable_name   = NULL;
  ConfigX402Status_t x402_config_status = config_readX402(&x402_config, &x402_bad_variable_name);
  switch (x402_config_status)
  {
    case CONFIG_X402_OFF:
    case CONFIG_X402_ON:
      break;
    case CONFIG_X402_PARTIAL:
      fprintf(stderr, "%s is not set, and the other CONTRASTAPI_X402_* variables are\n", x402_bad_variable_name);
      return false;
    case CONFIG_X402_INVALID:
      fprintf(stderr, "%s is set but is not valid\n", x402_bad_variable_name);
      return false;
  }
  X402RequestStartStatus_t x402_start_status = x402_request_start(x402_config_status == CONFIG_X402_ON ? &x402_config : NULL);
  explicit_bzero(&x402_config, sizeof(x402_config));
  if (x402_start_status == X402_REQUEST_START_OFF)
  {
    fprintf(stderr, "x402 payments are off\n");
    return true;
  }
  if (x402_start_status != X402_REQUEST_START_ON)
  {
    fprintf(stderr, "x402 payments could not start: %s\n", static_x402StartStatusName(x402_start_status));
    return false;
  }
  return true;
}

static const char* static_x402StartStatusName(X402RequestStartStatus_t start_status)
{
  switch (start_status)
  {
    case X402_REQUEST_START_OFF:
      return "OFF";
    case X402_REQUEST_START_ON:
      return "ON";
    case X402_REQUEST_START_INVALID:
      return "INVALID (a setting does not fit or an address does not decode)";
    case X402_REQUEST_START_MISMATCH:
      return "MISMATCH (the facilitator does not offer our scheme, network or fee payer)";
    case X402_REQUEST_START_UNAVAILABLE:
      return "UNAVAILABLE (the facilitator gave no usable answer)";
  }
  return "unknown";
}
