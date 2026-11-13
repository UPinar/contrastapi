#ifndef WATCHLIST_SSL_CHECK_H
#define WATCHLIST_SSL_CHECK_H

#include <stdbool.h>
#include <libpq-fe.h>

#include "tlsprobe.h"
#include "watchlist/watchlist_domain.h"

bool watchlist_ssl_check_tryWriteCertificateExpiry   (const TlsProbeResult_t* result, WatchlistDomainValue_t* value_out);
bool watchlist_ssl_check_tryWriteCertificateValidity (const TlsProbeResult_t* result, WatchlistDomainValue_t* value_out);
bool watchlist_ssl_check_tryWriteCertificateListing  (const SSLCHECKRecord_t* record, WatchlistDomainValue_t* value_out);
bool watchlist_ssl_check_tryWriteTlsProtocol         (const TlsProbeResult_t* result, WatchlistDomainValue_t* value_out);
bool watchlist_ssl_check_scanNextDomains             (PGconn* conn);

#endif
