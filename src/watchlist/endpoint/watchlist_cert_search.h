#ifndef WATCHLIST_CERT_SEARCH_H
#define WATCHLIST_CERT_SEARCH_H

#include <stdbool.h>
#include <libpq-fe.h>

#include "dns.h"
#include "external/certspotter.h"
#include "watchlist/watchlist_domain.h"

bool watchlist_cert_search_tryWriteCertIssuers    (const CertSpotterCertificateList_t* list, const DnsAnswer_t* host_set, const DnsAnswer_t* wildcard_set, WatchlistDomainValue_t* value_out);
bool watchlist_cert_search_isHostCaaSetNeeded     (const CertSpotterIssuer_t* issuer);
bool watchlist_cert_search_isWildcardCaaSetNeeded (const CertSpotterIssuer_t* issuer);
bool watchlist_cert_search_scanNextDomains        (PGconn* conn);

#endif
