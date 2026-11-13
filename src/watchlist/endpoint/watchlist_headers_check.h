#ifndef WATCHLIST_HEADERS_CHECK_H
#define WATCHLIST_HEADERS_CHECK_H

#include <stdbool.h>
#include <libpq-fe.h>

#include "header_check.h"
#include "watchlist/watchlist_domain.h"

bool watchlist_headers_check_tryWriteSecurityHeaders (const char* url, const HeaderCheckReport_t* report, WatchlistDomainValue_t* value_out);
bool watchlist_headers_check_scanNextDomains         (PGconn* conn);

#endif
