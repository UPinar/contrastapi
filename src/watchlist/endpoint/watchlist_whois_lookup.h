#ifndef WATCHLIST_WHOIS_LOOKUP_H
#define WATCHLIST_WHOIS_LOOKUP_H

#include <stdbool.h>
#include <stdint.h>
#include <libpq-fe.h>

#include "external/rdap.h"
#include "watchlist/watchlist_domain.h"

bool watchlist_whois_lookup_tryWriteRegistrationExpiry (const RdapRegistration_t* registration, int64_t now_epoch, WatchlistDomainValue_t* value_out);
bool watchlist_whois_lookup_tryWriteRegistrar          (const RdapRegistration_t* registration, WatchlistDomainValue_t* value_out);
bool watchlist_whois_lookup_tryWriteTransferLock       (const RdapRegistration_t* registration, WatchlistDomainValue_t* value_out);
bool watchlist_whois_lookup_tryWriteDnssecDelegation   (const RdapRegistration_t* registration, WatchlistDomainValue_t* value_out);
bool watchlist_whois_lookup_scanNextDomains            (PGconn* conn);

#endif
