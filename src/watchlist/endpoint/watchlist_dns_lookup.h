#ifndef WATCHLIST_DNS_LOOKUP_H
#define WATCHLIST_DNS_LOOKUP_H

#include <stdbool.h>
#include <stddef.h>
#include <libpq-fe.h>

#include "dns.h"
#include "emailcheck.h"
#include "watchlist/watchlist_domain.h"

#define WATCHLIST_DNS_LOOKUP_DNS_PRESENCE_ANSWER_COUNT 4

bool watchlist_dns_lookup_tryWriteDnsPresence           (const DnsAnswer_t* answers, DnsLookupStatus_t takeover_status, const DNSTAKEOVERCHECKRecord_t* takeover_record, WatchlistDomainValue_t* value_out);
bool watchlist_dns_lookup_tryWriteNsNames               (const DnsAnswer_t* ns_answer, WatchlistDomainValue_t* value_out);
bool watchlist_dns_lookup_tryWriteMxRecords             (const DnsAnswer_t* mx_answer, WatchlistDomainValue_t* value_out);
bool watchlist_dns_lookup_tryWriteIpAddressReachability (const DnsAnswer_t* a_answer, const DnsAnswer_t* aaaa_answer, WatchlistDomainValue_t* value_out);
void watchlist_dns_lookup_writeHostingIpAddresses       (const DnsAnswer_t* a_answer, const DnsAnswer_t* aaaa_answer, char* addresses_out, size_t addresses_size);
bool watchlist_dns_lookup_tryWriteCnameTakeover         (DnsLookupStatus_t status, const DNSTAKEOVERCHECKRecord_t* record, WatchlistDomainValue_t* value_out);
bool watchlist_dns_lookup_tryWriteEmailCheckResults     (const EmailCheckItem_t* checks, int check_count, WatchlistDomainValue_t* value_out);
bool watchlist_dns_lookup_scanNextDomains               (PGconn* conn);

#endif
