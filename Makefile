CC      = gcc
CXX     = g++
# Raw string literals -- R"(...)" -- are a GNU extension in C, so src/*.c needs a
# gnu* standard rather than a c* one. The pin sits on the C compile rule only:
# TEST_CXXFLAGS inherits CFLAGS, and g++ warns when handed a C -std flag.
CSTD    = -std=gnu17
# -MMD -MP: her derleme kendi header bagimliliklarini bir .d dosyasina yazar ve
# asagida -include ile geri okunur. Bunlar olmadan kurallar yalnizca .c dosyasina
# baglanir (.c ya da .cpp): cve.h'deki bir #define degisince hicbir sey yeniden derlenmez ve
# artimli build farkli struct yerlesimine gore derlenmis nesneleri birbirine
# linkler — sessizce, uyarisiz, yesil bir suitle. -MP ise silinen bir header'in
# eski .d uzerinden 'No rule to make target' hatasi vermesini onler. Silinen bir KAYNAK
# dosyasini kapsamaz: bir test dosyasi yeniden adlandirilirsa eski agac 'make clean' ister.
CFLAGS  = -Wall -Wextra -Wformat-nonliteral -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pthread -MMD -MP $(shell pkg-config --cflags libpq)
LDFLAGS = -lssl -lcrypto -lpq -lcurl -lresolv -lm -pthread -pie -Wl,-z,relro,-z,now

# -fno-sanitize-recover=undefined: without it UBSan prints its report and lets the
# program continue, so `make test SANITIZE=1` stays green with the report in the log.
ifdef SANITIZE
  CFLAGS  += -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g
  LDFLAGS += -fsanitize=address,undefined
endif
# ThreadSanitizer — data-race detection for the worker pool, the upstream threads, the
# raw-body threads, the maintenance thread, the acceptor's signal thread, the TLS
# settings that two probes share and the line buffer of the usage log.
# Cannot be combined with SANITIZE (ASan and TSan are mutually exclusive); needs a
# clean build. On the development machine a TSan binary needs ASLR off, or it can
# stop with "unexpected memory mapping" before any test runs:
#   make clean && make TSAN=1 bin/test_worker bin/test_upstream bin/test_rawbody bin/test_maintenance bin/test_acceptor bin/test_tlsprobe bin/test_usagelog
#   setarch "$(uname -m)" -R bin/test_worker && setarch "$(uname -m)" -R bin/test_upstream
#   setarch "$(uname -m)" -R bin/test_rawbody
#   setarch "$(uname -m)" -R bin/test_maintenance && setarch "$(uname -m)" -R bin/test_acceptor
#   setarch "$(uname -m)" -R bin/test_tlsprobe && setarch "$(uname -m)" -R bin/test_usagelog
ifdef TSAN
  CFLAGS  += -fsanitize=thread -fno-omit-frame-pointer -g
  LDFLAGS += -fsanitize=thread
endif
TARGET  = bin/contrastapi

SRCS = src/contrastapi.c src/router.c src/endpoint.c src/endpoint_table.c src/endpoint_run.c src/endpoint_run_watchlist.c src/endpoint_run_billing.c src/endpoint_weight.c src/handler.c src/response.c \
       src/jsonbuf.c src/jsoncanon.c src/utf8.c \
       src/auth.c src/db.c src/db_watchlist.c src/dbhelper.c src/ratelimit.c src/quota.c src/retryafter.c src/cache.c src/throttle.c src/connection.c src/request.c \
       src/validate.c src/ipguard.c src/query.c src/serialize.c src/http.c src/jsonread.c \
       src/jsonrpc.c src/mcp.c src/worker.c src/acceptor.c src/maintenance.c src/upstream.c src/rawbody.c src/config.c src/receive.c \
       src/picohttpparser.c src/cve_exploit.c \
       src/external/certspotter.c src/external/hibp.c src/external/shodan.c src/external/nowpayments.c src/external/abuseipdb.c src/external/rdap.c src/external/rdap_table.c src/external/wayback.c src/external/whois.c \
       src/external/whois_table.c src/cvss.c src/pages.c src/pages_table.c \
       src/dns.c src/dns_table.c src/watchlist/watchlist.c src/etld.c src/etld_table.c src/ssvc.c src/imagescan.c src/exifclient.c src/monotonic.c src/netconnect.c src/bytes.c \
       src/imageindicator.c src/tlsprobe.c src/tlsprobe_table.c src/emailauth.c src/emaildata.c src/emailcheck.c src/usagelog.c src/header_check.c src/header_fetch.c \
       src/robotstxt.c src/securitytxt.c src/datetime.c src/registryask.c src/registryask_table.c src/subdomain.c src/emailcheck_table.c src/billing.c src/keyvault.c src/x402.c src/x402_solana.c src/x402_facilitator.c src/x402_solana_rpc.c src/x402_ledger.c src/x402_request.c src/endpoint_run_vendorkey.c \
       src/watchlist/watchlist_domain.c src/watchlist/watchlist_domain_scan.c src/watchlist/endpoint/watchlist_dns_lookup.c src/watchlist/endpoint/watchlist_ssl_check.c \
       src/watchlist/endpoint/watchlist_whois_lookup.c src/watchlist/endpoint/watchlist_headers_check.c src/watchlist/endpoint/watchlist_cert_search.c
# src/web_assets.S embeds the files of web/ and docs/API_Documentation.md with .incbin.
ASM_SRCS = src/web_assets.S
OBJS = $(patsubst src/%.c, obj/%.o, $(SRCS)) $(patsubst src/%.S, obj/%.o, $(ASM_SRCS))

$(TARGET): $(OBJS) | bin
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CSTD) -Isrc -c -o $@ $<

# Each object of src/watchlist/ keeps each function and each object in a section of its own.
# A lane object holds the value writers of its lane and the scan of its lane. bin/test_watchlist_domain
# links the lane objects with --gc-sections. The link keeps the value writers and drops each
# scan, so the calls of a scan into db_watchlist.c, dns.c and the other I/O objects need no object there.
# A value writer that called one of them would still fail that link. A call into libc links
# whatever calls it, so the link does not catch it. Each lane builds its lane struct on the
# stack: an ASan build keeps every global, and a global lane would keep its scan.
obj/watchlist/%.o: CFLAGS += -ffunction-sections -fdata-sections

# A .S file is assembled without $(CSTD). $(CSTD) names a C dialect, and a .S file holds
# no C.
obj/%.o: src/%.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# .incbin reads its files while it assembles, and -MMD does not list them. So the
# object names every file of web/ and docs/API_Documentation.md as a prerequisite
# itself, and a changed file is embedded again.
obj/web_assets.o: $(shell find web -type f) docs/API_Documentation.md

bin obj:
	mkdir -p $@

# DB names the database that init-db and db-apply connect to. make prints each recipe, so
# DB holds a database name, never a connection string with a password in it. libpq reads
# the server and the user from its own environment: PGHOST, PGUSER, PGPASSWORD.
# DB_TEST names the empty database that test-sql uses.
DB      ?= contrastapi
DB_TEST ?= contrastapi_test

# init-db builds an empty database: the tables of schema.sql, then the api functions.
init-db:
	psql -X -d $(DB) -f sql/init.sql

# db-apply replaces the api functions of a database that already has its tables.
db-apply:
	psql -X -d $(DB) -f sql/apply.sql

# test-sql builds the tables and the api functions in DB_TEST, runs sql/tests/, and rolls
# everything back. It refuses DB_TEST=contrastapi, the name of the development database. It
# needs a superuser, and the four roles that sql/roles.sql creates.
test-sql:
	@if [ "$(DB_TEST)" = "contrastapi" ]; then echo "test-sql: DB_TEST must name an empty database, not contrastapi"; exit 1; fi
	psql -X -d $(DB_TEST) -f sql/tests/run.sql

# test-sql-one runs only the test file TEST_FILE names, such as t_cve_list.sql, after the same
# setup as test-sql. TEST_FILE is a path relative to sql/tests/.
# A mutation run uses it to run only the files that should catch a mutation.
# It refuses DB_TEST=contrastapi and an empty TEST_FILE.
test-sql-one:
	@if [ "$(DB_TEST)" = "contrastapi" ]; then echo "test-sql-one: DB_TEST must name an empty database, not contrastapi"; exit 1; fi
	@if [ -z "$(TEST_FILE)" ]; then echo "test-sql-one: TEST_FILE must name a file of sql/tests/, such as t_cve_list.sql"; exit 1; fi
	psql -X -d $(DB_TEST) -v test_file=$(TEST_FILE) -f sql/tests/run_one.sql


# test-sql-lock runs the lock scenarios of sql/tests/lock/ in parallel psql sessions. It builds
# a throwaway database named DB_TEST with the suffix _lock, and drops it at the end. DB_TEST
# itself stays untouched. It refuses DB_TEST=contrastapi.
test-sql-lock:
	@if [ "$(DB_TEST)" = "contrastapi" ]; then echo "test-sql-lock: DB_TEST must name a test database, not contrastapi"; exit 1; fi
	DB_TEST=$(DB_TEST) bash sql/tests/lock/run.sh

.PHONY: init-db db-apply test-sql test-sql-one test-sql-lock test clean ipguard-registry tools-list openapi etld-table etld-update rdap-table rdap-update exif-author-tags test-exiftool column-names grant-lists env-names version-keys version-keys-php

TEST_CFLAGS = $(CFLAGS) -Isrc -Itests
# A test file compiled by $(CXX) gets C++ raw string literals. That is the only
# reason it is compiled that way.
# Same flag set as TEST_CFLAGS, plus an explicit standard, so the dialect cannot drift
# with the compiler default.
TEST_CXXFLAGS = $(CFLAGS) -std=gnu++17 -Isrc -Itests
TEST_BINS   = bin/test_auth bin/test_jsonbuf bin/test_jsonread bin/test_handler bin/test_router bin/test_endpoint \
              bin/test_contrastapi bin/test_db_hit bin/test_validate bin/test_ipguard bin/test_query bin/test_serialize \
              bin/test_http bin/test_cve_exploit bin/test_cve_exploit_parse bin/test_jsonrpc bin/test_mcp \
              bin/test_response_context bin/test_worker bin/test_cvss bin/test_db bin/test_ratelimit bin/test_upstream \
              bin/test_config bin/test_maintenance bin/test_receive bin/test_utf8 bin/test_jsoncanon \
              bin/test_acceptor bin/test_pages bin/test_hibp bin/test_dns bin/test_etld bin/test_ssvc \
              bin/test_quota bin/test_cache bin/test_throttle bin/test_imagescan bin/test_rawbody bin/test_exifclient \
              bin/test_imageindicator bin/test_tlsprobe bin/test_emailauth bin/test_emaildata bin/test_emailcheck \
              bin/test_rdap bin/test_wayback bin/test_usagelog bin/test_header_check bin/test_header_fetch \
              bin/test_retryafter bin/test_whois bin/test_robotstxt bin/test_securitytxt bin/test_certspotter \
              bin/test_subdomain bin/test_watchlist_domain bin/test_watchlist_domain_scan bin/test_bytes bin/test_openapi bin/test_monotonic \
              bin/test_datetime bin/test_registryask bin/test_billing bin/test_keyvault bin/test_shodan bin/test_abuseipdb \
              bin/test_x402 bin/test_x402_solana bin/test_x402_facilitator bin/test_x402_solana_rpc bin/test_x402_ledger bin/test_x402_request bin/test_nowpayments
UNITY_OBJ            = tests/unity/unity.o
STUB_OBJ             = tests/db_stub.o
RL_STUB_OBJ          = tests/ratelimit_stub.o
CVE_EXPLOIT_STUB_OBJ   = tests/cve_exploit_stub.o
HTTP_STUB_OBJ          = tests/http_stub.o
HIBP_STUB_OBJ          = tests/hibp_stub.o
DNS_STUB_OBJ           = tests/dns_stub.o
EXIFCLIENT_STUB_OBJ    = tests/exifclient_stub.o
EMAILCHECK_STUB_OBJ    = tests/emailcheck_stub.o
TLSPROBE_STUB_OBJ      = tests/tlsprobe_stub.o
CACHE_STUB_OBJ         = tests/cache_stub.o
RDAP_STUB_OBJ          = tests/rdap_stub.o
WAYBACK_STUB_OBJ       = tests/wayback_stub.o
CERTSPOTTER_STUB_OBJ   = tests/certspotter_stub.o
SUBDOMAIN_STUB_OBJ     = tests/subdomain_stub.o
HEADER_FETCH_STUB_OBJ  = tests/header_fetch_stub.o
QUOTA_STUB_OBJ         = tests/quota_stub.o
THROTTLE_STUB_OBJ      = tests/throttle_stub.o
WHOIS_STUB_OBJ         = tests/whois_stub.o
SHODAN_STUB_OBJ        = tests/shodan_stub.o
NOWPAYMENTS_STUB_OBJ   = tests/nowpayments_stub.o
ABUSEIPDB_STUB_OBJ     = tests/abuseipdb_stub.o
X402_FACILITATOR_STUB_OBJ = tests/x402_facilitator_stub.o
X402_SOLANA_RPC_STUB_OBJ  = tests/x402_solana_rpc_stub.o
X402_LEDGER_STUB_OBJ      = tests/x402_ledger_stub.o
# X402_REQUEST_OBJS are what x402_request.o adds to a link: the module, the payload layer
# x402.o and the Solana check x402_solana.o. A link that also has handler.o or request.o adds
# them, with X402_REQUEST_STUB_OBJS in place of the facilitator, the RPC reader and the ledger,
# which would talk to a socket, the internet and the database. x402_solana.o needs -lcrypto.
X402_REQUEST_OBJS      = obj/x402_request.o obj/x402.o obj/x402_solana.o
X402_REQUEST_STUB_OBJS = $(X402_FACILITATOR_STUB_OBJ) $(X402_SOLANA_RPC_STUB_OBJ) $(X402_LEDGER_STUB_OBJ)
# X402_PAID_PATH_TEST_OBJS are what the paid path of request.o and handler.o adds to a test
# link: X402_REQUEST_OBJS and X402_REQUEST_STUB_OBJS. The paid path also needs a throttle, and
# every line that links handler.o or request.o already has $(THROTTLE_STUB_OBJ). The server
# links the real x402_ledger.o, x402_facilitator.o, x402_solana_rpc.o and throttle.o from SRCS.
X402_PAID_PATH_TEST_OBJS = $(X402_REQUEST_OBJS) $(X402_REQUEST_STUB_OBJS)
# VENDORKEY_RUN_OBJS are what the vendor_key_edit run adds to a link set that links the
# runs: the run, the key vault, and the two vendor stubs in place of shodan.o and
# abuseipdb.o, which would send requests.
VENDORKEY_RUN_OBJS     = obj/endpoint_run_vendorkey.o obj/keyvault.o $(SHODAN_STUB_OBJ) $(ABUSEIPDB_STUB_OBJ)
REQUEST_TEXT_OBJ       = tests/request_text.o
PQ_FAKE_OBJ            = tests/pq_fake.o
# OPENAPI_OBJ builds the OpenAPI document. It is not in SRCS, so the server binary does not
# link it. bin/openapi and bin/test_openapi do.
OPENAPI_OBJ            = obj/openapi.o
# OPENAPI_TABLE_OBJS are the objects that endpoints[] needs to link. The table names each
# row's run, and the runs call db_*, the upstream clients and the cache, so stubs replace
# those. The link fails without any one of them.
OPENAPI_TABLE_OBJS     = obj/endpoint.o obj/endpoint_table.o obj/endpoint_run.o obj/endpoint_run_watchlist.o obj/endpoint_run_billing.o obj/jsoncanon.o $(NOWPAYMENTS_STUB_OBJ) $(VENDORKEY_RUN_OBJS) obj/billing.o obj/datetime.o obj/auth.o obj/registryask.o obj/registryask_table.o obj/endpoint_weight.o obj/imagescan.o obj/imageindicator.o \
                         $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) obj/emailcheck_table.o $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) \
                         $(WAYBACK_STUB_OBJ) $(CERTSPOTTER_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) \
                         $(WHOIS_STUB_OBJ) obj/monotonic.o obj/etld.o obj/etld_table.o obj/watchlist/watchlist.o obj/query.o obj/jsonread.o obj/serialize.o \
                         obj/tlsprobe_table.o obj/header_check.o obj/jsonbuf.o obj/utf8.o obj/cvss.o obj/validate.o obj/ipguard.o obj/response.o \
                         $(STUB_OBJ) $(CVE_EXPLOIT_STUB_OBJ) $(HIBP_STUB_OBJ) $(DNS_STUB_OBJ) obj/usagelog.o obj/bytes.o

$(UNITY_OBJ): tests/unity/unity.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(STUB_OBJ): tests/db_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(RL_STUB_OBJ): tests/ratelimit_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(REQUEST_TEXT_OBJ): tests/request_text.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(PQ_FAKE_OBJ): tests/pq_fake.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

# --wrap=RAND_bytes: the bytes of a generated key are fixed, and the random source can fail.
bin/test_auth: tests/test_auth.c obj/auth.o obj/validate.o obj/ipguard.o obj/picohttpparser.o $(REQUEST_TEXT_OBJ) obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=RAND_bytes -lcrypto

# Linked with --wrap: tests/test_jsonbuf.cpp defines __wrap_realloc
# and __wrap_malloc so a growth step and an initial allocation can each be forced
# to fail, the same substitute-at-link-time idea as db_stub.c one level lower.
# Compiled as C++ for raw string literals, so all four wrap symbols live inside its
# extern "C" block or the link fails on a mangled name.
bin/test_jsonbuf: tests/test_jsonbuf.cpp obj/jsonbuf.o obj/utf8.o $(UNITY_OBJ) | bin
	$(CXX) $(TEST_CXXFLAGS) -o $@ $^ -Wl,--wrap=realloc,--wrap=malloc

# The real obj/db.o, obj/db_watchlist.o and obj/dbhelper.o, with PQexecParams replaced at
# link time: tests/test_db.c defines __wrap_PQexecParams, which builds its answer in memory
# through libpq, so the row reading in db.c and db_watchlist.c runs and no query reaches a
# server.
# --wrap=time, --wrap=PQresultErrorField and --wrap=PQstatus: tests/test_db.c defines the
# three, so a test sets the second, the SQLSTATE and the connection state that
# obj/dbhelper.o writes into its log lines.
# --wrap=strdup: tests/test_db.c defines __wrap_strdup, so a test can make the copy of one
# heap column fail.
# --wrap=malloc: tests/test_db.c defines __wrap_malloc, so a test can fill each block with
# 0xA5 and show a buffer that db.c or db_watchlist.c should have zeroed.
# db.c asks etld_findPlusOne whether a listed disposable domain is a public suffix. So the
# real obj/etld.o and obj/etld_table.o are linked, with obj/validate.o and obj/ipguard.o.
# etld.o checks each name with validate.o, and validate.o calls ipguard.o.
bin/test_db: tests/test_db.c obj/db.o obj/db_watchlist.o obj/ssvc.o obj/watchlist/watchlist.o obj/dbhelper.o obj/etld.o obj/etld_table.o obj/validate.o obj/ipguard.o obj/jsonread.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=PQexecParams,--wrap=time,--wrap=PQresultErrorField,--wrap=PQstatus,--wrap=strdup,--wrap=malloc -lpq

# The real obj/ratelimit.o and obj/dbhelper.o, with PQexec and PQexecParams replaced at
# link time: tests/test_ratelimit.c defines both wraps and answers each call from a queue,
# so the startup probe runs and no command reaches a server. It also defines
# __wrap_PQstatus, because a failed query's log line asks for the connection state.
bin/test_ratelimit: tests/test_ratelimit.c obj/ratelimit.o obj/dbhelper.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=PQexec,--wrap=PQexecParams,--wrap=PQstatus -lpq

# The real obj/quota.o, obj/cache.o and obj/throttle.o, each with obj/dbhelper.o, and
# PQexecParams and PQstatus replaced at link time: tests/pq_fake.c defines both wraps and
# answers each query from a queue, so no command reaches a server. --wrap=time: tests/pq_fake.c
# answers the next second at each call, so dbhelper.c drops no log line of a test.
bin/test_quota: tests/test_quota.c obj/quota.o obj/dbhelper.o $(PQ_FAKE_OBJ) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=PQexecParams,--wrap=PQstatus,--wrap=time -lpq

bin/test_cache: tests/test_cache.c obj/cache.o obj/dbhelper.o $(PQ_FAKE_OBJ) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=PQexecParams,--wrap=PQstatus,--wrap=time -lpq

bin/test_throttle: tests/test_throttle.c obj/throttle.o obj/dbhelper.o $(PQ_FAKE_OBJ) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=PQexecParams,--wrap=PQstatus,--wrap=time -lpq

# bin/test_x402_ledger links the real x402_ledger.c with obj/dbhelper.o and the same three
# wraps of tests/pq_fake.c. x402_ledger.c makes its hashes with HMAC-SHA256, hence -lcrypto, and
# writes them as hex with obj/bytes.o.
bin/test_x402_ledger: tests/test_x402_ledger.c obj/x402_ledger.o obj/dbhelper.o obj/bytes.o $(PQ_FAKE_OBJ) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=PQexecParams,--wrap=PQstatus,--wrap=time -lpq -lcrypto

bin/test_retryafter: tests/test_retryafter.c obj/retryafter.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

bin/test_bytes: tests/test_bytes.c obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# --wrap=clock_gettime: each test sets the time the clock reads.
bin/test_monotonic: tests/test_monotonic.c obj/monotonic.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=clock_gettime

bin/test_datetime: tests/test_datetime.c obj/datetime.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# bin/test_registryask links the real registryask.o and registryask_table.o. The rdap, whois,
# throttle and quota stubs answer each call that would leave the process. No cache object is
# linked, so a call of cache_* from registryask.o fails the link.
bin/test_registryask: tests/test_registryask.c obj/registryask.o obj/registryask_table.o $(RDAP_STUB_OBJ) $(WHOIS_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(QUOTA_STUB_OBJ) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# --wrap=realloc lets a test fail one allocation and measure what robotstxt.c asks for.
bin/test_robotstxt: tests/test_robotstxt.c obj/robotstxt.o obj/utf8.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=realloc

# securitytxt.o reads the Expires date with datetime.o.
bin/test_securitytxt: tests/test_securitytxt.c obj/securitytxt.o obj/datetime.o obj/utf8.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# WATCHLIST_DOMAIN_LANE_OBJS are the five lane objects of the domain watch and the value writer
# they share. Each lane object holds the value writers and the scan of its lane.
WATCHLIST_DOMAIN_LANE_OBJS = obj/watchlist/watchlist_domain.o obj/watchlist/endpoint/watchlist_dns_lookup.o obj/watchlist/endpoint/watchlist_ssl_check.o \
                             obj/watchlist/endpoint/watchlist_whois_lookup.o obj/watchlist/endpoint/watchlist_headers_check.o obj/watchlist/endpoint/watchlist_cert_search.o

# --wrap of five EVP calls lets tests/test_watchlist_domain.c fail the SHA-256 at each step and count
# the SHA-256 contexts left open. --gc-sections drops the scan of each lane object, so the test
# links the value writers alone (see the obj/watchlist/%.o flags).
bin/test_watchlist_domain: tests/test_watchlist_domain.c $(WATCHLIST_DOMAIN_LANE_OBJS) obj/tlsprobe_table.o obj/ipguard.o obj/datetime.o obj/utf8.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto -Wl,--gc-sections -Wl,--wrap=EVP_MD_CTX_new,--wrap=EVP_MD_CTX_free,--wrap=EVP_DigestInit_ex,--wrap=EVP_DigestUpdate,--wrap=EVP_DigestFinal_ex

# bin/test_watchlist_domain_scan links the lane objects with watchlist/watchlist_domain_scan.o, so each
# scan runs with the real value writers of its lane. The writers write each value and its
# SHA-256, hence -lcrypto. validate.o judges the domain name, and the DNS lane and validate.o
# call ipguard.o.
# emailcheck_table.o names each check, and tlsprobe_table.o each certificate problem. The
# test wraps emailcheck_kindId, so it can take the id of one check away.
# Every call that leaves the process is wrapped: tests/test_watchlist_domain_scan.c answers the claim of
# every lane, the quota, the DNS questions, the CNAME chain and the e-mail check from tables,
# records what each call got, and runs a fake clock. It answers the TLS probe, the SSL Blacklist
# and the TLS record the same way. It answers the registry server lookup, the registry ask,
# the RDAP record, time and the usage line the same way too. So no object of db.c, db_watchlist.c,
# quota.c, dns.c, emailcheck.c, tlsprobe.c, registryask.c, usagelog.c, header_fetch.c or
# throttle.c is linked.
# registryask_table.o holds the real scanner rules, so a test can check the scan passes them.
# The RDAP/WHOIS lane object reads dates with datetime.o and checks UTF-8 with utf8.o.
# The headers lane runs the real robotstxt.o, header_check.o and etld.o, which read no network:
# the test answers the robots.txt and home page fetches, the throttle charge and the headers
# record from tables. robotstxt.o reads with bytes.o, and etld.o finds names in etld_table.o.
# The ct lane is answered the same way: the Cert Spotter key and walk, the hold, the window of
# the share, the CAA questions and the ct record. So no object of certspotter.c is linked.
bin/test_watchlist_domain_scan: tests/test_watchlist_domain_scan.c $(WATCHLIST_DOMAIN_LANE_OBJS) obj/watchlist/watchlist_domain_scan.o obj/datetime.o obj/utf8.o obj/registryask_table.o obj/validate.o obj/ipguard.o obj/emailcheck_table.o obj/tlsprobe_table.o \
                     obj/robotstxt.o obj/bytes.o obj/header_check.o obj/etld.o obj/etld_table.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto -Wl,--wrap=db_claimDomainLaneScans,--wrap=db_recordDnsScan,--wrap=quota_dbReserve \
	  -Wl,--wrap=db_recordTlsScan,--wrap=db_SSLCHECK,--wrap=tlsprobe_probeHost \
	  -Wl,--wrap=dns_askQuestions,--wrap=dns_answerFree,--wrap=dns_checkTakeover,--wrap=monotonic_nowMs \
	  -Wl,--wrap=emailcheck_checkDomain -Wl,--wrap=emailcheck_EMAILAUTHCHECKRecordFree,--wrap=emailcheck_kindId \
	  -Wl,--wrap=dns_resetQuestionCount,--wrap=dns_readQuestionCount \
	  -Wl,--wrap=registryask_tryFindServer,--wrap=registryask_askDomain,--wrap=db_recordRdapWhoisScan,--wrap=time,--wrap=usagelog_writeEvent \
	  -Wl,--wrap=header_fetch_fetchRobotsTxt,--wrap=header_fetch_robotsTxtFree,--wrap=header_fetch_fetchHomePage,--wrap=header_fetch_resultFree,--wrap=throttle_dbCharge,--wrap=db_recordHeadersScan \
	  -Wl,--wrap=certspotter_hasApiKey,--wrap=certspotter_lookupCertificates,--wrap=quota_dbTryReadHoldRemainingSeconds,--wrap=quota_dbSetHold \
	  -Wl,--wrap=quota_windowRemainingSeconds,--wrap=db_recordCtScan,--wrap=robotstxt_parse

bin/test_jsonread: tests/test_jsonread.c obj/jsonread.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

bin/test_utf8: tests/test_utf8.c obj/utf8.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

bin/test_jsoncanon: tests/test_jsoncanon.c obj/jsoncanon.o obj/jsonread.o obj/jsonbuf.o obj/utf8.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# header_check.o rates header values it is given and measures them with utf8.o.
bin/test_header_check: tests/test_header_check.c obj/header_check.o obj/utf8.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# --wrap=EVP_Digest: tests/test_handler.c can make the hash of the image_inspect run fail.
# exifclient_stub replaces obj/exifclient.o, so no image reaches the exif service. The
# seven binaries that link endpoint_run.o link the stub, because the real client would
# connect to EXIFCLIENT_SOCKET_PATH. They link tlsprobe_stub in place of obj/tlsprobe.o,
# which would connect to the host a test names, and cache_stub in place of obj/cache.o, so
# a test can answer the ssl_check run's cache without a database. They link rdap_stub in
# place of obj/external/rdap.o, which would send a request to an RDAP server,
# wayback_stub in place of obj/external/wayback.o, which would send a request to the
# Wayback Machine, certspotter_stub in place of obj/external/certspotter.o, which would send
# a request to Cert Spotter, subdomain_stub in place of obj/subdomain.o, which would ask the
# resolver about the names under a domain, header_fetch_stub in place of obj/header_fetch.o,
# which would fetch the site a test names, and whois_stub in place of obj/external/whois.o and
# obj/external/whois_table.o, which would send a WHOIS query. They link throttle_stub in
# place of obj/throttle.o, so a test can answer the count of the whois_lookup run without a
# database. They link quota_stub in place of obj/quota.o, so a test can answer the count of
# the wayback_lookup, cert_search and subdomain_enum runs and the hold of the password_check,
# whois_lookup, wayback_lookup, cert_search and subdomain_enum runs. The wayback_lookup and health runs read monotonic_nowMs, so each of the seven
# links obj/monotonic.o too. The whois_lookup run asks through the real obj/registryask.o and
# obj/registryask_table.o, which call only the rdap, whois, throttle and quota stubs.
# They link the real obj/etld.o and obj/etld_table.o, which use no network, and the real
# obj/header_check.o, which the headers_check run and its writer in serialize.o call. The
# ssl_check writer in serialize.o names each certificate problem with the real
# obj/tlsprobe_table.o.
bin/test_handler: tests/test_handler.c obj/handler.o obj/endpoint.o obj/endpoint_table.o obj/endpoint_run.o obj/endpoint_run_watchlist.o obj/endpoint_run_billing.o obj/jsoncanon.o $(NOWPAYMENTS_STUB_OBJ) $(VENDORKEY_RUN_OBJS) obj/billing.o obj/datetime.o obj/auth.o obj/registryask.o obj/registryask_table.o obj/endpoint_weight.o obj/imagescan.o obj/imageindicator.o $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) obj/emailcheck_table.o $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) $(WAYBACK_STUB_OBJ) $(CERTSPOTTER_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(X402_PAID_PATH_TEST_OBJS) $(WHOIS_STUB_OBJ) obj/etld.o obj/etld_table.o obj/watchlist/watchlist.o obj/cvss.o obj/response.o obj/db.o obj/db_watchlist.o obj/ssvc.o obj/dbhelper.o obj/validate.o obj/query.o obj/serialize.o obj/tlsprobe_table.o obj/header_check.o obj/jsonbuf.o obj/utf8.o obj/cve_exploit.o obj/external/hibp.o obj/retryafter.o obj/dns.o obj/dns_table.o obj/monotonic.o obj/http.o obj/ipguard.o obj/jsonread.o obj/jsonrpc.o obj/mcp.o obj/picohttpparser.o obj/usagelog.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(LDFLAGS) -Wl,--wrap=EVP_Digest

bin/test_router: tests/test_router.c obj/router.o obj/pages.o obj/endpoint.o obj/endpoint_table.o obj/endpoint_run.o obj/endpoint_run_watchlist.o obj/endpoint_run_billing.o obj/jsoncanon.o $(NOWPAYMENTS_STUB_OBJ) $(VENDORKEY_RUN_OBJS) obj/billing.o obj/datetime.o obj/auth.o obj/registryask.o obj/registryask_table.o obj/endpoint_weight.o obj/imagescan.o obj/imageindicator.o $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) obj/emailcheck_table.o $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) $(WAYBACK_STUB_OBJ) $(CERTSPOTTER_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(X402_PAID_PATH_TEST_OBJS) $(WHOIS_STUB_OBJ) obj/etld.o obj/etld_table.o obj/watchlist/watchlist.o obj/handler.o obj/cvss.o obj/response.o obj/db.o obj/db_watchlist.o obj/ssvc.o obj/dbhelper.o obj/validate.o obj/query.o obj/serialize.o obj/tlsprobe_table.o obj/header_check.o obj/jsonbuf.o obj/utf8.o obj/cve_exploit.o obj/external/hibp.o obj/retryafter.o obj/dns.o obj/dns_table.o obj/monotonic.o obj/http.o obj/ipguard.o obj/jsonread.o obj/jsonrpc.o obj/mcp.o obj/picohttpparser.o obj/usagelog.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(LDFLAGS)

# The endpoint table names every REST handler, and the handlers call the table's
# gate. This binary and bin/test_handler therefore link the same objects.
# --wrap=monotonic_nowMs: tests/test_endpoint.c defines __wrap_monotonic_nowMs, so a test can
# set the clock the wayback_lookup run reads its deadline from. The health run reads the same
# clock to tell whether its kept answer is still fresh.
# --wrap=dns_askQuestions,--wrap=dns_answerFree: the watchlist_edit run asks DNS for the name
# of a domain item's add. The fake answers with the status a test sets, and the wrapped free
# counts the frees and calls the real one. Calls inside obj/dns.o are not wrapped.
bin/test_endpoint: tests/test_endpoint.c obj/endpoint.o obj/endpoint_table.o obj/endpoint_run.o obj/endpoint_run_watchlist.o obj/endpoint_run_billing.o obj/jsoncanon.o $(NOWPAYMENTS_STUB_OBJ) $(VENDORKEY_RUN_OBJS) obj/billing.o obj/datetime.o obj/auth.o obj/registryask.o obj/registryask_table.o obj/endpoint_weight.o obj/imagescan.o obj/imageindicator.o $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) obj/emailcheck_table.o $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) $(WAYBACK_STUB_OBJ) $(CERTSPOTTER_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(X402_PAID_PATH_TEST_OBJS) $(WHOIS_STUB_OBJ) obj/etld.o obj/etld_table.o obj/watchlist/watchlist.o obj/handler.o obj/cvss.o obj/response.o obj/db.o obj/db_watchlist.o obj/ssvc.o obj/dbhelper.o obj/validate.o obj/query.o obj/serialize.o obj/tlsprobe_table.o obj/header_check.o obj/jsonbuf.o obj/utf8.o obj/cve_exploit.o obj/external/hibp.o obj/retryafter.o obj/dns.o obj/dns_table.o obj/monotonic.o obj/http.o obj/ipguard.o obj/jsonread.o obj/jsonrpc.o obj/mcp.o obj/picohttpparser.o obj/usagelog.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=monotonic_nowMs,--wrap=dns_askQuestions,--wrap=dns_answerFree $(LDFLAGS)

# --wrap=mmap and --wrap=munmap: tests/test_contrastapi.c checks that connection_serveRequest
# unmaps the mapping of a large body. --wrap=explicit_bzero: it checks that the read buffer
# is cleared before connection_serveRequest returns. -D_FORTIFY_SOURCE=2 turns
# explicit_bzero into __explicit_bzero_chk, so that one is wrapped too.
# --wrap=endpoint_findByHttpPath: request.o finds the test file's raw body rows beside the
# table's. Calls inside obj/endpoint.o are not wrapped.
bin/test_contrastapi: tests/test_contrastapi.c obj/connection.o obj/request.o obj/receive.o obj/upstream.o obj/rawbody.o obj/picohttpparser.o obj/auth.o obj/router.o obj/pages.o obj/pages_table.o obj/web_assets.o obj/endpoint.o obj/endpoint_table.o obj/endpoint_run.o obj/endpoint_run_watchlist.o obj/endpoint_run_billing.o obj/jsoncanon.o $(NOWPAYMENTS_STUB_OBJ) $(VENDORKEY_RUN_OBJS) obj/billing.o obj/datetime.o obj/auth.o obj/registryask.o obj/registryask_table.o obj/endpoint_weight.o obj/imagescan.o obj/imageindicator.o $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) obj/emailcheck_table.o $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) $(WAYBACK_STUB_OBJ) $(CERTSPOTTER_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(X402_PAID_PATH_TEST_OBJS) $(WHOIS_STUB_OBJ) obj/etld.o obj/etld_table.o obj/watchlist/watchlist.o obj/handler.o obj/cvss.o obj/response.o obj/db.o obj/db_watchlist.o obj/ssvc.o obj/dbhelper.o obj/ratelimit.o obj/validate.o obj/query.o obj/serialize.o obj/tlsprobe_table.o obj/header_check.o obj/jsonbuf.o obj/utf8.o obj/cve_exploit.o obj/external/hibp.o obj/retryafter.o obj/dns.o obj/dns_table.o obj/monotonic.o obj/http.o obj/ipguard.o obj/jsonread.o obj/jsonrpc.o obj/mcp.o $(REQUEST_TEXT_OBJ) obj/usagelog.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(LDFLAGS) -Wl,--wrap=mmap,--wrap=munmap,--wrap=explicit_bzero,--wrap=__explicit_bzero_chk,--wrap=endpoint_findByHttpPath

# DB_HIT_OBJS lists the objects of bin/test_db_hit apart from Unity and request_text.
# FUZZ_SERVER_OBJS is computed from it, so the fuzz servers link the same objects.
DB_HIT_OBJS = obj/request.o obj/receive.o obj/upstream.o obj/rawbody.o obj/picohttpparser.o \
              obj/auth.o obj/router.o obj/pages.o obj/pages_table.o obj/web_assets.o \
              obj/endpoint.o obj/endpoint_table.o obj/endpoint_run.o obj/endpoint_run_watchlist.o \
              obj/endpoint_run_billing.o obj/jsoncanon.o $(NOWPAYMENTS_STUB_OBJ) $(VENDORKEY_RUN_OBJS) obj/billing.o obj/datetime.o obj/registryask.o \
              obj/registryask_table.o obj/endpoint_weight.o obj/imagescan.o obj/imageindicator.o \
              $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) obj/emailcheck_table.o \
              $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) $(WAYBACK_STUB_OBJ) \
              $(CERTSPOTTER_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) \
              $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(X402_PAID_PATH_TEST_OBJS) $(WHOIS_STUB_OBJ) obj/monotonic.o obj/etld.o \
              obj/etld_table.o obj/watchlist/watchlist.o obj/handler.o obj/cvss.o obj/response.o \
              obj/validate.o obj/query.o obj/serialize.o obj/tlsprobe_table.o obj/header_check.o \
              obj/jsonbuf.o obj/utf8.o obj/jsonread.o obj/jsonrpc.o obj/mcp.o obj/ipguard.o \
              $(CVE_EXPLOIT_STUB_OBJ) $(HIBP_STUB_OBJ) $(DNS_STUB_OBJ) $(STUB_OBJ) $(RL_STUB_OBJ) \
              obj/usagelog.o obj/bytes.o

# db_stub + ratelimit_stub replace obj/db.o, obj/db_watchlist.o and obj/ratelimit.o; no -lpq needed.
# hibp_stub replaces obj/external/hibp.o, so no request reaches Have I Been Pwned.
# dns_stub replaces obj/dns.o, so no question reaches a resolver.
# --wrap=realloc: tests/test_db_hit.cpp defines __wrap_realloc so the growth step of a
# CVEEXPLOIT body, a full CVETRIAGE page or a CVE list page can be made to fail; jsonbuf.o
# is the only realloc caller linked here (http.o, the other one, is not on this line).
# --wrap=malloc: tests/test_db_hit.cpp defines __wrap_malloc so the body malloc in a
# handler's jsonbuf_create can be made to fail.
# --wrap=calloc: tests/test_db_hit.cpp defines __wrap_calloc so calloc(0) fails, as the
# C standard allows.
# --wrap=explicit_bzero: tests/test_db_hit.cpp records each clear, so a claim test can see
# that the key and the answer body are cleared. -D_FORTIFY_SOURCE=2 can turn explicit_bzero
# into __explicit_bzero_chk, so that one is wrapped too.
# --wrap=EVP_Digest: tests/test_db_hit.cpp defines __wrap_EVP_Digest, so a test can make the
# hash of a vendor key link fail.
# --wrap=x402_parsePaymentHeader,--wrap=x402_parsePaymentJson,--wrap=x402_solana_checkTransaction:
# tests/test_db_hit.cpp answers all three from a global, so a paid request needs no signed
# Solana transaction.
# --wrap=monotonic_nowMs: tests/test_db_hit.cpp moves the clock ahead in setUp, so the /health
# answer an earlier test left on the worker thread is too old to be sent again. A test can also
# stop the clock and set the age of that answer to the millisecond.
bin/test_db_hit: tests/test_db_hit.cpp $(DB_HIT_OBJS) $(REQUEST_TEXT_OBJ) $(UNITY_OBJ) | bin
	$(CXX) $(TEST_CXXFLAGS) -o $@ $^ -Wl,--wrap=realloc,--wrap=malloc,--wrap=calloc,--wrap=explicit_bzero,--wrap=__explicit_bzero_chk,--wrap=EVP_Digest,--wrap=RAND_bytes,--wrap=x402_parsePaymentHeader,--wrap=x402_parsePaymentJson,--wrap=x402_solana_checkTransaction,--wrap=jsoncanon_tryWrite,--wrap=monotonic_nowMs -lcrypto

# validate_asnLookupTarget calls ipguard_isGloballyReachableIp. So each line that links
# obj/validate.o links obj/ipguard.o too.
bin/test_validate: tests/test_validate.c obj/validate.o obj/ipguard.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# --wrap=RAND_bytes fixes the nonce of a seal or the bytes of a link, or makes the
# random source fail. --wrap=EVP_CIPHER_CTX_new makes the cipher context fail.
# --wrap=EVP_Digest makes the hash of a link fail.
bin/test_keyvault: tests/test_keyvault.c obj/keyvault.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=RAND_bytes -Wl,--wrap=EVP_CIPHER_CTX_new -Wl,--wrap=EVP_Digest -lcrypto

# test_x402 links x402.c and what it writes and reads with. jsonbuf.o needs utf8.o, and
# jsonread.o needs bytes.o.
bin/test_x402: tests/test_x402.cpp obj/x402.o obj/jsonbuf.o obj/utf8.o obj/jsonread.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CXX) $(TEST_CXXFLAGS) -o $@ $^

# x402_solana.o uses OpenSSL for SHA-256 and Ed25519, and test_x402_solana signs its
# transactions with Ed25519 keys it makes, hence -lcrypto.
bin/test_x402_solana: tests/test_x402_solana.c obj/x402_solana.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto

# bin/test_x402_facilitator links the real x402_facilitator.c with the recording HTTP stub.
# Each answer is a fixture. The client writes its body with x402.o and jsonbuf.o, reads the
# answers with jsonread.o and checks a settle signature with x402_solana.o, hence -lcrypto.
bin/test_x402_facilitator: tests/test_x402_facilitator.cpp obj/x402_facilitator.o obj/x402.o obj/x402_solana.o obj/jsonbuf.o obj/utf8.o obj/jsonread.o obj/bytes.o $(HTTP_STUB_OBJ) $(UNITY_OBJ) | bin
	$(CXX) $(TEST_CXXFLAGS) -o $@ $^ -lcrypto

# bin/test_x402_solana_rpc links the real x402_solana_rpc.c with the recording HTTP stub. Each
# answer is a fixture. It checks the signature text with x402_solana.o, hence -lcrypto, and
# reads the answers with jsonread.o, which needs bytes.o.
bin/test_x402_solana_rpc: tests/test_x402_solana_rpc.cpp obj/x402_solana_rpc.o obj/x402_solana.o obj/jsonread.o obj/bytes.o $(HTTP_STUB_OBJ) $(UNITY_OBJ) | bin
	$(CXX) $(TEST_CXXFLAGS) -o $@ $^ -lcrypto

# bin/test_x402_request links the real x402_request.o, x402.o and x402_solana.o with the
# facilitator, RPC, ledger and throttle stubs. x402.o writes with jsonbuf.o, which needs
# utf8.o, and reads with jsonread.o, which needs bytes.o. x402_solana.o uses OpenSSL for
# SHA-256 and Ed25519, hence -lcrypto.
# --wrap=x402_parsePaymentHeader,--wrap=x402_parsePaymentJson,--wrap=x402_solana_checkTransaction:
# tests/test_x402_request.c answers all three from a global and keeps the amount and the
# policy each got.
bin/test_x402_request: tests/test_x402_request.c $(X402_REQUEST_OBJS) $(X402_REQUEST_STUB_OBJS) $(THROTTLE_STUB_OBJ) obj/jsonbuf.o obj/utf8.o obj/jsonread.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=x402_parsePaymentHeader,--wrap=x402_parsePaymentJson,--wrap=x402_solana_checkTransaction -lcrypto

# test_billing links the real billing.c and what it reads with. It checks signatures with
# HMAC, hence -lcrypto. validate.o needs ipguard.o.
bin/test_billing: tests/test_billing.c obj/billing.o obj/jsonread.o obj/bytes.o obj/datetime.o obj/validate.o obj/ipguard.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto

bin/test_ipguard: tests/test_ipguard.c obj/ipguard.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# etld.o reads the rules from etld_table.o, and checks each name with validate.o.
bin/test_etld: tests/test_etld.c obj/etld.o obj/etld_table.o obj/validate.o obj/ipguard.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# emailauth.o reads the size of an rsa key with libcrypto, and the test makes its keys with it.
bin/test_emailauth: tests/test_emailauth.c obj/emailauth.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto

# The test checks each selector of the tables with validate.o.
bin/test_emaildata: tests/test_emaildata.c obj/emaildata.o obj/validate.o obj/ipguard.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# emailcheck.o asks with dns.o and reads the records with emailauth.o and emaildata.o.
# emailcheck_table.o holds the id of each check.
# --wrap=dns_askQuestions: the answers are fakes, and the real dns_answerFree frees them.
# --wrap=monotonic_nowMs: the deadline of the second round runs on a fake clock.
# --wrap=emailauth_parseDkim: a counter tells how many DKIM records the check reads.
bin/test_emailcheck: tests/test_emailcheck.c obj/emailcheck.o obj/emailcheck_table.o obj/emailauth.o obj/emaildata.o obj/dns.o obj/dns_table.o obj/monotonic.o obj/validate.o obj/ipguard.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=dns_askQuestions,--wrap=monotonic_nowMs,--wrap=emailauth_parseDkim -lcrypto -lresolv

# ipguard-registry checks the ipguard tables against the snapshot of IANA's
# special-purpose address registries in tests/ipguard_registry. CI runs it. The weekly
# iana_registry workflow runs the same check against a fresh download.
bin/ipguard_ask: tests/ipguard_registry/ask.c obj/ipguard.o | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

ipguard-registry: bin/ipguard_ask
	python3 -I tests/ipguard_registry/check.py tests/ipguard_registry bin/ipguard_ask

# tools-list writes the tools/list document to stdout. CI checks that it is JSON that
# lists tools. bin/tools_list links the objects of bin/test_mcp, without Unity and the
# test file, so it needs no database. Run it as make -s tools-list when the output goes
# to a file: without -s, make writes its build lines to stdout too.
bin/tools_list: tests/tools_list/dump.c obj/mcp.o obj/endpoint.o obj/endpoint_table.o obj/endpoint_run.o obj/endpoint_run_watchlist.o obj/endpoint_run_billing.o obj/jsoncanon.o $(NOWPAYMENTS_STUB_OBJ) $(VENDORKEY_RUN_OBJS) obj/billing.o obj/datetime.o obj/auth.o obj/registryask.o obj/registryask_table.o obj/endpoint_weight.o obj/imagescan.o obj/imageindicator.o $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) obj/emailcheck_table.o $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) $(WAYBACK_STUB_OBJ) $(CERTSPOTTER_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(X402_PAID_PATH_TEST_OBJS) $(WHOIS_STUB_OBJ) obj/monotonic.o obj/etld.o obj/etld_table.o obj/watchlist/watchlist.o obj/handler.o obj/response.o obj/query.o obj/picohttpparser.o obj/jsonrpc.o obj/jsonread.o obj/serialize.o obj/tlsprobe_table.o obj/header_check.o obj/jsonbuf.o obj/utf8.o \
  obj/cvss.o obj/validate.o obj/ipguard.o $(STUB_OBJ) $(CVE_EXPLOIT_STUB_OBJ) $(HIBP_STUB_OBJ) $(DNS_STUB_OBJ) $(REQUEST_TEXT_OBJ) obj/usagelog.o obj/bytes.o | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto -lm

tools-list: bin/tools_list
	@bin/tools_list

# openapi writes the OpenAPI 3.1 document of the REST API to stdout. CI checks that it is
# JSON whose openapi is 3.1.0 and whose paths is a non-empty object. bin/openapi links only
# what endpoints[] needs, with stubs in place of the database and the upstream clients, so
# it opens no connection. Run it as make -s openapi when the output goes to a file.
bin/openapi: tests/openapi/dump.c $(OPENAPI_OBJ) $(OPENAPI_TABLE_OBJS) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto -lm

openapi: bin/openapi
	@bin/openapi

# column-names compares each column list of src/ with the RETURNS TABLE of the api function
# its query names: the names, their order and count, and each reader's type against the
# column's type. It reads both sides as text, through gcc -E for the C side, so it needs no
# database. CI runs it, and runs it again on copies of src/ and sql/ with one break each.
column-names:
	python3 -I tests/column_names/check.py src sql

# grant-lists checks the role lists of sql/grants.sql. It compares the server list with the
# calls of the code. It fails when api_role_functions differs from the api.fn_ names in the
# string literals of src/, when a list names a function twice, or when a listed function has
# no CREATE FUNCTION. A role lacks EXECUTE on a function its list misses, so that call would
# fail at run time. It reads text only, so it needs no database. CI runs it, and runs it
# again on two broken copies of src/ and three broken copies of sql/.
GRANT_LISTS_ARGS = src sql
grant-lists:
	python3 -I tests/grants/check.py $(GRANT_LISTS_ARGS)

# env-names fails when a tracked file still names a server env var with the old prefix
# CONTRAST_ followed by a capital letter. The server reads only CONTRASTAPI_ names, so an env
# file written from such a line sets nothing: the thread counts fall back to their defaults
# and the usage log stays off, both without an error. CI runs it, and runs it again on a
# copy of the tree with one old name put back.
env-names:
	@if git grep -nE '(^|[^A-Za-z0-9_])CONTRAST_[A-Z]'; then echo "env-names: rename the lines above to CONTRASTAPI_"; exit 1; fi

# version-keys compares the sortable version keys of schema.sql with independent references:
# packaging's PEP 440 order for PyPI, ports of osv-scalibr's comparators for Maven and NuGet,
# Ruby's Gem::Version for RubyGems, and osv.dev's and Composer's order for Packagist. It needs
# DB, a database that holds schema.sql, and psql and python3-packaging. It writes nothing
# there apart from TEMP tables. Without OSV advisory rows, the parts that read them check nothing.
# The RubyGems test skips when ruby is absent. When CI is set, as GitHub Actions sets it,
# a missing ruby fails the target instead. CI runs it on the database init-db builds. Its first
# step needs no database: it checks that the four tests that write their versions into a psql
# script refuse a version with a control character.
version-keys:
	python3 -B -I tests/version_keys/test_refuse_control_characters.py
	python3 -B -I tests/version_keys/test_pypi_key.py $(DB)
	python3 -B -I tests/version_keys/test_maven_key.py $(DB)
	python3 -B -I tests/version_keys/test_nuget_key.py $(DB)
	@if command -v ruby >/dev/null 2>&1; then echo "python3 -B -I tests/version_keys/test_rubygems_key.py $(DB)"; python3 -B -I tests/version_keys/test_rubygems_key.py $(DB); elif [ -n "$$CI" ]; then echo "version-keys: ruby is not installed, and CI must run test_rubygems_key.py"; exit 1; else echo "version-keys: test_rubygems_key.py skipped, ruby is not installed"; fi
	python3 -B -I tests/version_keys/test_packagist_key.py $(DB)

# version-keys-php compares the Packagist key with PHP's own version_compare and Composer's
# VersionParser. It needs php and the autoload file of the Debian package php-composer-semver,
# and skips when either is absent. CI does not run it.
COMPOSER_SEMVER_AUTOLOAD = /usr/share/php/Composer/Semver/autoload.php

version-keys-php:
	@if command -v php >/dev/null 2>&1 && [ -f $(COMPOSER_SEMVER_AUTOLOAD) ]; then echo "python3 -B -I tests/version_keys/test_packagist_php.py $(DB)"; python3 -B -I tests/version_keys/test_packagist_php.py $(DB); else echo "version-keys-php: skipped, php or $(COMPOSER_SEMVER_AUTOLOAD) is absent"; fi

# exif-author-tags compares the tag names of exiftool's Author group with AUTHOR_GROUP_TAGS
# in tests/test_exifclient.c. EXIFTOOL names the exiftool to ask. The weekly exiftool_tags
# workflow runs the same check on exiftool's newest source.
EXIFTOOL ?= exiftool

exif-author-tags:
	$(EXIFTOOL) -config "" -listx | python3 -I tests/exif_author_tags/check.py - tests/test_exifclient.c

# test-exiftool feeds the images of tests/fixtures to EXIFTOOL with the arguments of the exif
# service, as expected.json lists them, and compares the keys it answers with expected.json. The
# suites need no exiftool (they link tests/exifclient_stub.c or a fake service), so the target skips when
# EXIFTOOL is not installed instead of failing. The exiftool updater runs the same check.
test-exiftool:
	@if command -v $(EXIFTOOL) >/dev/null 2>&1; then python3 -I tests/fixtures/check_exiftool.py $(EXIFTOOL) tests/fixtures; else echo "test-exiftool: skipped, $(EXIFTOOL) is not installed"; fi

# etld-table writes src/etld_table.c from the copy of the Public Suffix List in tests/psl.
# The table is committed, so a build needs no Python. CI runs etld-table and fails when
# the committed table differs from what it writes.
etld-table:
	python3 -I tests/psl/gen_etld_table.py tests/psl/public_suffix_list.dat src/etld_table.c

# etld-update downloads the current list over the copy, writes the table again and runs
# the suite. The monthly psl workflow says when the ICANN section has changed. Read the
# diff of the list, and commit it with the table.
etld-update:
	curl -fsS --max-time 60 -o tests/psl/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat
	$(MAKE) etld-table
	$(MAKE) test

# rdap-table writes src/external/rdap_table.c from the copy of IANA's RDAP bootstrap file in
# tests/rdap_bootstrap. The table is committed, so a build needs no Python. CI runs rdap-table
# and fails when the committed table differs from what it writes.
rdap-table:
	python3 -I tests/rdap_bootstrap/gen_rdap_table.py tests/rdap_bootstrap/dns.json src/external/rdap_table.c

# rdap-update downloads the current file over the copy, writes the table again and runs the
# suite. The weekly rdap_bootstrap workflow says when a TLD gained, changed or lost its
# server. Read the diff of the file, and commit it with the table.
rdap-update:
	curl -fsS --max-time 60 -o tests/rdap_bootstrap/dns.json https://data.iana.org/rdap/dns.json
	$(MAKE) rdap-table
	$(MAKE) test

bin/test_query: tests/test_query.c obj/query.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# The image_inspect writer names formats and file types with imagescan.o, and imagescan.o
# hashes with libcrypto. It names the indicators with imageindicator.o. The headers_check
# writer names each finding, its issues and its remediation with header_check.o. The
# email_auth_check writer names each check with emailcheck_table.o. The ssl_check writer
# names each certificate problem with tlsprobe_table.o. The watchlist writers name the endpoint
# of each item with watchlist/watchlist.o.
bin/test_serialize: tests/test_serialize.cpp obj/serialize.o obj/tlsprobe_table.o obj/emailcheck_table.o obj/header_check.o obj/jsonbuf.o obj/utf8.o obj/imagescan.o obj/imageindicator.o obj/watchlist/watchlist.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CXX) $(TEST_CXXFLAGS) -o $@ $^ -lcrypto

# --wrap=curl_easy_setopt, --wrap=curl_easy_perform and --wrap=curl_slist_append:
# tests/test_http.c records the options http.c sets, can refuse one of them, feeds a
# body to a transfer that never reaches the network, and can make adding a header fail.
# --wrap=curl_easy_header: it answers the response header lookups of http.c.
# --wrap=strdup, --wrap=calloc and --wrap=realloc: it can make each of them fail.
# --wrap=ipguard_isGloballyReachableSockaddr: it counts the socket checks, and lets a
# loopback test server through.
bin/test_http: tests/test_http.c obj/http.o obj/ipguard.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=curl_easy_setopt,--wrap=curl_easy_perform,--wrap=curl_slist_append,--wrap=curl_easy_header,--wrap=strdup,--wrap=calloc,--wrap=realloc,--wrap=ipguard_isGloballyReachableSockaddr -lcurl

bin/test_cvss: tests/test_cvss.c obj/cvss.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lm

bin/test_ssvc: tests/test_ssvc.c obj/ssvc.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# imagescan.o and bytes.o: the format, the hash and the signatures need no other object.
# --wrap=EVP_Digest: tests/test_imagescan.c can make the hash fail.
bin/test_imagescan: tests/test_imagescan.c obj/imagescan.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto -Wl,--wrap=EVP_Digest

# exifclient.o reads the exif service's answer with jsonread.o. The answers are literals
# in tests/test_exifclient.c.
# --wrap of the socket calls, poll, shutdown, close and clock_gettime: exifclient_inspect
# runs against a fake exif service and a fake clock. --wrap=malloc makes the answer's
# buffer fail, and --wrap of explicit_bzero records how much of it is cleared.
# -D_FORTIFY_SOURCE=2 can turn poll, recv and explicit_bzero into their _chk forms, so
# those are wrapped too. This build of exifclient.o calls plain poll and recv, and
# __explicit_bzero_chk.
bin/test_exifclient: tests/test_exifclient.c obj/exifclient.o obj/jsonread.o obj/monotonic.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ \
	  -Wl,--wrap=socket,--wrap=connect,--wrap=send,--wrap=recv,--wrap=__recv_chk,--wrap=poll,--wrap=__poll_chk,--wrap=shutdown,--wrap=close,--wrap=clock_gettime \
	  -Wl,--wrap=malloc,--wrap=explicit_bzero,--wrap=__explicit_bzero_chk

# imageindicator.o alone: the rules read a result struct and the clock. --wrap=time:
# tests/test_imageindicator.c fixes the clock the rule about the future reads.
bin/test_imageindicator: tests/test_imageindicator.c obj/imageindicator.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=time

# tlsprobe.o resolves names with dns.o, which needs dns_table.o, monotonic.o, validate.o,
# ipguard.o and bytes.o. It connects with netconnect.o, and it counts the days of a
# certificate with datetime.o. tests/test_tlsprobe.c makes its certificates in memory, and a
# thread of the test runs a real OpenSSL server on one end of a socketpair.
# --wrap of socket, connect, getsockopt, poll and close: the probe's socket is the other
# end of that socketpair, and a test can make a connection fail or never finish.
# -D_FORTIFY_SOURCE=2 can turn poll into __poll_chk, so both are wrapped. This build of
# netconnect.o calls plain poll, and the SANITIZE=1 build calls __poll_chk.
# --wrap=clock_gettime: the deadlines run on a fake clock.
# --wrap=dns_askQuestions: the A and AAAA answers are fakes.
# --wrap=SSL_CTX_set_default_verify_paths: the probe's TLS settings also trust the test's
# own certificate authority.
# --wrap=X509_STORE_CTX_new: a test makes the second check of the chain fail, as an
# allocation would. libssl's own calls are not wrapped.
# --wrap=X509_verify: a test counts the signature checks of the OCSP issuer search.
# --wrap=SSL_connect: a test checks the options of each handshake step.
# --wrap=ERR_peek_last_error: a test hands the probe an error of another library.
# --wrap=SSL_ctrl: a test makes a server look as if it sent no renegotiation_info extension.
bin/test_tlsprobe: tests/test_tlsprobe.c obj/tlsprobe.o obj/datetime.o obj/dns.o obj/dns_table.o obj/monotonic.o obj/netconnect.o obj/validate.o obj/ipguard.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ \
	  -Wl,--wrap=socket,--wrap=connect,--wrap=getsockopt,--wrap=poll,--wrap=__poll_chk,--wrap=close,--wrap=clock_gettime \
	  -Wl,--wrap=dns_askQuestions,--wrap=SSL_CTX_set_default_verify_paths,--wrap=X509_STORE_CTX_new,--wrap=X509_verify,--wrap=SSL_connect \
	  -Wl,--wrap=ERR_peek_last_error,--wrap=SSL_ctrl -lssl -lcrypto -lresolv

$(CVE_EXPLOIT_STUB_OBJ): tests/cve_exploit_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(HTTP_STUB_OBJ): tests/http_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(HIBP_STUB_OBJ): tests/hibp_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(DNS_STUB_OBJ): tests/dns_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(EXIFCLIENT_STUB_OBJ): tests/exifclient_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(EMAILCHECK_STUB_OBJ): tests/emailcheck_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(TLSPROBE_STUB_OBJ): tests/tlsprobe_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(CACHE_STUB_OBJ): tests/cache_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(RDAP_STUB_OBJ): tests/rdap_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(WAYBACK_STUB_OBJ): tests/wayback_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(CERTSPOTTER_STUB_OBJ): tests/certspotter_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(SHODAN_STUB_OBJ): tests/shodan_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(NOWPAYMENTS_STUB_OBJ): tests/nowpayments_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(ABUSEIPDB_STUB_OBJ): tests/abuseipdb_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(SUBDOMAIN_STUB_OBJ): tests/subdomain_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(HEADER_FETCH_STUB_OBJ): tests/header_fetch_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(QUOTA_STUB_OBJ): tests/quota_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(THROTTLE_STUB_OBJ): tests/throttle_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(WHOIS_STUB_OBJ): tests/whois_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(X402_FACILITATOR_STUB_OBJ): tests/x402_facilitator_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(X402_SOLANA_RPC_STUB_OBJ): tests/x402_solana_rpc_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(X402_LEDGER_STUB_OBJ): tests/x402_ledger_stub.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

bin/test_cve_exploit: tests/test_cve_exploit.c obj/request.o obj/receive.o obj/upstream.o obj/rawbody.o obj/picohttpparser.o obj/auth.o \
  obj/router.o obj/pages.o obj/pages_table.o obj/web_assets.o obj/endpoint.o obj/endpoint_table.o obj/endpoint_run.o obj/endpoint_run_watchlist.o obj/endpoint_run_billing.o obj/jsoncanon.o $(NOWPAYMENTS_STUB_OBJ) $(VENDORKEY_RUN_OBJS) obj/billing.o obj/datetime.o obj/auth.o obj/registryask.o obj/registryask_table.o obj/endpoint_weight.o obj/imagescan.o obj/imageindicator.o $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) obj/emailcheck_table.o $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) $(WAYBACK_STUB_OBJ) $(CERTSPOTTER_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(X402_PAID_PATH_TEST_OBJS) $(WHOIS_STUB_OBJ) obj/monotonic.o obj/etld.o obj/etld_table.o obj/watchlist/watchlist.o obj/handler.o obj/cvss.o obj/response.o obj/validate.o \
  obj/query.o obj/serialize.o obj/tlsprobe_table.o obj/header_check.o obj/jsonbuf.o obj/utf8.o obj/jsonread.o obj/jsonrpc.o obj/mcp.o obj/ipguard.o \
  $(CVE_EXPLOIT_STUB_OBJ) $(HIBP_STUB_OBJ) $(DNS_STUB_OBJ) $(STUB_OBJ) $(RL_STUB_OBJ) $(REQUEST_TEXT_OBJ) obj/usagelog.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto -lm

# Links the real cve_exploit.c and drives it through cve_exploit_fetch.
# cve_exploit.o sends its queries through dbhelper.o. --wrap=PQexecParams:
# tests/test_cve_exploit_parse.c defines __wrap_PQexecParams, so the tests read
# queued answers and no query reaches a server. --wrap=PQstatus: a failed query's
# log line asks for the connection state, and the tests' connection is not a real
# one, so tests/test_cve_exploit_parse.c answers it.
bin/test_cve_exploit_parse: tests/test_cve_exploit_parse.c obj/cve_exploit.o obj/dbhelper.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=PQexecParams,--wrap=PQstatus -lpq

# Real hibp.c against the recording HTTP stub: the range answer is a fixture, and the
# URL, the header and the timeout of hibp_check's request are recorded.
# obj/http.o stays out of this line. http_stub.o defines the same symbols, and the two
# would collide.
bin/test_hibp: tests/test_hibp.c obj/external/hibp.o obj/retryafter.o obj/validate.o obj/ipguard.o $(HTTP_STUB_OBJ) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# bin/test_rdap links the real rdap.c and the real table with the recording HTTP stub. Each
# answer is a fixture. The stub records the URL, the headers, the timeout, the body limit and
# the trust flag of each request.
bin/test_rdap: tests/test_rdap.c obj/external/rdap.o obj/external/rdap_table.o obj/retryafter.o obj/validate.o obj/ipguard.o obj/jsonread.o $(HTTP_STUB_OBJ) obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# bin/test_wayback links the real wayback.c with the recording HTTP stub. Each answer is a
# fixture. --wrap=monotonic_nowMs: the deadline of each request runs on a fake clock.
bin/test_wayback: tests/test_wayback.c obj/external/wayback.o obj/retryafter.o obj/validate.o obj/ipguard.o obj/jsonread.o $(HTTP_STUB_OBJ) obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=monotonic_nowMs

# bin/test_nowpayments links the real nowpayments.c with the recording HTTP stub.
# --wrap=explicit_bzero: the test checks that the key header buffer is cleared after the
# call. -D_FORTIFY_SOURCE=2 can turn explicit_bzero into __explicit_bzero_chk, so both are
# wrapped.
bin/test_nowpayments: tests/test_nowpayments.c obj/external/nowpayments.o obj/validate.o obj/ipguard.o obj/jsonread.o obj/bytes.o $(HTTP_STUB_OBJ) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=explicit_bzero,--wrap=__explicit_bzero_chk

# bin/test_shodan links the real shodan.c with the recording HTTP stub. Each answer is a
# fixture, and the stub records the URL, the flags, the timeout and the body cap. shodan.o
# checks CVE ids with validate.o, which needs ipguard.o, and reads JSON with jsonread.o,
# which needs bytes.o. It clears the URL with OPENSSL_cleanse, hence -lcrypto.
bin/test_shodan: tests/test_shodan.c obj/external/shodan.o obj/validate.o obj/ipguard.o obj/jsonread.o obj/bytes.o $(HTTP_STUB_OBJ) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto

# bin/test_abuseipdb links the real abuseipdb.c with the recording HTTP stub, the same way.
# abuseipdb.o reads the wait of a 429 with retryafter.o. --wrap=time: the test answers a
# fixed now, so the wait read from X-RateLimit-Reset is fixed.
bin/test_abuseipdb: tests/test_abuseipdb.c obj/external/abuseipdb.o obj/retryafter.o obj/jsonread.o obj/bytes.o $(HTTP_STUB_OBJ) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=time -lcrypto

# bin/test_certspotter links the real certspotter.c with the recording HTTP stub. Each
# answer is a fixture, and the stub records the URL, the header and the trust flag.
# certspotter.o adds names with subdomain.o. subdomain.o asks with dns.o and reads SPF with
# emailauth.o, so the link takes those and their libraries too. No test here asks DNS.
# quota_stub.o answers the reservation the walk makes before each request.
bin/test_certspotter: tests/test_certspotter.c obj/external/certspotter.o obj/subdomain.o obj/emailauth.o obj/dns.o obj/dns_table.o obj/monotonic.o obj/retryafter.o obj/validate.o obj/ipguard.o obj/jsonread.o $(HTTP_STUB_OBJ) $(QUOTA_STUB_OBJ) obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto -lresolv

# bin/test_subdomain links the real subdomain.c with the real emailauth.o and dns.o.
# --wrap=dns_askQuestions: the answers are fakes, and the real dns_answerFree frees them.
# --wrap=dns_answerFree counts the answers freed. --wrap=getrandom: the probe labels are fixed.
bin/test_subdomain: tests/test_subdomain.c obj/subdomain.o obj/emailauth.o obj/dns.o obj/dns_table.o obj/monotonic.o obj/validate.o obj/ipguard.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=dns_askQuestions -Wl,--wrap=getrandom -Wl,--wrap=dns_answerFree -lcrypto -lresolv

# bin/test_whois links the real whois.c, its table, and the real rdap_table.c, so a listed
# TLD that gains an RDAP server fails here. tests/test_whois.c plays the WHOIS server on one
# end of a socketpair. whois.o connects with netconnect.o.
# --wrap of socket, connect, getsockopt, send, poll and close: the lookup's socket is the other
# end of that socketpair. A test can make a connection fail or never finish, and a send or a
# poll fail.
# -D_FORTIFY_SOURCE=2 can turn poll and explicit_bzero into their _chk forms, so those are
# wrapped too.
# --wrap=monotonic_nowMs: the deadlines run on a fake clock. --wrap=dns_askQuestions: the A
# and AAAA answers are fakes. --wrap=malloc makes the answer's buffer fail, and
# --wrap=explicit_bzero records how much of it is cleared.
bin/test_whois: tests/test_whois.c obj/external/whois.o obj/external/whois_table.o obj/external/rdap_table.o obj/dns.o obj/dns_table.o obj/monotonic.o obj/netconnect.o obj/validate.o obj/ipguard.o obj/bytes.o obj/datetime.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ \
	  -Wl,--wrap=socket,--wrap=connect,--wrap=getsockopt,--wrap=send,--wrap=poll,--wrap=__poll_chk,--wrap=close,--wrap=monotonic_nowMs \
	  -Wl,--wrap=dns_askQuestions,--wrap=malloc,--wrap=explicit_bzero,--wrap=__explicit_bzero_chk -lresolv

# bin/test_header_fetch links the real header_fetch.c with the recording HTTP stub. It links
# header_check.o for the list of names to keep. Each answer of a redirect chain is a fixture.
# --wrap=monotonic_nowMs: the deadline of the chain runs on a fake clock. --wrap=curl_url and --wrap=curl_url_get: a test makes one call fail,
# as it fails when memory runs out. The URL parsing itself is libcurl's.
bin/test_header_fetch: tests/test_header_fetch.c obj/header_fetch.o obj/header_check.o obj/utf8.o $(HTTP_STUB_OBJ) obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=monotonic_nowMs,--wrap=curl_url,--wrap=curl_url_get -lcurl

# bin/test_usagelog links usagelog.o and monotonic.o. --wrap=time and --wrap=monotonic_nowMs give every
# line a fixed time and a fixed "duration_ms", so a test can pin a whole line. --wrap=write
# lets a test fail or cut a write of the file writer. The test starts threads. TEST_CFLAGS
# already carries -pthread, so the recipe adds no flag.
bin/test_usagelog: tests/test_usagelog.c obj/usagelog.o obj/monotonic.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=time,--wrap=monotonic_nowMs,--wrap=write

# bin/test_dns links the real dns.o, and uses no network. The DNS answers are byte arrays
# in tests/test_dns.c.
# --wrap=malloc,calloc,strdup: tests/test_dns.c makes the n-th allocation fail.
# --wrap of the socket calls, poll, close, clock_gettime, __res_ninit and __res_nclose:
# dns_askQuestions runs against a fake network, a fake clock and fake name servers.
# -D_FORTIFY_SOURCE=2 can turn poll into __poll_chk and recv into __recv_chk, so both are
# wrapped too. This build of dns.o calls __poll_chk and plain recv.
bin/test_dns: tests/test_dns.c obj/dns.o obj/dns_table.o obj/monotonic.o obj/validate.o obj/ipguard.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=malloc,--wrap=calloc,--wrap=strdup \
	  -Wl,--wrap=socket,--wrap=connect,--wrap=send,--wrap=recv,--wrap=__recv_chk,--wrap=poll,--wrap=__poll_chk,--wrap=close,--wrap=clock_gettime \
	  -Wl,--wrap=__res_ninit,--wrap=__res_nclose -lresolv

bin/test_jsonrpc: tests/test_jsonrpc.c obj/jsonrpc.o obj/jsonread.o obj/jsonbuf.o obj/utf8.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

bin/test_response_context: tests/test_response_context.c obj/response.o obj/usagelog.o obj/monotonic.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# pages.o and the response.o it sends with: the test sends fixture files into socket pairs.
# pages_table.o and web_assets.o: the test also reads the table the server serves.
bin/test_pages: tests/test_pages.c obj/pages.o obj/pages_table.o obj/web_assets.o obj/response.o obj/usagelog.o obj/monotonic.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# upstream.o alone: the upstream thread counter needs no other object. The test starts
# threads, hence the pthread flag that TEST_CFLAGS already carries.
bin/test_upstream: tests/test_upstream.c obj/upstream.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# rawbody.o alone: the raw-body thread counter needs no other object. The test
# starts threads, hence the pthread flag that TEST_CFLAGS already carries.
bin/test_rawbody: tests/test_rawbody.c obj/rawbody.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# config.o and the bytes.o it reads hex with: the test sets the environment variables that
# config.c reads.
bin/test_config: tests/test_config.c obj/config.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^

# worker.o alone: tests/test_worker.c defines db_open, db_close and usagelog_writeEvent, and
# replaces PQstatus at link time, so a worker runs on a fake connection. The link needs no
# -lpq, because worker.o calls no other libpq function.
bin/test_worker: tests/test_worker.c obj/worker.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=PQstatus

# acceptor.o with the real worker.o: tests/test_acceptor.c defines db_open and db_close,
# and its pools pass a NULL conninfo, so no connection opens. worker.o still names PQstatus,
# hence -lpq. It also calls usagelog_writeEvent, hence usagelog.o and the monotonic.o that
# usagelog.o needs. The test never starts the usage log, so no event writes a line.
bin/test_acceptor: tests/test_acceptor.c obj/acceptor.o obj/worker.o obj/usagelog.o obj/monotonic.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lpq

# maintenance.o and monotonic.o: tests/test_maintenance.c defines db_open and db_close, and replaces
# PQstatus and PQreset at link time, so the thread runs its jobs on a fake connection. The
# link needs no -lpq, because maintenance.o calls no other libpq function.
bin/test_maintenance: tests/test_maintenance.c obj/maintenance.o obj/monotonic.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=PQstatus,--wrap=PQreset

# receive.o and the picohttpparser.o it frames a request with: the test reads from socket
# pairs. Some tests start a writer thread, hence the pthread flag that TEST_CFLAGS already
# carries.
# --wrap=clock_gettime: tests/test_receive.c can script the two clock readings of a call,
# so a test of the deadline's millisecond edge does not depend on the machine's speed.
# --wrap=mmap, --wrap=madvise and --wrap=munmap: tests/test_receive.c can make the mapping
# of a large body fail. It can check that the mapping is marked MADV_DONTDUMP, and that the
# mapping it unmaps is the one it made.
bin/test_receive: tests/test_receive.c obj/receive.o obj/picohttpparser.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -Wl,--wrap=clock_gettime,--wrap=mmap,--wrap=madvise,--wrap=munmap

# mcp.c reads each tool's row from endpoint_table.o, through the lookup and the gate in
# endpoint.o, and calls the row's run in endpoint_run.o or endpoint_run_watchlist.o. The
# runs call db_*, cve_exploit_fetch, hibp_check, dns_lookupDomain, dns_checkTakeover,
# dns_lookupPtr, dns_answerFree, emailcheck_checkDomain, emailcheck_checkAddressDomain and
# header_fetch_fetchHomePage, and stubs replace them. serialize, header_check, cvss,
# validate, ipguard, jsonrpc and json* are real.
# The table names the REST handlers, so handler.o and the response.o and query.o it
# calls are linked too.
# --wrap=realloc and --wrap=malloc for the same reasons as bin/test_db_hit: tests/test_mcp.cpp
# defines __wrap_realloc and __wrap_malloc.
# The image_inspect run hashes with imagescan.o, hence -lcrypto.
# --wrap=endpoint_findByMcpName: mcp.o finds the test file's tool rows beside the table's.
# Calls inside obj/endpoint.o are not wrapped.
# --wrap=monotonic_nowMs: tests/test_mcp.cpp moves the clock ahead in setUp, so the health
# answer an earlier test left on the thread is too old to be sent again.
bin/test_mcp: tests/test_mcp.cpp obj/mcp.o obj/endpoint.o obj/endpoint_table.o obj/endpoint_run.o obj/endpoint_run_watchlist.o obj/endpoint_run_billing.o obj/jsoncanon.o $(NOWPAYMENTS_STUB_OBJ) $(VENDORKEY_RUN_OBJS) obj/billing.o obj/datetime.o obj/auth.o obj/registryask.o obj/registryask_table.o obj/endpoint_weight.o obj/imagescan.o obj/imageindicator.o $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) obj/emailcheck_table.o $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) $(WAYBACK_STUB_OBJ) $(CERTSPOTTER_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(X402_PAID_PATH_TEST_OBJS) $(WHOIS_STUB_OBJ) obj/monotonic.o obj/etld.o obj/etld_table.o obj/watchlist/watchlist.o obj/handler.o obj/response.o obj/query.o obj/picohttpparser.o obj/jsonrpc.o obj/jsonread.o obj/serialize.o obj/tlsprobe_table.o obj/header_check.o obj/jsonbuf.o obj/utf8.o \
  obj/cvss.o obj/validate.o obj/ipguard.o $(STUB_OBJ) $(CVE_EXPLOIT_STUB_OBJ) $(HIBP_STUB_OBJ) $(DNS_STUB_OBJ) $(REQUEST_TEXT_OBJ) obj/usagelog.o obj/bytes.o $(UNITY_OBJ) | bin
	$(CXX) $(TEST_CXXFLAGS) -o $@ $^ -lcrypto -Wl,--wrap=realloc,--wrap=malloc,--wrap=endpoint_findByMcpName,--wrap=monotonic_nowMs

# test_openapi reads the document that openapi.o builds from endpoints[]. It needs no
# database, and image_inspect's run hashes with imagescan.o, hence -lcrypto.
bin/test_openapi: tests/test_openapi.c $(OPENAPI_OBJ) $(OPENAPI_TABLE_OBJS) $(UNITY_OBJ) | bin
	$(CC) $(TEST_CFLAGS) -o $@ $^ -lcrypto -lm

test: $(TEST_BINS)
	@bin/test_auth && bin/test_nowpayments && bin/test_jsonbuf && bin/test_jsonread && bin/test_handler && bin/test_router && bin/test_endpoint && bin/test_contrastapi && bin/test_db_hit && bin/test_validate && bin/test_ipguard && bin/test_query && bin/test_serialize && bin/test_http && bin/test_cve_exploit && bin/test_cve_exploit_parse && bin/test_jsonrpc && bin/test_mcp && bin/test_response_context && bin/test_worker && bin/test_cvss && bin/test_db && bin/test_ratelimit && bin/test_upstream && bin/test_config && bin/test_maintenance && bin/test_receive && bin/test_utf8 && bin/test_jsoncanon && bin/test_acceptor && bin/test_pages && bin/test_hibp && bin/test_dns && bin/test_etld && bin/test_ssvc && bin/test_quota && bin/test_cache && bin/test_throttle && bin/test_imagescan && bin/test_rawbody && bin/test_exifclient && bin/test_imageindicator && bin/test_tlsprobe && bin/test_emailauth && bin/test_emaildata && bin/test_emailcheck && bin/test_rdap && bin/test_wayback && bin/test_usagelog && bin/test_header_check && bin/test_header_fetch && bin/test_retryafter && bin/test_whois && bin/test_robotstxt && bin/test_securitytxt && bin/test_certspotter && bin/test_watchlist_domain && bin/test_watchlist_domain_scan && bin/test_subdomain && bin/test_bytes && bin/test_openapi && bin/test_monotonic && bin/test_datetime && bin/test_registryask && bin/test_billing && bin/test_keyvault && bin/test_shodan && bin/test_abuseipdb && bin/test_x402 && bin/test_x402_solana && bin/test_x402_facilitator && bin/test_x402_solana_rpc && bin/test_x402_ledger && bin/test_x402_request

# ---- Fuzzing -----------------------------------------------------------------------
# libFuzzer exists only in clang, so the fuzz harnesses build with FUZZ_CC, not with $(CC).
# `make` and `make test` never build them. Their objects go to obj/fuzz/, so a fuzz object
# never mixes with a gcc object, and `make clean` removes them with obj/.
# FUZZ_CFLAGS keeps assert on, as the server does (no -DNDEBUG). An assert that an input
# reaches is then a crash here, as in production. FUZZ_CFLAGS drops -O2,
# -fstack-protector-strong, -fPIE and -D_FORTIFY_SOURCE=2. _FORTIFY_SOURCE turns strcpy
# and memcpy into __strcpy_chk and __memcpy_chk, which ASan does not intercept. glibc
# then aborts without an ASan report.
FUZZ_CC      ?= clang-20
FUZZ_SECONDS ?= 60
FUZZ_WORK    ?= obj/fuzz/work
FUZZ_CFLAGS   = -g -O1 -Wall -Wextra -Wformat-nonliteral -fno-omit-frame-pointer -pthread \
                -fsanitize=address,undefined -fno-sanitize-recover=undefined -MMD -MP \
                $(CSTD) -Isrc -Itests $(shell pkg-config --cflags libpq)
FUZZ_NAMES    = jsonread query request price mcp net dns x402 x402_solana x402_facilitator x402_solana_rpc
FUZZ_BINS     = $(addprefix bin/fuzz_, $(FUZZ_NAMES))

# FUZZ_SERVER_OBJS lists the objects of fuzz_request, fuzz_price and fuzz_mcp. It is
# computed from DB_HIT_OBJS, so the same stubs stand in for the database, the upstream
# services and the resolver. An object added to bin/test_db_hit reaches the fuzz servers too.
FUZZ_SERVER_OBJS = $(patsubst tests/%,obj/fuzz/tests/%,$(patsubst obj/%,obj/fuzz/%,$(DB_HIT_OBJS)))
FUZZ_JSONREAD_OBJS = $(addprefix obj/fuzz/, jsonread.o bytes.o jsonrpc.o jsonbuf.o utf8.o)
FUZZ_QUERY_OBJS    = $(addprefix obj/fuzz/, query.o bytes.o)
FUZZ_NET_OBJS      = $(addprefix obj/fuzz/, robotstxt.o securitytxt.o datetime.o header_check.o emailauth.o cvss.o retryafter.o \
                       external/rdap.o external/rdap_table.o external/whois.o external/whois_table.o dns.o dns_table.o \
                       monotonic.o netconnect.o validate.o ipguard.o jsonread.o bytes.o utf8.o) \
                     obj/fuzz/tests/http_stub.o
FUZZ_DNS_OBJS      = $(addprefix obj/fuzz/, dns.o bytes.o dns_table.o monotonic.o validate.o ipguard.o)
FUZZ_X402_OBJS     = $(addprefix obj/fuzz/, x402.o jsonbuf.o utf8.o jsonread.o bytes.o)
FUZZ_X402_SOLANA_OBJS = obj/fuzz/x402_solana.o
FUZZ_X402_FACILITATOR_OBJS = $(addprefix obj/fuzz/, x402_facilitator.o x402.o x402_solana.o jsonbuf.o utf8.o jsonread.o bytes.o) \
                             obj/fuzz/tests/http_stub.o
FUZZ_X402_SOLANA_RPC_OBJS  = $(addprefix obj/fuzz/, x402_solana_rpc.o x402_solana.o jsonread.o bytes.o) obj/fuzz/tests/http_stub.o

# FUZZ_OPTS_<name> holds the options of one harness. -max_len is the longest input
# libFuzzer makes for it. fuzz_request and fuzz_price also skip a longer input.
# jsonread: ENDPOINT_MCP_MAX_BODY_BYTE_COUNT (66560), the longest JSON body.
# query: REQUEST_TARGET_MAX_LEN (1023).
# request: the cap byte, a head buffer and that body (70657).
# price: the row byte, a target with its two separators, and that body (67586).
# mcp: the header byte, a head buffer and that body (70657).
# dns: DNS_MESSAGE_MAX_SIZE (65535) plus the type byte (65536).
# x402: 3420 is X402_PAYMENT_HEADER_MAX_LEN (3416) plus one base64 quartet, so libFuzzer can
# cross the cap.
# x402_solana: 1300 is past X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT (1232), so libFuzzer tries
# the length cap too.
# x402_facilitator and x402_solana_rpc: the status byte and one byte past the answer cap
# (16384), so libFuzzer tries the cap too.
# net: 65536 is a round cap. libFuzzer makes no longer input, so it never tries an RDAP
# or robots.txt body past 64 KiB, nor a WHOIS answer of 65535 or 65536 bytes
# (WHOIS_MAX_ANSWER_BYTE_COUNT).
FUZZ_OPTS_jsonread = -max_len=66560 -dict=tests/fuzz/json.dict
FUZZ_OPTS_query    = -max_len=1023 -dict=tests/fuzz/query.dict
FUZZ_OPTS_request  = -max_len=70657 -dict=tests/fuzz/http.dict
FUZZ_OPTS_price    = -max_len=67586 -dict=tests/fuzz/json.dict
FUZZ_OPTS_mcp      = -max_len=70657 -dict=tests/fuzz/json.dict
FUZZ_OPTS_net      = -max_len=65536 -dict=tests/fuzz/net.dict
FUZZ_OPTS_dns      = -max_len=65536
FUZZ_OPTS_x402     = -max_len=3420 -dict=tests/fuzz/json.dict
FUZZ_OPTS_x402_solana = -max_len=1300
FUZZ_OPTS_x402_facilitator = -max_len=16386 -dict=tests/fuzz/json.dict
FUZZ_OPTS_x402_solana_rpc  = -max_len=16386 -dict=tests/fuzz/json.dict

obj/fuzz/tests/%.o: tests/%.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer-no-link -c -o $@ $<

obj/fuzz/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer-no-link -c -o $@ $<

obj/fuzz/%.o: src/%.S
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c -o $@ $<

obj/fuzz/web_assets.o: $(shell find web -type f) docs/API_Documentation.md

bin/fuzz_jsonread: tests/fuzz/fuzz_jsonread.c $(FUZZ_JSONREAD_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^)

bin/fuzz_query: tests/fuzz/fuzz_query.c $(FUZZ_QUERY_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^)

# fuzz_request wraps read() so that each read of the client socket returns at most
# as many bytes as the input's first byte says (0 is no cap).
bin/fuzz_request: tests/fuzz/fuzz_request.c $(FUZZ_SERVER_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^) -Wl,--wrap=read -lcrypto -lm

bin/fuzz_price: tests/fuzz/fuzz_price.c $(FUZZ_SERVER_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^) -lcrypto -lm

bin/fuzz_mcp: tests/fuzz/fuzz_mcp.c $(FUZZ_SERVER_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^) -lcrypto -lm

bin/fuzz_net: tests/fuzz/fuzz_net.c $(FUZZ_NET_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^) -lcrypto -lresolv -lm

bin/fuzz_dns: tests/fuzz/fuzz_dns.c $(FUZZ_DNS_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^) -lcrypto -lresolv -lm

bin/fuzz_x402: tests/fuzz/fuzz_x402.c $(FUZZ_X402_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^)

bin/fuzz_x402_solana: tests/fuzz/fuzz_x402_solana.c $(FUZZ_X402_SOLANA_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^) -lcrypto

bin/fuzz_x402_facilitator: tests/fuzz/fuzz_x402_facilitator.c $(FUZZ_X402_FACILITATOR_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^) -lcrypto

bin/fuzz_x402_solana_rpc: tests/fuzz/fuzz_x402_solana_rpc.c $(FUZZ_X402_SOLANA_RPC_OBJS) | bin
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^) -lcrypto

fuzz: $(FUZZ_BINS)

# fuzz-run fuzzes each harness for FUZZ_SECONDS. The inputs it finds go to FUZZ_WORK and
# never to tests/fuzz/corpus/. libFuzzer writes new inputs into the first corpus directory
# it is given. It writes a crashing input to -artifact_prefix.
fuzz-run: $(FUZZ_BINS)
	$(foreach name,$(FUZZ_NAMES),mkdir -p $(FUZZ_WORK)/$(name) && \
	  bin/fuzz_$(name) -max_total_time=$(FUZZ_SECONDS) $(FUZZ_OPTS_$(name)) -artifact_prefix=$(FUZZ_WORK)/$(name)- \
	  $(FUZZ_WORK)/$(name) tests/fuzz/corpus/$(name) && ) true

# fuzz-replay runs each harness once over its seeds in tests/fuzz/corpus/, with no fuzzing.
# CI runs it. A seed that crashes fails the target.
fuzz-replay: $(FUZZ_BINS)
	$(foreach name,$(FUZZ_NAMES),mkdir -p $(FUZZ_WORK) && \
	  bin/fuzz_$(name) -runs=0 $(FUZZ_OPTS_$(name)) -artifact_prefix=$(FUZZ_WORK)/$(name)- tests/fuzz/corpus/$(name) && ) true

.PHONY: fuzz fuzz-run fuzz-replay

FUZZ_OBJS = $(sort $(FUZZ_SERVER_OBJS) $(FUZZ_JSONREAD_OBJS) $(FUZZ_QUERY_OBJS) $(FUZZ_NET_OBJS) $(FUZZ_DNS_OBJS) $(FUZZ_X402_OBJS) $(FUZZ_X402_SOLANA_OBJS) $(FUZZ_X402_FACILITATOR_OBJS) $(FUZZ_X402_SOLANA_RPC_OBJS))
FUZZ_DEPS = $(FUZZ_BINS:=.d) $(FUZZ_OBJS:.o=.d)
-include $(FUZZ_DEPS)

# Uretilen bagimlilik dosyalari: src/ nesneleri, tests/ tarafindaki nesneler
# (unity + stub'lar) ve test ikilileri (test_X.c dogrudan ikiliye derleniyor,
# .d adi ikiliyi izler). clean bunlari ayrica siler: obj/ disinda kalanlar
# 'rm -rf obj' ile gitmez.
DEPS = $(OBJS:.o=.d) $(UNITY_OBJ:.o=.d) $(STUB_OBJ:.o=.d) $(RL_STUB_OBJ:.o=.d) \
       $(CVE_EXPLOIT_STUB_OBJ:.o=.d) \
       $(HTTP_STUB_OBJ:.o=.d) $(HIBP_STUB_OBJ:.o=.d) $(DNS_STUB_OBJ:.o=.d) $(EXIFCLIENT_STUB_OBJ:.o=.d) $(EMAILCHECK_STUB_OBJ:.o=.d) $(TLSPROBE_STUB_OBJ:.o=.d) $(CACHE_STUB_OBJ:.o=.d) $(RDAP_STUB_OBJ:.o=.d) $(THROTTLE_STUB_OBJ:.o=.d) $(WHOIS_STUB_OBJ:.o=.d) $(WAYBACK_STUB_OBJ:.o=.d) $(CERTSPOTTER_STUB_OBJ:.o=.d) $(SHODAN_STUB_OBJ:.o=.d) $(ABUSEIPDB_STUB_OBJ:.o=.d) $(SUBDOMAIN_STUB_OBJ:.o=.d) $(HEADER_FETCH_STUB_OBJ:.o=.d) $(QUOTA_STUB_OBJ:.o=.d) $(X402_FACILITATOR_STUB_OBJ:.o=.d) $(X402_SOLANA_RPC_STUB_OBJ:.o=.d) $(X402_LEDGER_STUB_OBJ:.o=.d) $(REQUEST_TEXT_OBJ:.o=.d) $(PQ_FAKE_OBJ:.o=.d) $(OPENAPI_OBJ:.o=.d) $(TEST_BINS:=.d)
-include $(DEPS)

clean:
	rm -f $(TARGET) $(OBJS) $(TEST_BINS) $(UNITY_OBJ) $(STUB_OBJ) $(RL_STUB_OBJ) $(CVE_EXPLOIT_STUB_OBJ) $(HTTP_STUB_OBJ) $(HIBP_STUB_OBJ) $(DNS_STUB_OBJ) $(EXIFCLIENT_STUB_OBJ) $(EMAILCHECK_STUB_OBJ) $(TLSPROBE_STUB_OBJ) $(CACHE_STUB_OBJ) $(RDAP_STUB_OBJ) $(WAYBACK_STUB_OBJ) $(CERTSPOTTER_STUB_OBJ) $(SHODAN_STUB_OBJ) $(ABUSEIPDB_STUB_OBJ) $(SUBDOMAIN_STUB_OBJ) $(HEADER_FETCH_STUB_OBJ) $(QUOTA_STUB_OBJ) $(THROTTLE_STUB_OBJ) $(WHOIS_STUB_OBJ) $(X402_REQUEST_STUB_OBJS) $(REQUEST_TEXT_OBJ) $(PQ_FAKE_OBJ)
	rm -f $(DEPS) $(FUZZ_BINS) $(FUZZ_DEPS)
	rm -rf obj
