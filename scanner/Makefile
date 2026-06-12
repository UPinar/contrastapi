CC = gcc
CFLAGS = -Wall -Wextra -O2
# Use curl-impersonate-chrome if available, fall back to standard libcurl
CURL_IMP := $(shell pkg-config --exists libcurl-impersonate-chrome 2>/dev/null && echo yes)
ifeq ($(CURL_IMP),yes)
  CURL_LIB = $(shell pkg-config --libs libcurl-impersonate-chrome)
  CFLAGS += -DHAVE_CURL_IMPERSONATE
else ifneq ($(wildcard /usr/local/lib/libcurl-impersonate-chrome.so),)
  CURL_LIB = -lcurl-impersonate-chrome
  CFLAGS += -DHAVE_CURL_IMPERSONATE
else
  CURL_LIB = -lcurl
endif
LIBS = $(CURL_LIB) -lssl -lcrypto -lresolv -lcjson

all: contrastscan

contrastscan: src/contrastscan.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# unit tests
test: tests/test_scoring.c
	$(CC) $(CFLAGS) -o test_scoring $< -lcjson
	./test_scoring

# integration tests (requires network + jq)
test-integration: contrastscan
	bash tests/test_integration.sh

# standalone modules (development/debug)
headers: src/headers.c
	$(CC) $(CFLAGS) -o $@ $< -lcurl -lcjson

ssl_check: src/ssl_check.c
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto -lcjson

dns_check: src/dns_check.c
	$(CC) $(CFLAGS) -o $@ $< -lresolv -lcjson

clean:
	rm -f contrastscan headers ssl_check dns_check test_scoring

.PHONY: all test test-integration clean
