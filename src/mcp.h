#ifndef MCP_H
#define MCP_H

#include <stddef.h>
#include <stdbool.h>
#include <libpq-fe.h>

#include "jsonread.h"
#include "jsonrpc.h"
#include "picohttpparser.h"
#include "request.h"
#include "endpoint.h"
#include "pricing.h"

#define MCP_TOOL_NAME_MAX_LEN               32

#define MCP_PROTOCOL_VERSION "2025-11-25"

#define MCP_SERVER_INSTRUCTIONS \
  "ContrastAPI is a security data and monitoring server, with " \
  "watchlists of CVEs, packages, domains and IP addresses. "    \
  "Call cve_lookup for a CVE, package_check for a package, "    \
  "dns_lookup for a domain and ip_lookup for an IP address. "   \
  "Call watchlist_edit and watchlist_events for monitoring, "   \
  "which needs an API key. A Pro API key is sold at "           \
  PRICING_PAGE_URL ". "                                         \
  "It looks up, searches and scores CVE, KEV and CWE records. " \
  "It gives public exploit intelligence. It decodes and "       \
  "scores a CVSS v3 "                                           \
  "vector. It checks a password's SHA-1 against Have I Been "   \
  "Pwned. It reads a domain's DNS records and checks a host "   \
  "name for a dangling CNAME. It checks a domain's SPF, "       \
  "DMARC, DKIM and MTA-STS records. It checks whether an "      \
  "e-mail address's domain takes mail and whether the address " \
  "is disposable. It checks the TLS certificate and settings "  \
  "of a host name and rates the security headers of a web "     \
  "site. It looks up the registration of a domain name over "   \
  "RDAP or WHOIS. It lists the Wayback Machine captures of a "  \
  "host name. It lists the unexpired certificates that "        \
  "Certificate Transparency logs hold for a host name. It "     \
  "lists the subdomains of a registrable domain from "          \
  "Certificate Transparency and DNS. It names the MITRE "       \
  "D3FEND defenses that counter a MITRE ATT&CK technique. It "  \
  "finds a driver file hash in the LOLDrivers catalog. It "     \
  "looks up the AS, the country, the cloud range, the Tor "     \
  "exit and the DROP listing of a public IP address. It looks " \
  "up an AS by its number or by an address it holds. It "       \
  "checks a package or a list of packages of nine ecosystems "  \
  "against OSV.dev advisories and malicious packages. It "      \
  "gives the end-of-life dates of a product or a package from " \
  "endoflife.date. The watchlist keeps CVE, package, domain "   \
  "and IP items for an API key, and watchlist_events reads "    \
  "their change events. A Pro API key can save its own Shodan " \
  "and AbuseIPDB keys with vendor_key_edit, and ip_lookup "     \
  "then adds their answers. It says what it keeps about the "   \
  "caller. "                                                    \
  "A call with no API key and no credits left can pay per "     \
  "call with x402 in USDC on Solana."

#define MCP_HEADER_PROTOCOL_VERSION_MAX_LEN 40
#define MCP_HEADER_METHOD_MAX_LEN           64
#define MCP_HEADER_NAME_MAX_LEN             64

typedef struct {
  bool m_hasProtocolVersion;
  char ma_protocolVersion[MCP_HEADER_PROTOCOL_VERSION_MAX_LEN + 1];
  bool m_hasMethod;
  char ma_method[MCP_HEADER_METHOD_MAX_LEN + 1];
  bool m_hasName;
  char ma_name[MCP_HEADER_NAME_MAX_LEN + 1];
  bool m_duplicated;
} McpRoutingHeaders_t;

void mcp_readRoutingHeaders(const struct phr_header* headers, size_t header_count, McpRoutingHeaders_t* headers_out);

#define MCP_META_KEY_X402_PAYMENT          "x402/payment"
#define MCP_META_KEY_X402_PAYMENT_RESPONSE "x402/payment-response"

typedef enum {
  MCP_PAYMENT_META_NONE,
  MCP_PAYMENT_META_FOUND,
  MCP_PAYMENT_META_REPEATED
} McpPaymentMetaStatus_t;

typedef struct {
  McpPaymentMetaStatus_t m_status;
  JsonReadSpan_t         m_span;
} McpPaymentMeta_t;

typedef struct {
  bool                m_isRun;
  EndpointRunStatus_t m_runStatus;
  const Endpoint_t*   mp_endpoint;
  size_t              m_resultMetaOffset;
} McpRunReport_t;

bool  mcp_isModernEra                (const McpRoutingHeaders_t* routing_headers);
bool  mcp_dispatch                   (const char* body, size_t len, const McpRoutingHeaders_t* routing_headers, char** json_out, int* status_out, PGconn* conn, const RequestCharge_t* charge, McpRunReport_t* run_report_out);
bool  mcp_tryBuildModernRefusal      (const char* body, size_t len, const McpRoutingHeaders_t* routing_headers, char** json_out, int* status_out);
void  mcp_readPaymentMeta            (const char* body, McpPaymentMeta_t* meta_out);
char* mcp_buildResultWithMeta        (const char* response_json, size_t meta_offset, const char* meta_key, const char* meta_value_json);
char* mcp_buildPaymentRequiredResult (const char* id_raw, const char* payment_required_json, bool is_modern);
char* mcp_buildToolErrorResult       (const char* id_raw, const char* text, bool is_modern);

typedef enum {
  MCP_TOOL_CALL_OK = 0,
  MCP_TOOL_CALL_NO_PARAMS,
  MCP_TOOL_CALL_NO_NAME,
  MCP_TOOL_CALL_BAD_NAME,
} McpToolCallStatus_t;

McpToolCallStatus_t mcp_readToolCall(const JsonRpcRequest_t* request, char name_out[MCP_TOOL_NAME_MAX_LEN + 1], JsonReadSpan_t* args_out);

void mcp_creditCost(const char* body, EndpointPrice_t* price_out);

#endif
