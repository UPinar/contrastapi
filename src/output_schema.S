/* output_schema.S embeds the output schemas of src/schema/ in the binary with .incbin.
   The C side reads them through output_schema.h.

   OUTPUT_SCHEMA writes one file: the symbol holds its bytes, and one 0 byte follows
   them. So C reads the symbol as a NUL-terminated string, and no length symbol is
   needed. A schema file holds no 0 byte, because it is JSON text.

   .incbin reads its path from the directory make runs in, the repository root. */

.macro OUTPUT_SCHEMA symbol, file
  .section .rodata
  .balign 16
  .global \symbol
  .type \symbol, %object
\symbol:
  .incbin "\file"
  .byte 0
.L\symbol\()_end:
  .size \symbol, .L\symbol\()_end - \symbol
.endm

OUTPUT_SCHEMA output_schema_health,    "src/schema/health.json"
OUTPUT_SCHEMA output_schema_kevLookup, "src/schema/kev_lookup.json"
OUTPUT_SCHEMA output_schema_cweLookup, "src/schema/cwe_lookup.json"
OUTPUT_SCHEMA output_schema_cveLookup, "src/schema/cve_lookup.json"
OUTPUT_SCHEMA output_schema_cveLookupBulk, "src/schema/cve_lookup_bulk.json"
OUTPUT_SCHEMA output_schema_cveSearch, "src/schema/cve_search.json"
OUTPUT_SCHEMA output_schema_cveLeading, "src/schema/cve_leading.json"
OUTPUT_SCHEMA output_schema_cveTriage, "src/schema/cve_triage.json"
OUTPUT_SCHEMA output_schema_cveTriageBulk, "src/schema/cve_triage_bulk.json"
OUTPUT_SCHEMA output_schema_epssRisers, "src/schema/epss_risers.json"
OUTPUT_SCHEMA output_schema_cveProducts, "src/schema/cve_products.json"
OUTPUT_SCHEMA output_schema_cveRiskScore, "src/schema/cve_risk_score.json"
OUTPUT_SCHEMA output_schema_cveExploit, "src/schema/cve_exploit.json"
OUTPUT_SCHEMA output_schema_productExposure, "src/schema/product_exposure.json"
OUTPUT_SCHEMA output_schema_cpeSearch, "src/schema/cpe_search.json"
OUTPUT_SCHEMA output_schema_cvssCalculator, "src/schema/cvss_calculator.json"
OUTPUT_SCHEMA output_schema_passwordCheck, "src/schema/password_check.json"
OUTPUT_SCHEMA output_schema_privacyMyData, "src/schema/privacy_my_data.json"
OUTPUT_SCHEMA output_schema_asnLookup, "src/schema/asn_lookup.json"
OUTPUT_SCHEMA output_schema_ipLookup, "src/schema/ip_lookup.json"
OUTPUT_SCHEMA output_schema_d3fendForAttack, "src/schema/d3fend_for_attack.json"
OUTPUT_SCHEMA output_schema_driverLookup, "src/schema/driver_lookup.json"
OUTPUT_SCHEMA output_schema_driverLookupBulk, "src/schema/driver_lookup_bulk.json"
OUTPUT_SCHEMA output_schema_packageCheck, "src/schema/package_check.json"
OUTPUT_SCHEMA output_schema_packageCheckBulk, "src/schema/package_check_bulk.json"
OUTPUT_SCHEMA output_schema_dnsLookup, "src/schema/dns_lookup.json"
OUTPUT_SCHEMA output_schema_dnsTakeoverCheck, "src/schema/dns_takeover_check.json"
OUTPUT_SCHEMA output_schema_emailAddressCheck, "src/schema/email_address_check.json"
OUTPUT_SCHEMA output_schema_emailAuthCheck, "src/schema/email_auth_check.json"
OUTPUT_SCHEMA output_schema_whoisLookup, "src/schema/whois_lookup.json"
OUTPUT_SCHEMA output_schema_waybackLookup, "src/schema/wayback_lookup.json"
OUTPUT_SCHEMA output_schema_certSearch, "src/schema/cert_search.json"
OUTPUT_SCHEMA output_schema_subdomainEnum, "src/schema/subdomain_enum.json"
OUTPUT_SCHEMA output_schema_sslCheck, "src/schema/ssl_check.json"
OUTPUT_SCHEMA output_schema_headersCheck, "src/schema/headers_check.json"
OUTPUT_SCHEMA output_schema_redirectChain, "src/schema/redirect_chain.json"
OUTPUT_SCHEMA output_schema_wellKnown, "src/schema/well_known.json"
OUTPUT_SCHEMA output_schema_watchlistEdit, "src/schema/watchlist_edit.json"
OUTPUT_SCHEMA output_schema_watchlistEvents, "src/schema/watchlist_events.json"
OUTPUT_SCHEMA output_schema_vendorKeyEdit, "src/schema/vendor_key_edit.json"

/* Without this section the linker warns, and it marks the stack of the whole binary
   executable. %progbits and %object use %, not @: the GNU as manual names % for the ARM
   targets, where @ starts a comment. */
.section .note.GNU-stack,"",%progbits
