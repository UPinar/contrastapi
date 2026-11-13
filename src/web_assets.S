/* web_assets.S embeds the files of web/ and docs/API_Documentation.md in the binary
   with .incbin. The C side reads them through web_assets.h.

   WEB_ASSET writes one file: the symbol holds its bytes, and <symbol>ByteCount holds
   its length as 8 bytes. The length is the distance between two labels of one section,
   so the assembler writes it as a number and the linker never relocates it.

   .incbin reads its path from the directory make runs in, the repository root. */

.macro WEB_ASSET symbol, file
  .section .rodata
  .balign 16
  .global \symbol
  .type \symbol, %object
\symbol:
  .incbin "\file"
.L\symbol\()_end:
  .size \symbol, .L\symbol\()_end - \symbol
  .balign 8
  .global \symbol\()ByteCount
  .type \symbol\()ByteCount, %object
\symbol\()ByteCount:
  .8byte .L\symbol\()_end - \symbol
  .size \symbol\()ByteCount, 8
.endm

WEB_ASSET web_assets_styleCss,                       "web/static/style.css"
WEB_ASSET web_assets_pageCss,                        "web/static/css/page.css"
WEB_ASSET web_assets_landingJs,                      "web/static/js/landing.js"
WEB_ASSET web_assets_welcomeJs,                      "web/static/js/welcome.js"
WEB_ASSET web_assets_cryptoCheckoutJs,               "web/static/js/crypto_checkout.js"
WEB_ASSET web_assets_vendorKeysJs,                   "web/static/js/vendor_keys.js"
WEB_ASSET web_assets_themeInitJs,                    "web/static/js/theme-init.js"
WEB_ASSET web_assets_themeJs,                        "web/static/js/theme.js"
WEB_ASSET web_assets_geistMonoWoff2,                 "web/static/fonts/geist-mono.woff2"
WEB_ASSET web_assets_faviconSvg,                     "web/static/favicon.svg"
WEB_ASSET web_assets_favicon32Png,                   "web/static/favicon-32.png"
WEB_ASSET web_assets_favicon192Png,                  "web/static/favicon-192.png"
WEB_ASSET web_assets_appleTouchIconPng,              "web/static/apple-touch-icon.png"
WEB_ASSET web_assets_ogImagePng,                     "web/static/og-image.png"
WEB_ASSET web_assets_logoPhPng,                      "web/static/logo-ph.png"
WEB_ASSET web_assets_logoNavPng,                     "web/static/logo-nav.png"
WEB_ASSET web_assets_faviconIco,                     "web/favicon.ico"
WEB_ASSET web_assets_robotsTxt,                      "web/robots.txt"
WEB_ASSET web_assets_serverCardJson,                 "web/well-known/server-card.json"
WEB_ASSET web_assets_indexHtml,                      "web/pages/index.html"
WEB_ASSET web_assets_quickstartHtml,                 "web/pages/quickstart.html"
WEB_ASSET web_assets_mcpSetupHtml,                   "web/pages/mcp_setup.html"
WEB_ASSET web_assets_pricingHtml,                    "web/pages/pricing.html"
WEB_ASSET web_assets_botHtml,                        "web/pages/bot.html"
WEB_ASSET web_assets_cveApiHtml,                     "web/pages/cve_api.html"
WEB_ASSET web_assets_packageVulnerabilityApiHtml,    "web/pages/package_vulnerability_api.html"
WEB_ASSET web_assets_domainMonitoringApiHtml,        "web/pages/domain_monitoring_api.html"
WEB_ASSET web_assets_ipIntelligenceApiHtml,          "web/pages/ip_intelligence_api.html"
WEB_ASSET web_assets_securityMonitoringApiHtml,      "web/pages/security_monitoring_api.html"
WEB_ASSET web_assets_termsHtml,                      "web/pages/terms.html"
WEB_ASSET web_assets_privacyHtml,                    "web/pages/privacy.html"
WEB_ASSET web_assets_welcomeHtml,                    "web/pages/welcome.html"
WEB_ASSET web_assets_vendorKeysHtml,                 "web/pages/vendor_keys.html"
WEB_ASSET web_assets_navHtml,                        "web/pages/nav.html"
WEB_ASSET web_assets_footerHtml,                     "web/pages/footer.html"
WEB_ASSET web_assets_llmsTxt,                        "web/llms.txt"
WEB_ASSET web_assets_sitemapXml,                     "web/sitemap.xml"
WEB_ASSET web_assets_apiDocumentationMd,             "docs/API_Documentation.md"

/* Without this section the linker warns, and it marks the stack of the whole binary
   executable. %progbits and %object use %, not @: the GNU as manual names % for the ARM
   targets, where @ starts a comment. */
.section .note.GNU-stack,"",%progbits
