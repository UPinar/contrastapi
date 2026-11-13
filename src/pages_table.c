#include <assert.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pages.h"
#include "web_assets.h"
#include "mcp.h"
#include "version.h"
#include "ratelimit.h"
#include "maintenance.h"
#include "cve.h"
#include "lol.h"
#include "package.h"
#include "http.h"
#include "pricing.h"
#include "usagelog.h"

#define PAGES_STATIC_CACHE_CONTROL     "public, max-age=3600"
#define PAGES_DISCOVERY_CACHE_CONTROL  "public, max-age=600"
#define PAGES_HTML_CACHE_CONTROL       "public, max-age=300"

#define PAGES_HTML_EXTRA_HEADERS \
  "Content-Security-Policy: default-src 'self'; " \
  "style-src 'self'; script-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; " \
  "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\n"

#define PAGES_RENDER_BUF_SIZE          262144
#define PAGES_NUMBER_BUF_SIZE          16
#define PAGES_USDC_ATOMIC_PER_USD      1000000
#define PAGES_USDC_ATOMIC_PER_CENT     10000
_Static_assert(PRICING_X402_USDC_ATOMIC_PER_CREDIT % PAGES_USDC_ATOMIC_PER_CENT == 0,
               "the price of a credit must be a whole number of cents to be written as dollars and cents");
#define PAGES_CONTENT_VERSION_BUF_SIZE 9

typedef struct {
  const char*          mp_name;
  const unsigned char* mp_asset;
  const uint64_t*      mp_assetByteCount;
} PagesTableFragment_t;

const PagesSource_t pages_sources[] = {
  {
    .mp_httpPath       = "/",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_indexHtml,
    .mp_assetByteCount = &web_assets_indexHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/quickstart",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_quickstartHtml,
    .mp_assetByteCount = &web_assets_quickstartHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/mcp-setup",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_mcpSetupHtml,
    .mp_assetByteCount = &web_assets_mcpSetupHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/pricing",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_pricingHtml,
    .mp_assetByteCount = &web_assets_pricingHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/bot",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_botHtml,
    .mp_assetByteCount = &web_assets_botHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/cve-api",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_cveApiHtml,
    .mp_assetByteCount = &web_assets_cveApiHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/package-vulnerability-api",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_packageVulnerabilityApiHtml,
    .mp_assetByteCount = &web_assets_packageVulnerabilityApiHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/domain-monitoring-api",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_domainMonitoringApiHtml,
    .mp_assetByteCount = &web_assets_domainMonitoringApiHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/ip-intelligence-api",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_ipIntelligenceApiHtml,
    .mp_assetByteCount = &web_assets_ipIntelligenceApiHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/security-monitoring-api",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_securityMonitoringApiHtml,
    .mp_assetByteCount = &web_assets_securityMonitoringApiHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/terms",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_termsHtml,
    .mp_assetByteCount = &web_assets_termsHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/privacy",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_privacyHtml,
    .mp_assetByteCount = &web_assets_privacyHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/welcome",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_welcomeHtml,
    .mp_assetByteCount = &web_assets_welcomeHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/vendor-keys",
    .mp_contentType    = "text/html; charset=utf-8",
    .mp_cacheControl   = PAGES_HTML_CACHE_CONTROL,
    .mp_extraHeaders   = PAGES_HTML_EXTRA_HEADERS,
    .mp_asset          = web_assets_vendorKeysHtml,
    .mp_assetByteCount = &web_assets_vendorKeysHtmlByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/static/style.css",
    .mp_contentType    = "text/css; charset=utf-8",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_styleCss,
    .mp_assetByteCount = &web_assets_styleCssByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/css/page.css",
    .mp_contentType    = "text/css; charset=utf-8",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_pageCss,
    .mp_assetByteCount = &web_assets_pageCssByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/js/landing.js",
    .mp_contentType    = "text/javascript; charset=utf-8",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_landingJs,
    .mp_assetByteCount = &web_assets_landingJsByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/js/welcome.js",
    .mp_contentType    = "text/javascript; charset=utf-8",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_welcomeJs,
    .mp_assetByteCount = &web_assets_welcomeJsByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/js/crypto_checkout.js",
    .mp_contentType    = "text/javascript; charset=utf-8",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_cryptoCheckoutJs,
    .mp_assetByteCount = &web_assets_cryptoCheckoutJsByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/js/vendor_keys.js",
    .mp_contentType    = "text/javascript; charset=utf-8",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_vendorKeysJs,
    .mp_assetByteCount = &web_assets_vendorKeysJsByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/js/theme-init.js",
    .mp_contentType    = "text/javascript; charset=utf-8",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_themeInitJs,
    .mp_assetByteCount = &web_assets_themeInitJsByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/js/theme.js",
    .mp_contentType    = "text/javascript; charset=utf-8",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_themeJs,
    .mp_assetByteCount = &web_assets_themeJsByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/fonts/geist-mono.woff2",
    .mp_contentType    = "font/woff2",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_geistMonoWoff2,
    .mp_assetByteCount = &web_assets_geistMonoWoff2ByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/favicon.svg",
    .mp_contentType    = "image/svg+xml",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_faviconSvg,
    .mp_assetByteCount = &web_assets_faviconSvgByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/favicon-32.png",
    .mp_contentType    = "image/png",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_favicon32Png,
    .mp_assetByteCount = &web_assets_favicon32PngByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/favicon-192.png",
    .mp_contentType    = "image/png",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_favicon192Png,
    .mp_assetByteCount = &web_assets_favicon192PngByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/apple-touch-icon.png",
    .mp_contentType    = "image/png",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_appleTouchIconPng,
    .mp_assetByteCount = &web_assets_appleTouchIconPngByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/og-image.png",
    .mp_contentType    = "image/png",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_ogImagePng,
    .mp_assetByteCount = &web_assets_ogImagePngByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/logo-ph.png",
    .mp_contentType    = "image/png",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_logoPhPng,
    .mp_assetByteCount = &web_assets_logoPhPngByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/static/logo-nav.png",
    .mp_contentType    = "image/png",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_logoNavPng,
    .mp_assetByteCount = &web_assets_logoNavPngByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/favicon.ico",
    .mp_contentType    = "image/x-icon",
    .mp_cacheControl   = PAGES_STATIC_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_faviconIco,
    .mp_assetByteCount = &web_assets_faviconIcoByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/robots.txt",
    .mp_contentType    = "text/plain; charset=utf-8",
    .mp_cacheControl   = PAGES_DISCOVERY_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_robotsTxt,
    .mp_assetByteCount = &web_assets_robotsTxtByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/llms.txt",
    .mp_contentType    = "text/plain; charset=utf-8",
    .mp_cacheControl   = PAGES_DISCOVERY_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_llmsTxt,
    .mp_assetByteCount = &web_assets_llmsTxtByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/llms-full.txt",
    .mp_contentType    = "text/plain; charset=utf-8",
    .mp_cacheControl   = PAGES_DISCOVERY_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_apiDocumentationMd,
    .mp_assetByteCount = &web_assets_apiDocumentationMdByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/sitemap.xml",
    .mp_contentType    = "application/xml",
    .mp_cacheControl   = PAGES_DISCOVERY_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_sitemapXml,
    .mp_assetByteCount = &web_assets_sitemapXmlByteCount,
    .m_isTemplate      = false,
  },
  {
    .mp_httpPath       = "/.well-known/mcp/server-card.json",
    .mp_contentType    = "application/json",
    .mp_cacheControl   = PAGES_DISCOVERY_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_serverCardJson,
    .mp_assetByteCount = &web_assets_serverCardJsonByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/.well-known/mcp-server.json",
    .mp_contentType    = "application/json",
    .mp_cacheControl   = PAGES_DISCOVERY_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_serverCardJson,
    .mp_assetByteCount = &web_assets_serverCardJsonByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/mcp.json",
    .mp_contentType    = "application/json",
    .mp_cacheControl   = PAGES_DISCOVERY_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_serverCardJson,
    .mp_assetByteCount = &web_assets_serverCardJsonByteCount,
    .m_isTemplate      = true,
  },
  {
    .mp_httpPath       = "/.well-known/mcp.json",
    .mp_contentType    = "application/json",
    .mp_cacheControl   = PAGES_DISCOVERY_CACHE_CONTROL,
    .mp_extraHeaders   = "",
    .mp_asset          = web_assets_serverCardJson,
    .mp_assetByteCount = &web_assets_serverCardJsonByteCount,
    .m_isTemplate      = true,
  },
};

static const PagesTableFragment_t PAGES_FRAGMENTS[] = {
  { "NAV",    web_assets_navHtml,    &web_assets_navHtmlByteCount },
  { "FOOTER", web_assets_footerHtml, &web_assets_footerHtmlByteCount },
};

#define PAGES_FILE_COUNT     ((int)(sizeof(pages_sources) / sizeof(pages_sources[0])))
#define PAGES_FRAGMENT_COUNT ((int)(sizeof(PAGES_FRAGMENTS) / sizeof(PAGES_FRAGMENTS[0])))

const int pages_sourceCount = PAGES_FILE_COUNT;

static PagesFile_t g_files[PAGES_FILE_COUNT];
static int         g_fileCount = 0;
static char        g_renderBuffer[PAGES_RENDER_BUF_SIZE];

static void static_formatUsdcAmount(unsigned int atomic_count, char* text_out, size_t text_size)
{
  assert(atomic_count % PAGES_USDC_ATOMIC_PER_CENT == 0);
  int text_len = snprintf(text_out, text_size, "%u.%02u", atomic_count / PAGES_USDC_ATOMIC_PER_USD,
                          (atomic_count % PAGES_USDC_ATOMIC_PER_USD) / PAGES_USDC_ATOMIC_PER_CENT);
  assert(text_len > 0 && (size_t)text_len < text_size);
  (void)text_len;
}

static void static_formatNumber(int number, char* text_out, size_t text_size)
{
  int text_len = snprintf(text_out, text_size, "%d", number);
  assert(text_len > 0 && (size_t)text_len < text_size);
  (void)text_len;
}

static void static_formatContentVersion(const unsigned char* bytes, uint64_t byte_count, char* text_out, size_t text_size)
{
  uint32_t hash = 2166136261u;
  for (uint64_t i = 0; i < byte_count; i++)
  {
    hash ^= bytes[i];
    hash *= 16777619u;
  }
  int text_len = snprintf(text_out, text_size, "%08" PRIx32, hash);
  assert(text_len == PAGES_CONTENT_VERSION_BUF_SIZE - 1 && (size_t)text_len < text_size);
  (void)text_len;
}

static bool static_renderIntoFreeSpace(const PagesTemplate_t* page_template, size_t* used_byte_count, PagesRendered_t* result_out)
{
  if (*used_byte_count >= sizeof(g_renderBuffer))
    return false;

  result_out->mp_text    = g_renderBuffer + *used_byte_count;
  result_out->m_capacity = sizeof(g_renderBuffer) - *used_byte_count;
  if (!pages_render(page_template, result_out))
    return false;

  *used_byte_count += result_out->m_byteCount + 1;
  return true;
}

static bool static_renderFragments(size_t* used_byte_count, const char* fragment_texts_out[PAGES_FRAGMENT_COUNT])
{
  for (int i = 0; i < PAGES_FRAGMENT_COUNT; i++)
  {
    PagesTemplate_t fragment_template = {
      .mp_text      = (const char*)PAGES_FRAGMENTS[i].mp_asset,
      .m_byteCount  = (size_t)*PAGES_FRAGMENTS[i].mp_assetByteCount,
      .mp_values    = NULL,
      .m_valueCount = 0,
    };
    PagesRendered_t rendered = {
      .mp_text     = NULL,
      .m_capacity  = 0,
      .m_byteCount = 0,
    };
    if (!static_renderIntoFreeSpace(&fragment_template, used_byte_count, &rendered))
    {
      fprintf(stderr, "pages_init: fragment %s could not be rendered\n", PAGES_FRAGMENTS[i].mp_name);
      return false;
    }
    fragment_texts_out[i] = rendered.mp_text;
  }
  return true;
}

static bool static_buildFiles(const PagesValue_t* values, int value_count, size_t* used_byte_count)
{
  for (int i = 0; i < PAGES_FILE_COUNT; i++)
  {
    const PagesSource_t* source = &pages_sources[i];
    PagesFile_t* file = &g_files[i];
    file->mp_httpPath     = source->mp_httpPath;
    file->mp_contentType  = source->mp_contentType;
    file->mp_cacheControl = source->mp_cacheControl;
    file->mp_extraHeaders = source->mp_extraHeaders;

    if (!source->m_isTemplate)
    {
      file->mp_body         = source->mp_asset;
      file->m_bodyByteCount = (size_t)*source->mp_assetByteCount;
      continue;
    }

    PagesTemplate_t page_template = {
      .mp_text      = (const char*)source->mp_asset,
      .m_byteCount  = (size_t)*source->mp_assetByteCount,
      .mp_values    = values,
      .m_valueCount = value_count,
    };
    PagesRendered_t rendered = {
      .mp_text     = NULL,
      .m_capacity  = 0,
      .m_byteCount = 0,
    };
    if (!static_renderIntoFreeSpace(&page_template, used_byte_count, &rendered))
    {
      fprintf(stderr, "pages_init: %s could not be rendered\n", source->mp_httpPath);
      return false;
    }
    file->mp_body         = (const unsigned char*)rendered.mp_text;
    file->m_bodyByteCount = rendered.m_byteCount;
  }
  return true;
}

bool pages_init(int tool_count)
{
  assert(tool_count >= 0);

  g_fileCount = 0;
  size_t used_byte_count = 0;

  const char* fragment_texts[PAGES_FRAGMENT_COUNT];
  if (!static_renderFragments(&used_byte_count, fragment_texts))
    return false;

  char tool_count_text[PAGES_NUMBER_BUF_SIZE];
  char anon_limit_text[PAGES_NUMBER_BUF_SIZE];
  char key_limit_text[PAGES_NUMBER_BUF_SIZE];
  char lookup_bulk_max_text[PAGES_NUMBER_BUF_SIZE];
  char triage_bulk_max_text[PAGES_NUMBER_BUF_SIZE];
  char driver_bulk_max_text[PAGES_NUMBER_BUF_SIZE];
  char package_bulk_max_text[PAGES_NUMBER_BUF_SIZE];
  char pro_monthly_text[PAGES_NUMBER_BUF_SIZE];
  char pro_yearly_text[PAGES_NUMBER_BUF_SIZE];
  char x402_usd_per_credit_text[PAGES_NUMBER_BUF_SIZE];
  char rl_retention_minutes_text[PAGES_NUMBER_BUF_SIZE];
  char maintenance_minutes_text[PAGES_NUMBER_BUF_SIZE];
  char usagelog_days_text[PAGES_NUMBER_BUF_SIZE];
  static_formatNumber(tool_count,                 tool_count_text,        sizeof(tool_count_text));
  static_formatNumber(RL_ANON_CREDIT_LIMIT,       anon_limit_text,        sizeof(anon_limit_text));
  static_formatNumber(RL_KEY_CREDIT_LIMIT,        key_limit_text,         sizeof(key_limit_text));
  static_formatNumber(CVELOOKUPBULK_MAX_IDS,      lookup_bulk_max_text,   sizeof(lookup_bulk_max_text));
  static_formatNumber(CVETRIAGEBULK_MAX_IDS,      triage_bulk_max_text,   sizeof(triage_bulk_max_text));
  static_formatNumber(DRIVERLOOKUPBULK_MAX_IDS,   driver_bulk_max_text,   sizeof(driver_bulk_max_text));
  static_formatNumber(PACKAGECHECKBULK_MAX_ITEMS, package_bulk_max_text,  sizeof(package_bulk_max_text));
  static_formatNumber(PRICING_PRO_MONTHLY_USD,    pro_monthly_text,       sizeof(pro_monthly_text));
  static_formatNumber(PRICING_PRO_YEARLY_USD,     pro_yearly_text,        sizeof(pro_yearly_text));
  static_formatUsdcAmount(PRICING_X402_USDC_ATOMIC_PER_CREDIT, x402_usd_per_credit_text, sizeof(x402_usd_per_credit_text));
  static_formatNumber(RL_RETENTION_MAX_SECONDS / 60,     rl_retention_minutes_text, sizeof(rl_retention_minutes_text));
  static_formatNumber(MAINTENANCE_INTERVAL_SECONDS / 60, maintenance_minutes_text,  sizeof(maintenance_minutes_text));
  static_formatNumber(USAGELOG_RETENTION_DAYS,           usagelog_days_text,        sizeof(usagelog_days_text));

  char style_css_version[PAGES_CONTENT_VERSION_BUF_SIZE];
  char page_css_version[PAGES_CONTENT_VERSION_BUF_SIZE];
  char landing_js_version[PAGES_CONTENT_VERSION_BUF_SIZE];
  char welcome_js_version[PAGES_CONTENT_VERSION_BUF_SIZE];
  char crypto_checkout_js_version[PAGES_CONTENT_VERSION_BUF_SIZE];
  char vendor_keys_js_version[PAGES_CONTENT_VERSION_BUF_SIZE];
  char theme_init_js_version[PAGES_CONTENT_VERSION_BUF_SIZE];
  char theme_js_version[PAGES_CONTENT_VERSION_BUF_SIZE];
  static_formatContentVersion(web_assets_styleCss,  web_assets_styleCssByteCount,  style_css_version,  sizeof(style_css_version));
  static_formatContentVersion(web_assets_pageCss,   web_assets_pageCssByteCount,   page_css_version,   sizeof(page_css_version));
  static_formatContentVersion(web_assets_landingJs, web_assets_landingJsByteCount, landing_js_version, sizeof(landing_js_version));
  static_formatContentVersion(web_assets_welcomeJs, web_assets_welcomeJsByteCount, welcome_js_version, sizeof(welcome_js_version));
  static_formatContentVersion(web_assets_cryptoCheckoutJs, web_assets_cryptoCheckoutJsByteCount, crypto_checkout_js_version, sizeof(crypto_checkout_js_version));
  static_formatContentVersion(web_assets_vendorKeysJs, web_assets_vendorKeysJsByteCount, vendor_keys_js_version, sizeof(vendor_keys_js_version));
  static_formatContentVersion(web_assets_themeInitJs, web_assets_themeInitJsByteCount, theme_init_js_version, sizeof(theme_init_js_version));
  static_formatContentVersion(web_assets_themeJs,     web_assets_themeJsByteCount,     theme_js_version,      sizeof(theme_js_version));

  const PagesValue_t values[] = {
    { "TOOL_COUNT",                   tool_count_text            },
    { "VERSION",                      CONTRASTAPI_VERSION        },
    { "MCP_PROTOCOL_VERSION",         MCP_PROTOCOL_VERSION       },
    { "MCP_SERVER_INSTRUCTIONS",      MCP_SERVER_INSTRUCTIONS    },
    { "RL_ANON_CREDIT_LIMIT",         anon_limit_text            },
    { "RL_KEY_CREDIT_LIMIT",          key_limit_text             },
    { "CVELOOKUPBULK_MAX_IDS",        lookup_bulk_max_text       },
    { "CVETRIAGEBULK_MAX_IDS",        triage_bulk_max_text       },
    { "DRIVERLOOKUPBULK_MAX_IDS",     driver_bulk_max_text       },
    { "PACKAGECHECKBULK_MAX_ITEMS",   package_bulk_max_text      },
    { "PRICING_PRO_MONTHLY_USD",      pro_monthly_text           },
    { "PRICING_PRO_YEARLY_USD",       pro_yearly_text            },
    { "PRICING_X402_USD_PER_CREDIT",  x402_usd_per_credit_text   },
    { "RL_RETENTION_MAX_MINUTES",     rl_retention_minutes_text  },
    { "MAINTENANCE_INTERVAL_MINUTES", maintenance_minutes_text   },
    { "USAGELOG_RETENTION_DAYS",      usagelog_days_text         },
    { "HTTP_USER_AGENT",              HTTP_USER_AGENT            },
    { "STYLE_CSS_VERSION",            style_css_version          },
    { "PAGE_CSS_VERSION",             page_css_version           },
    { "LANDING_JS_VERSION",           landing_js_version         },
    { "WELCOME_JS_VERSION",           welcome_js_version         },
    { "CRYPTO_CHECKOUT_JS_VERSION",   crypto_checkout_js_version },
    { "VENDOR_KEYS_JS_VERSION",       vendor_keys_js_version     },
    { "THEME_INIT_JS_VERSION",        theme_init_js_version      },
    { "THEME_JS_VERSION",             theme_js_version           },
    { "NAV",                          fragment_texts[0]          },
    { "FOOTER",                       fragment_texts[1]          },
  };
  const int value_count = (int)(sizeof(values) / sizeof(values[0]));
  assert(strcmp(values[value_count - 2].mp_name, PAGES_FRAGMENTS[0].mp_name) == 0);
  assert(strcmp(values[value_count - 1].mp_name, PAGES_FRAGMENTS[1].mp_name) == 0);

  if (!static_buildFiles(values, value_count, &used_byte_count))
    return false;

  g_fileCount = PAGES_FILE_COUNT;
  return true;
}

const PagesFile_t* pages_findServedFile(const char* http_path)
{
  return pages_findFileByPath(g_files, g_fileCount, http_path);
}
