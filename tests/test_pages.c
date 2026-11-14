#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "unity/unity.h"
#include "pages.h"
#include "response.h"
#include "mcp.h"
#include "version.h"
#include "ratelimit.h"
#include "usagelog.h"
#include "maintenance.h"
#include "pricing.h"
#include "cve.h"
#include "lol.h"
#include "package.h"
#include "http.h"

#define RESP_BUF 4096

void setUp(void)    {}
void tearDown(void) { response_setHeadRequest(false); }

static const unsigned char FIXTURE_NUL_BODY[] = { 'a', '\0', 'b' };

static const PagesFile_t FIXTURE_FILES[] = {
  { "/static/style.css", "text/css; charset=utf-8",   "public, max-age=3600", "", (const unsigned char*)"body{}", 6 },
  { "/robots.txt",       "text/plain; charset=utf-8", "public, max-age=600",  "", (const unsigned char*)"User-agent: *\n", 14 },
  { "/page",             "text/html; charset=utf-8",  "max-age=300",          "Content-Security-Policy: default-src 'self'\r\n", (const unsigned char*)"<p>hi</p>", 9 },
  { "/nul",              "application/octet-stream",  "no-store",             "", FIXTURE_NUL_BODY, sizeof(FIXTURE_NUL_BODY) },
};
static const int FIXTURE_FILE_COUNT = (int)(sizeof(FIXTURE_FILES) / sizeof(FIXTURE_FILES[0]));

#define HTML_CSP \
  "Content-Security-Policy: default-src 'self'; " \
  "style-src 'self'; script-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; " \
  "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\n"

typedef struct {
  const char* mp_httpPath;
  const char* mp_contentType;
  const char* mp_cacheControl;
  const char* mp_extraHeaders;
  const char* mp_sourcePath;
} ServedFile_t;

static const ServedFile_t SERVED_FILES[] = {
  { "/",                               "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/quickstart",                     "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/mcp-setup",                      "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/pricing",                        "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/bot",                            "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/cve-api",                        "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/package-vulnerability-api",      "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/domain-monitoring-api",          "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/ip-intelligence-api",            "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/security-monitoring-api",        "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/terms",                          "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/privacy",                        "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/welcome",                        "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/vendor-keys",                    "text/html; charset=utf-8",       "public, max-age=300",  HTML_CSP, NULL },
  { "/static/style.css",               "text/css; charset=utf-8",        "public, max-age=3600", "", "web/static/style.css" },
  { "/static/css/page.css",            "text/css; charset=utf-8",        "public, max-age=3600", "", "web/static/css/page.css" },
  { "/static/js/landing.js",           "text/javascript; charset=utf-8", "public, max-age=3600", "", "web/static/js/landing.js" },
  { "/static/js/welcome.js",           "text/javascript; charset=utf-8", "public, max-age=3600", "", "web/static/js/welcome.js" },
  { "/static/js/crypto_checkout.js",   "text/javascript; charset=utf-8", "public, max-age=3600", "", "web/static/js/crypto_checkout.js" },
  { "/static/js/vendor_keys.js",       "text/javascript; charset=utf-8", "public, max-age=3600", "", "web/static/js/vendor_keys.js" },
  { "/static/js/theme-init.js",        "text/javascript; charset=utf-8", "public, max-age=3600", "", "web/static/js/theme-init.js" },
  { "/static/js/theme.js",             "text/javascript; charset=utf-8", "public, max-age=3600", "", "web/static/js/theme.js" },
  { "/static/fonts/geist-mono.woff2",  "font/woff2",                     "public, max-age=3600", "", "web/static/fonts/geist-mono.woff2" },
  { "/static/favicon.svg",             "image/svg+xml",                  "public, max-age=3600", "", "web/static/favicon.svg" },
  { "/static/favicon-32.png",          "image/png",                      "public, max-age=3600", "", "web/static/favicon-32.png" },
  { "/static/favicon-192.png",         "image/png",                      "public, max-age=3600", "", "web/static/favicon-192.png" },
  { "/static/apple-touch-icon.png",    "image/png",                      "public, max-age=3600", "", "web/static/apple-touch-icon.png" },
  { "/static/og-image.png",            "image/png",                      "public, max-age=3600", "", "web/static/og-image.png" },
  { "/static/logo-ph.png",             "image/png",                      "public, max-age=3600", "", "web/static/logo-ph.png" },
  { "/static/logo-nav.png",            "image/png",                      "public, max-age=3600", "", "web/static/logo-nav.png" },
  { "/favicon.ico",                    "image/x-icon",                   "public, max-age=3600", "", "web/favicon.ico" },
  { "/robots.txt",                     "text/plain; charset=utf-8",      "public, max-age=600",  "", "web/robots.txt" },
  { "/llms.txt",                       "text/plain; charset=utf-8",      "public, max-age=600",  "", NULL },
  { "/llms-full.txt",                  "text/plain; charset=utf-8",      "public, max-age=600",  "", "docs/API_Documentation.md" },
  { "/sitemap.xml",                    "application/xml",                "public, max-age=600",  "", "web/sitemap.xml" },
  { "/.well-known/mcp/server-card.json",          "application/json",    "public, max-age=600",  "", NULL },
  { "/.well-known/mcp-server.json",               "application/json",    "public, max-age=600",  "", NULL },
  { "/mcp.json",                                  "application/json",    "public, max-age=600",  "", NULL },
  { "/.well-known/mcp.json",                      "application/json",    "public, max-age=600",  "", NULL },
};
static const int SERVED_FILE_COUNT = (int)(sizeof(SERVED_FILES) / sizeof(SERVED_FILES[0]));

static const char* const UNLISTED_PAGE_PATHS[] = { "/welcome", "/vendor-keys" };

static bool static_isUnlistedPage(const char* http_path)
{
  for (size_t i = 0; i < sizeof(UNLISTED_PAGE_PATHS) / sizeof(UNLISTED_PAGE_PATHS[0]); i++)
  {
    if (strcmp(UNLISTED_PAGE_PATHS[i], http_path) == 0)
      return true;
  }
  return false;
}

#define SERVER_CARD_HEAD \
  "{\n" \
  "  \"$schema\": \"https://modelcontextprotocol.io/schemas/server-card.json\",\n" \
  "  \"version\": \"1.0\",\n" \
  "  \"protocolVersion\": \"" MCP_PROTOCOL_VERSION "\",\n" \
  "  \"serverInfo\": {\n" \
  "    \"name\": \"contrastapi\",\n" \
  "    \"title\": \"ContrastAPI: Security Data & Monitoring API, MCP Server\",\n" \
  "    \"description\": \"" MCP_SERVER_INSTRUCTIONS "\",\n" \
  "    \"version\": \"" CONTRASTAPI_VERSION "\",\n" \
  "    \"homepage\": \"https://api.contrastcyber.com/\",\n" \
  "    \"repository\": \"https://github.com/UPinar/contrastapi\"\n" \
  "  },\n" \
  "  \"transport\": [\n" \
  "    {\n" \
  "      \"type\": \"streamable-http\",\n" \
  "      \"url\": \"https://api.contrastcyber.com/mcp/\"\n" \
  "    }\n" \
  "  ],\n" \
  "  \"capabilities\": {\n" \
  "    \"tools\": true,\n" \
  "    \"resources\": false,\n" \
  "    \"prompts\": false\n" \
  "  },\n" \
  "  \"provider\": {\n" \
  "    \"name\": \"ContrastCyber\",\n" \
  "    \"url\": \"https://contrastcyber.com\"\n" \
  "  },\n" \
  "  \"auth\": \"none\",\n"

#define SERVER_CARD_TAIL \
  "  \"documentation\": \"https://github.com/UPinar/contrastapi/blob/main/docs/MCP_Documentation.md\"\n" \
  "}\n"

static size_t static_captureSend(const PagesFile_t* file, char* buf, size_t len)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    buf[0] = '\0';
    return 0;
  }
  pages_send(fds[1], file);
  close(fds[1]);
  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
  return n > 0 ? (size_t)n : 0;
}

void test_find_served_file_finds_nothing_before_init(void)
{
  TEST_ASSERT_TRUE(pages_sourceCount > 0);
  for (int i = 0; i < pages_sourceCount; i++)
    TEST_ASSERT_NULL_MESSAGE(pages_findServedFile(pages_sources[i].mp_httpPath), pages_sources[i].mp_httpPath);
}

void test_find_file_by_path_finds_every_path_of_the_table(void)
{
  for (int i = 0; i < FIXTURE_FILE_COUNT; i++)
    TEST_ASSERT_EQUAL_PTR_MESSAGE(&FIXTURE_FILES[i], pages_findFileByPath(FIXTURE_FILES, FIXTURE_FILE_COUNT, FIXTURE_FILES[i].mp_httpPath), FIXTURE_FILES[i].mp_httpPath);
}

void test_find_file_by_path_refuses_each_near_spelling(void)
{
  static const char* const near_paths[] = {
    "/static/../static/style.css", "/static/%2e%2e/style.css", "/static/STYLE.CSS",
    "/static/", "/static", "/static//style.css", "/static/./style.css",
    "/static/style.css/", "/static/style.css?v=1", "/static/style.css%00",
    "/staticstyle.css", "/static/style.cs", "/ROBOTS.TXT", "/robots.txtx",
    "/robots.tx", "/", "",
  };
  for (size_t i = 0; i < sizeof(near_paths) / sizeof(near_paths[0]); i++)
    TEST_ASSERT_NULL_MESSAGE(pages_findFileByPath(FIXTURE_FILES, FIXTURE_FILE_COUNT, near_paths[i]), near_paths[i]);
}

void test_find_file_by_path_in_an_empty_table_finds_nothing(void)
{
  TEST_ASSERT_NULL(pages_findFileByPath(FIXTURE_FILES, 0, "/static/style.css"));
}

void test_methods_are_get_and_head(void)
{
  TEST_ASSERT_EQUAL_STRING("GET",  pages_allowedMethods[0]);
  TEST_ASSERT_EQUAL_STRING("HEAD", pages_allowedMethods[1]);
  TEST_ASSERT_NULL(pages_allowedMethods[2]);

  TEST_ASSERT_TRUE(pages_isHttpMethodAllowed("GET"));
  TEST_ASSERT_TRUE(pages_isHttpMethodAllowed("HEAD"));
  static const char* const refused[] = { "POST", "PUT", "DELETE", "OPTIONS", "get", "head", "GETX", "HEA", "" };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(pages_isHttpMethodAllowed(refused[i]), refused[i]);
}

void test_send_writes_the_file_with_its_own_headers(void)
{
  char buf[RESP_BUF];
  static_captureSend(&FIXTURE_FILES[2], buf, sizeof(buf));
  TEST_ASSERT_EQUAL_STRING("HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/html; charset=utf-8\r\n"
                           "Content-Length: 9\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "X-Frame-Options: DENY\r\n"
                           "Referrer-Policy: no-referrer\r\n"
                           "Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n"
                           "Cache-Control: max-age=300\r\n"
                           "Content-Security-Policy: default-src 'self'\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "<p>hi</p>", buf);
}

void test_send_of_a_body_with_a_nul_sends_every_byte(void)
{
  char buf[RESP_BUF];
  size_t bytes_read = static_captureSend(&FIXTURE_FILES[3], buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: 3\r\n"));
  const char* head_end = strstr(buf, "\r\n\r\n");
  TEST_ASSERT_NOT_NULL(head_end);
  size_t head_byte_count = (size_t)(head_end - buf) + 4;
  TEST_ASSERT_EQUAL_UINT(head_byte_count + sizeof(FIXTURE_NUL_BODY), bytes_read);
  TEST_ASSERT_EQUAL_MEMORY(FIXTURE_NUL_BODY, buf + head_byte_count, sizeof(FIXTURE_NUL_BODY));
}

void test_head_request_gets_the_get_head_and_no_body(void)
{
  char get_buf[RESP_BUF];
  static_captureSend(&FIXTURE_FILES[2], get_buf, sizeof(get_buf));
  const char* get_head_end = strstr(get_buf, "\r\n\r\n");
  TEST_ASSERT_NOT_NULL(get_head_end);
  size_t head_byte_count = (size_t)(get_head_end - get_buf) + 4;

  response_setHeadRequest(true);
  char head_buf[RESP_BUF];
  size_t bytes_read = static_captureSend(&FIXTURE_FILES[2], head_buf, sizeof(head_buf));
  TEST_ASSERT_EQUAL_UINT(head_byte_count, bytes_read);
  TEST_ASSERT_EQUAL_MEMORY(get_buf, head_buf, head_byte_count);
}

void test_render_fills_each_known_placeholder(void)
{
  static const PagesValue_t values[] = { { "VERSION", "1.0.0" }, { "TOOL_COUNT", "15" } };
  static const char template_text[] = "v=@@VERSION@@ n=@@TOOL_COUNT@@ again=@@VERSION@@";
  const PagesTemplate_t page_template = { template_text, sizeof(template_text) - 1, values, 2 };
  char rendered_text[64];
  PagesRendered_t rendered = { rendered_text, sizeof(rendered_text), 99 };
  TEST_ASSERT_TRUE(pages_render(&page_template, &rendered));
  TEST_ASSERT_EQUAL_STRING("v=1.0.0 n=15 again=1.0.0", rendered_text);
  TEST_ASSERT_EQUAL_UINT(strlen("v=1.0.0 n=15 again=1.0.0"), rendered.m_byteCount);
}

void test_render_refuses_an_unknown_placeholder(void)
{
  static const PagesValue_t values[] = { { "VERSION", "1.0.0" } };
  static const char* const templates[] = { "a @@NOPE@@ b", "@@version@@", "@@VERSION_@@", "@@VERSIO@@" };
  for (size_t i = 0; i < sizeof(templates) / sizeof(templates[0]); i++)
  {
    const PagesTemplate_t page_template = { templates[i], strlen(templates[i]), values, 1 };
    char rendered_text[64] = "dirty";
    PagesRendered_t rendered = { rendered_text, sizeof(rendered_text), 99 };
    TEST_ASSERT_FALSE_MESSAGE(pages_render(&page_template, &rendered), templates[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", rendered_text, templates[i]);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, rendered.m_byteCount, templates[i]);
  }
}

void test_render_refuses_an_unclosed_placeholder(void)
{
  static const PagesValue_t values[] = { { "VERSION", "1.0.0" }, { "VERSION ", "1.0.0" }, { "VER-SION", "1.0.0" } };
  static const char* const templates[] = { "a @@VERSION", "a @@VERSION@", "@@@@", "x @@", "@@VERSION @@", "@@VER-SION@@" };
  for (size_t i = 0; i < sizeof(templates) / sizeof(templates[0]); i++)
  {
    const PagesTemplate_t page_template = { templates[i], strlen(templates[i]), values, 3 };
    char rendered_text[64];
    PagesRendered_t rendered = { rendered_text, sizeof(rendered_text), 99 };
    TEST_ASSERT_FALSE_MESSAGE(pages_render(&page_template, &rendered), templates[i]);
  }
}

void test_render_keeps_text_that_is_not_a_placeholder(void)
{
  static const char template_text[] = "{{ secrets.X }} a@b @ contact@contrastcyber.com";
  const PagesTemplate_t page_template = { template_text, sizeof(template_text) - 1, NULL, 0 };
  char rendered_text[64];
  PagesRendered_t rendered = { rendered_text, sizeof(rendered_text), 0 };
  TEST_ASSERT_TRUE(pages_render(&page_template, &rendered));
  TEST_ASSERT_EQUAL_STRING(template_text, rendered_text);
  TEST_ASSERT_EQUAL_UINT(sizeof(template_text) - 1, rendered.m_byteCount);
}

void test_render_reads_the_byte_count_it_is_given(void)
{
  static const PagesValue_t values[] = { { "VERSION", "1.0.0" } };
  char rendered_text[64];
  PagesRendered_t rendered = { rendered_text, sizeof(rendered_text), 0 };
  TEST_ASSERT_TRUE(pages_render(&(PagesTemplate_t){ "ab@@NOPE@@", 2, values, 1 }, &rendered));
  TEST_ASSERT_EQUAL_STRING("ab", rendered_text);
  TEST_ASSERT_EQUAL_UINT(2, rendered.m_byteCount);

  TEST_ASSERT_TRUE(pages_render(&(PagesTemplate_t){ "ab@@NOPE@@", 3, values, 1 }, &rendered));
  TEST_ASSERT_EQUAL_STRING("ab@", rendered_text);
  TEST_ASSERT_FALSE(pages_render(&(PagesTemplate_t){ "x@@VERSION@@", 11, values, 1 }, &rendered));

  char* exact_template = malloc(9);
  TEST_ASSERT_NOT_NULL(exact_template);
  memcpy(exact_template, "@@VERSION", 9);
  TEST_ASSERT_FALSE(pages_render(&(PagesTemplate_t){ exact_template, 9, values, 1 }, &rendered));
  free(exact_template);
}

void test_render_refuses_output_that_does_not_fit(void)
{
  static const PagesValue_t values[] = { { "VERSION", "1.0.0" } };
  const PagesTemplate_t version_template = { "v@@VERSION@@", 12, values, 1 };
  const PagesTemplate_t text_template    = { "abc", 3, values, 1 };
  char rendered_text[16];

  TEST_ASSERT_TRUE(pages_render(&version_template, &(PagesRendered_t){ rendered_text, 7, 0 }));
  TEST_ASSERT_EQUAL_STRING("v1.0.0", rendered_text);

  memcpy(rendered_text, "dirty", 6);
  PagesRendered_t rendered = { rendered_text, 6, 99 };
  TEST_ASSERT_FALSE(pages_render(&version_template, &rendered));
  TEST_ASSERT_EQUAL_STRING("", rendered_text);
  TEST_ASSERT_EQUAL_UINT(0, rendered.m_byteCount);

  TEST_ASSERT_TRUE(pages_render(&text_template, &(PagesRendered_t){ rendered_text, 4, 0 }));
  TEST_ASSERT_FALSE(pages_render(&text_template, &(PagesRendered_t){ rendered_text, 3, 0 }));
}

void test_init_serves_the_files_of_the_table_and_no_other(void)
{
  TEST_ASSERT_TRUE(pages_init(15));

  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    const PagesFile_t* file = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL_MESSAGE(file, SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(SERVED_FILES[i].mp_contentType,  file->mp_contentType,  SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(SERVED_FILES[i].mp_cacheControl, file->mp_cacheControl, SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(SERVED_FILES[i].mp_extraHeaders, file->mp_extraHeaders, SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(file->m_bodyByteCount > 0, SERVED_FILES[i].mp_httpPath);
  }

  TEST_ASSERT_EQUAL_INT(SERVED_FILE_COUNT, pages_sourceCount);
  for (int i = 0; i < pages_sourceCount; i++)
  {
    bool is_expected = false;
    for (int j = 0; j < SERVED_FILE_COUNT && !is_expected; j++)
      is_expected = strcmp(pages_sources[i].mp_httpPath, SERVED_FILES[j].mp_httpPath) == 0;
    TEST_ASSERT_TRUE_MESSAGE(is_expected, pages_sources[i].mp_httpPath);
  }
}

static unsigned char* static_readWholeFile(const char* path, size_t* byte_count_out)
{
  FILE* file = fopen(path, "rb");
  TEST_ASSERT_NOT_NULL_MESSAGE(file, path);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, fseek(file, 0, SEEK_END), path);
  long size = ftell(file);
  TEST_ASSERT_TRUE_MESSAGE(size > 0, path);
  rewind(file);
  unsigned char* bytes = malloc((size_t)size);
  TEST_ASSERT_NOT_NULL(bytes);
  size_t read_byte_count = fread(bytes, 1, (size_t)size, file);
  fclose(file);
  TEST_ASSERT_EQUAL_UINT_MESSAGE((size_t)size, read_byte_count, path);
  *byte_count_out = (size_t)size;
  return bytes;
}

void test_each_embedded_file_holds_the_bytes_of_its_source(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (SERVED_FILES[i].mp_sourcePath == NULL)
      continue;
    size_t source_byte_count = 0;
    unsigned char* source = static_readWholeFile(SERVED_FILES[i].mp_sourcePath, &source_byte_count);
    const PagesFile_t* file = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL_MESSAGE(file, SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(source_byte_count, file->m_bodyByteCount, SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, memcmp(source, file->mp_body, source_byte_count), SERVED_FILES[i].mp_httpPath);
    free(source);
  }
}

void test_server_card_holds_the_values_of_the_running_server(void)
{
  static const char* const card_paths[] = {
    "/.well-known/mcp/server-card.json", "/.well-known/mcp-server.json", "/mcp.json", "/.well-known/mcp.json",
  };
  static const char expected_card_7[]  = SERVER_CARD_HEAD "  \"tools_count\": 7,\n" SERVER_CARD_TAIL;
  static const char expected_card_15[] = SERVER_CARD_HEAD "  \"tools_count\": 15,\n" SERVER_CARD_TAIL;

  TEST_ASSERT_TRUE(pages_init(7));
  for (size_t i = 0; i < sizeof(card_paths) / sizeof(card_paths[0]); i++)
  {
    const PagesFile_t* card = pages_findServedFile(card_paths[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(card, card_paths[i]);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(sizeof(expected_card_7) - 1, card->m_bodyByteCount, card_paths[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, memcmp(expected_card_7, card->mp_body, card->m_bodyByteCount), card_paths[i]);
  }

  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* card = pages_findServedFile(card_paths[0]);
  TEST_ASSERT_NOT_NULL(card);
  TEST_ASSERT_EQUAL_UINT(sizeof(expected_card_15) - 1, card->m_bodyByteCount);
  TEST_ASSERT_EQUAL_INT(0, memcmp(expected_card_15, card->mp_body, card->m_bodyByteCount));
}

static bool static_bodyHolds(const PagesFile_t* file, const void* text, size_t text_byte_count)
{
  for (size_t at = 0; at + text_byte_count <= file->m_bodyByteCount; at++)
  {
    if (memcmp(file->mp_body + at, text, text_byte_count) == 0)
      return true;
  }
  return false;
}

void test_each_page_holds_the_fragments_and_the_values_of_the_running_server(void)
{
  TEST_ASSERT_TRUE(pages_init(15));

  size_t nav_byte_count = 0;
  size_t footer_byte_count = 0;
  unsigned char* nav = static_readWholeFile("web/pages/nav.html", &nav_byte_count);
  unsigned char* footer = static_readWholeFile("web/pages/footer.html", &footer_byte_count);
  int page_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL_MESSAGE(page, SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(page, nav, nav_byte_count), SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(page, footer, footer_byte_count), SERVED_FILES[i].mp_httpPath);
    page_count++;
  }
  TEST_ASSERT_EQUAL_INT(14, page_count);
  free(nav);
  free(footer);

  char expected[3][256];
  snprintf(expected[0], sizeof(expected[0]), "Bulk CVE lookup (up to %d IDs per request)", CVELOOKUPBULK_MAX_IDS);
  snprintf(expected[1], sizeof(expected[1]), "%d credits / hour per IPv4 address or IPv6 /64", RL_ANON_CREDIT_LIMIT);
  snprintf(expected[2], sizeof(expected[2]), "split -l %d - batch_", CVELOOKUPBULK_MAX_IDS);
  char driver_bulk[128];
  snprintf(driver_bulk, sizeof(driver_bulk), "Many driver file hashes in the LOLDrivers catalog at once (up to %d hashes per request)", DRIVERLOOKUPBULK_MAX_IDS);
  char package_bulk[128];
  snprintf(package_bulk, sizeof(package_bulk), "Many packages with exact versions at once (up to %d packages per request)", PACKAGECHECKBULK_MAX_ITEMS);
  char llms_key[128];
  char llms_triage[256];
  snprintf(llms_key, sizeof(llms_key), "API key (%d credits/hour)", RL_KEY_CREDIT_LIMIT);
  snprintf(llms_triage, sizeof(llms_triage), "Rank a list of CVE IDs by composite risk score, body `{\"cve_ids\": [...]}` (up to %d IDs)", CVETRIAGEBULK_MAX_IDS);
  const struct { const char* mp_httpPath; const char* mp_text; } holds[] = {
    { "/",           expected[0] },
    { "/",           driver_bulk },
    { "/",           package_bulk },
    { "/pricing",    expected[1] },
    { "/quickstart", expected[2] },
    { "/mcp-setup",  "\"protocolVersion\":\"" MCP_PROTOCOL_VERSION "\"" },
    { "/bot",        "<code class=\"ua\">" HTTP_USER_AGENT "</code>" },
    { "/llms.txt",   llms_key },
    { "/llms.txt",   llms_triage },
    { "/cve-api",       "<a href=\"https://contrastcyber.com/security/kev\">" },
    { "/llms.txt",      "(https://contrastcyber.com/security/)" },
    { "/llms-full.txt", "(https://contrastcyber.com/security/)" },
  };
  for (size_t i = 0; i < sizeof(holds) / sizeof(holds[0]); i++)
  {
    const PagesFile_t* file = pages_findServedFile(holds[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL_MESSAGE(file, holds[i].mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(file, holds[i].mp_text, strlen(holds[i].mp_text)), holds[i].mp_text);
  }
}

static size_t static_bodyFind(const PagesFile_t* file, size_t from, const char* text)
{
  size_t text_byte_count = strlen(text);
  for (size_t at = from; at + text_byte_count <= file->m_bodyByteCount; at++)
  {
    if (memcmp(file->mp_body + at, text, text_byte_count) == 0)
      return at;
  }
  return file->m_bodyByteCount;
}

static size_t static_textFind(const char* text, size_t byte_count, size_t from, const char* needle)
{
  size_t needle_byte_count = strlen(needle);
  for (size_t at = from; at + needle_byte_count <= byte_count; at++)
  {
    if (memcmp(text + at, needle, needle_byte_count) == 0)
      return at;
  }
  return byte_count;
}

void test_no_page_holds_an_inline_style_or_script(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  int page_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(page);
    size_t byte_count = page->m_bodyByteCount;
    char* lower = malloc(byte_count);
    TEST_ASSERT_NOT_NULL(lower);
    for (size_t k = 0; k < byte_count; k++)
      lower[k] = (char)tolower((unsigned char)page->mp_body[k]);

    page_count++;
    TEST_ASSERT_EQUAL_UINT_MESSAGE(byte_count, static_textFind(lower, byte_count, 0, "<style"), page->mp_httpPath);
    for (size_t at = static_textFind(lower, byte_count, 0, "<script"); at < byte_count; at = static_textFind(lower, byte_count, at + 1, "<script"))
    {
      bool is_same_origin = memcmp(page->mp_body + at, "<script src=\"/", 14) == 0 && page->mp_body[at + 14] != '/';
      bool is_data = memcmp(page->mp_body + at, "<script type=\"application/ld+json\">", 35) == 0;
      TEST_ASSERT_TRUE_MESSAGE(is_same_origin || is_data, page->mp_httpPath);
    }
    TEST_ASSERT_EQUAL_UINT_MESSAGE(byte_count, static_textFind(lower, byte_count, 0, " style="), page->mp_httpPath);
    for (size_t at = static_textFind(lower, byte_count, 0, " on"); at < byte_count; at = static_textFind(lower, byte_count, at + 1, " on"))
    {
      size_t name_end = at + 3;
      while (name_end < byte_count && lower[name_end] >= 'a' && lower[name_end] <= 'z')
        name_end++;
      bool is_handler = name_end > at + 3 && name_end < byte_count && lower[name_end] == '=';
      TEST_ASSERT_FALSE_MESSAGE(is_handler, page->mp_httpPath);
    }
    free(lower);
  }
  TEST_ASSERT_EQUAL_INT(14, page_count);
}

void test_each_served_file_sends_its_whole_head(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  response_setHeadRequest(true);
  TEST_ASSERT_EQUAL_INT(SERVED_FILE_COUNT, pages_sourceCount);
  for (int i = 0; i < pages_sourceCount; i++)
  {
    const char* http_path = pages_sources[i].mp_httpPath;
    const PagesFile_t* file = pages_findServedFile(http_path);
    TEST_ASSERT_NOT_NULL_MESSAGE(file, http_path);
    char buf[RESP_BUF];
    static_captureSend(file, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(buf, "HTTP/1.1 200 OK\r\n", 17), http_path);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, file->mp_extraHeaders), http_path);
    const char* head_end = strstr(buf, "\r\n\r\n");
    TEST_ASSERT_NOT_NULL_MESSAGE(head_end, http_path);
    TEST_ASSERT_EQUAL_CHAR_MESSAGE('\0', head_end[4], http_path);
  }
}

static void static_checkInternalLink(const PagesFile_t* page, const char* link)
{
  char path[256];
  snprintf(path, sizeof(path), "%s", link);
  char fragment[128] = "";
  char* hash = strchr(path, '#');
  if (hash != NULL)
  {
    snprintf(fragment, sizeof(fragment), "%s", hash + 1);
    *hash = '\0';
  }
  char* query = strchr(path, '?');
  if (query != NULL)
    *query = '\0';
  size_t path_len = strlen(path);
  while (path_len > 1 && path[path_len - 1] == '/')
    path[--path_len] = '\0';

  const PagesFile_t* target = path_len == 0 ? page : pages_findServedFile(path);
  TEST_ASSERT_NOT_NULL_MESSAGE(target, link);
  if (fragment[0] != '\0')
  {
    char id_attribute[160];
    snprintf(id_attribute, sizeof(id_attribute), "id=\"%s\"", fragment);
    TEST_ASSERT_TRUE_MESSAGE(static_bodyFind(target, 0, id_attribute) < target->m_bodyByteCount, link);
  }
}

void test_every_internal_link_reaches_a_served_file(void)
{
  TEST_ASSERT_TRUE(pages_init(15));

  static const char* const attributes[] = { " href=\"", " src=\"" };
  int link_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(page);
    for (size_t a = 0; a < sizeof(attributes) / sizeof(attributes[0]); a++)
    {
      for (size_t at = static_bodyFind(page, 0, attributes[a]); at < page->m_bodyByteCount;
           at = static_bodyFind(page, at + 1, attributes[a]))
      {
        size_t value_start = at + strlen(attributes[a]);
        size_t value_end = static_bodyFind(page, value_start, "\"");
        TEST_ASSERT_TRUE(value_end < page->m_bodyByteCount);
        char link[256];
        snprintf(link, sizeof(link), "%.*s", (int)(value_end - value_start), (const char*)page->mp_body + value_start);
        bool is_here = (link[0] == '/' && link[1] != '/') || link[0] == '#';
        if (!is_here)
          continue;
        static_checkInternalLink(page, link);
        link_count++;
      }
    }
  }
  TEST_ASSERT_TRUE(link_count > 0);

  const PagesFile_t* sitemap = pages_findServedFile("/sitemap.xml");
  TEST_ASSERT_NOT_NULL(sitemap);
  static const char loc_start[] = "<loc>https://api.contrastcyber.com";
  int url_count = 0;
  for (size_t at = static_bodyFind(sitemap, 0, loc_start); at < sitemap->m_bodyByteCount;
       at = static_bodyFind(sitemap, at + 1, loc_start))
  {
    size_t path_start = at + strlen(loc_start);
    size_t path_end = static_bodyFind(sitemap, path_start, "</loc>");
    char path[256];
    snprintf(path, sizeof(path), "%.*s", (int)(path_end - path_start), (const char*)sitemap->mp_body + path_start);
    const PagesFile_t* target = pages_findServedFile(path);
    TEST_ASSERT_NOT_NULL_MESSAGE(target, path);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("text/html; charset=utf-8", target->mp_contentType, path);
    url_count++;
  }
  TEST_ASSERT_TRUE(url_count > 0);

  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    if (static_isUnlistedPage(SERVED_FILES[i].mp_httpPath))
      continue;
    char loc[256];
    snprintf(loc, sizeof(loc), "%s%s</loc>", loc_start, SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(static_bodyFind(sitemap, 0, loc) < sitemap->m_bodyByteCount, loc);
  }
}

void test_a_pricing_list_item_holds_its_text_in_one_element(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* page = pages_findServedFile("/pricing");
  TEST_ASSERT_NOT_NULL(page);
  int item_count = 0;
  for (size_t at = static_bodyFind(page, 0, "<li>"); at < page->m_bodyByteCount; at = static_bodyFind(page, at + 1, "<li>"))
  {
    size_t content_start = at + 4;
    size_t content_end = static_bodyFind(page, content_start, "</li>");
    TEST_ASSERT_TRUE(content_end < page->m_bodyByteCount);
    const char* content = (const char*)page->mp_body + content_start;
    size_t content_byte_count = content_end - content_start;
    if (memchr(content, '<', content_byte_count) != NULL)
    {
      char item[512];
      snprintf(item, sizeof(item), "%.*s", (int)content_byte_count, content);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(content, "<span>", 6), item);
      TEST_ASSERT_TRUE_MESSAGE(content_byte_count >= 13 && memcmp(content + content_byte_count - 7, "</span>", 7) == 0, item);
      TEST_ASSERT_NULL_MESSAGE(strstr(item + 6, "<span>"), item);
    }
    item_count++;
  }
  TEST_ASSERT_TRUE(item_count > 0);
}

static void static_findProCard(const PagesFile_t* page, size_t* start_out, size_t* end_out)
{
  *start_out = static_bodyFind(page, 0, "<h2>Pro</h2>");
  TEST_ASSERT_TRUE_MESSAGE(*start_out < page->m_bodyByteCount, "no Pro card");
  *end_out = static_bodyFind(page, *start_out, "</ul>");
  TEST_ASSERT_TRUE_MESSAGE(*end_out < page->m_bodyByteCount, "the Pro card has no list end");
}

void test_pricing_page_shows_the_pro_prices(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* page = pages_findServedFile("/pricing");
  TEST_ASSERT_NOT_NULL(page);
  size_t card_start = 0;
  size_t card_end = 0;
  static_findProCard(page, &card_start, &card_end);

  TEST_ASSERT_TRUE_MESSAGE(static_bodyFind(page, card_start, "<div class=\"price\">$19 <span>/month</span></div>") < card_end, "monthly price");
  TEST_ASSERT_TRUE_MESSAGE(static_bodyFind(page, card_start, "<div class=\"price-alt\"><span>or</span> $190 <span>/year</span></div>") < card_end, "yearly price");
  TEST_ASSERT_EQUAL_size_t(page->m_bodyByteCount, static_bodyFind(page, 0, "@@PRICING_"));
}

void test_pricing_page_shows_the_x402_credit_price(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* page = pages_findServedFile("/pricing");
  TEST_ASSERT_NOT_NULL(page);
  const char* item = "<li>Pay per call with x402: $0.01 per credit, in USDC on Solana</li>";
  TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(page, item, strlen(item)), item);
  const char* answer = "One credit costs $0.01, paid in USDC on Solana with x402.";
  TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(page, answer, strlen(answer)), answer);
  TEST_ASSERT_EQUAL_size_t(page->m_bodyByteCount, static_bodyFind(page, 0, "@@PRICING_"));

  const PagesFile_t* terms = pages_findServedFile("/terms");
  TEST_ASSERT_NOT_NULL(terms);
  const char* terms_price = "at $0.01 per credit.";
  TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(terms, terms_price, strlen(terms_price)), terms_price);
  TEST_ASSERT_EQUAL_size_t(terms->m_bodyByteCount, static_bodyFind(terms, 0, "@@PRICING_"));
}

void test_pricing_pro_card_lists_monitoring_first(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* page = pages_findServedFile("/pricing");
  TEST_ASSERT_NOT_NULL(page);
  size_t card_start = 0;
  size_t card_end = 0;
  static_findProCard(page, &card_start, &card_end);

  char credits_item[128];
  snprintf(credits_item, sizeof(credits_item), "<li>%d credits / hour per key</li>", RL_KEY_CREDIT_LIMIT);
  size_t first_item = static_bodyFind(page, card_start, "<li>");
  size_t monitoring = static_bodyFind(page, card_start, "<li>Monitoring (the watchlist tools) of CVEs, products, CVE searches, packages, domains and IP addresses</li>");
  size_t credits = static_bodyFind(page, card_start, credits_item);
  size_t key_auth = static_bodyFind(page, card_start, "<li>API key authentication");
  TEST_ASSERT_TRUE_MESSAGE(monitoring < card_end, "monitoring item");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(first_item, monitoring, "monitoring is not the first item");
  TEST_ASSERT_TRUE_MESSAGE(monitoring < credits && credits < card_end, credits_item);
  TEST_ASSERT_TRUE_MESSAGE(credits < key_auth && key_auth < card_end, "key authentication item");
}

void test_terms_page_bills_monthly_or_yearly(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* page = pages_findServedFile("/terms");
  TEST_ASSERT_NOT_NULL(page);
  const char* sentence = "<li>Card payments go through Lemon Squeezy. They are billed monthly or yearly, as you choose, until you cancel.</li>";
  TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(page, sentence, strlen(sentence)), sentence);
}

void test_terms_page_states_the_refund_policy(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* page = pages_findServedFile("/terms");
  TEST_ASSERT_NOT_NULL(page);
  static const char* const sentences[] = {
    "If you are not satisfied with a card subscription, ask for a refund within 7 days of your first payment. You then get it in full.",
    "A full refund ends your key at once.",
    "Renewals are not refunded.",
    "Crypto payments are not refunded.",
    "You can cancel at any time. Your key then keeps working until the end of the period you paid for.",
    "We may revoke an API key that violates these Terms, without refund.",
  };
  for (size_t i = 0; i < sizeof(sentences) / sizeof(sentences[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(page, sentences[i], strlen(sentences[i])), sentences[i]);
}

static void static_contentVersion(const PagesFile_t* file, char* text_out, size_t text_size)
{
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < file->m_bodyByteCount; i++)
  {
    hash ^= file->mp_body[i];
    hash *= 16777619u;
  }
  snprintf(text_out, text_size, "%08" PRIx32, hash);
}

void test_each_versioned_link_carries_the_version_of_its_file(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  int link_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(page);
    const char* body = (const char*)page->mp_body;
    for (size_t at = static_bodyFind(page, 0, "?v="); at < page->m_bodyByteCount; at = static_bodyFind(page, at + 1, "?v="))
    {
      size_t path_start = at;
      while (path_start > 0 && body[path_start - 1] != '"')
        path_start--;
      char path[128];
      snprintf(path, sizeof(path), "%.*s", (int)(at - path_start), body + path_start);
      const PagesFile_t* file = pages_findServedFile(path);
      TEST_ASSERT_NOT_NULL_MESSAGE(file, path);

      char version[16];
      static_contentVersion(file, version, sizeof(version));
      char expected[32];
      snprintf(expected, sizeof(expected), "?v=%s\"", version);
      size_t expected_len = strlen(expected);
      TEST_ASSERT_TRUE_MESSAGE(at + expected_len <= page->m_bodyByteCount, path);
      TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected, body + at, expected_len, path);
      link_count++;
    }
  }
  TEST_ASSERT_EQUAL_INT(71, link_count);
}

#define FAQ_TEXT_SIZE 2048

static size_t static_readJsonValue(const PagesFile_t* page, size_t from, size_t end, const char* key,
                                   char* text_out, size_t text_size)
{
  const char* body = (const char*)page->mp_body;
  size_t at = static_bodyFind(page, from, key);
  TEST_ASSERT_TRUE_MESSAGE(at < end, key);
  at += strlen(key);
  while (at < end && body[at] == ' ')
    at++;
  TEST_ASSERT_TRUE_MESSAGE(at < end && body[at] == ':', key);
  at++;
  while (at < end && body[at] == ' ')
    at++;
  TEST_ASSERT_TRUE_MESSAGE(at < end && body[at] == '"', key);
  at++;
  size_t length = 0;
  while (at < end && body[at] != '"')
  {
    TEST_ASSERT_TRUE_MESSAGE(body[at] != '\\', "a JSON-LD escape the test does not decode");
    TEST_ASSERT_TRUE_MESSAGE(length + 1 < text_size, key);
    text_out[length++] = body[at++];
  }
  TEST_ASSERT_TRUE_MESSAGE(at < end, key);
  text_out[length] = '\0';
  return at + 1;
}

static void static_readVisibleText(const PagesFile_t* page, size_t from, size_t end, char* text_out, size_t text_size)
{
  const char* body = (const char*)page->mp_body;
  size_t length = 0;
  bool is_in_tag = false;
  for (size_t at = from; at < end; at++)
  {
    if (body[at] == '<')
      is_in_tag = true;
    else if (body[at] == '>')
      is_in_tag = false;
    else if (!is_in_tag)
    {
      TEST_ASSERT_TRUE_MESSAGE(body[at] != '&', "a character reference the test does not decode");
      TEST_ASSERT_TRUE_MESSAGE(length + 1 < text_size, page->mp_httpPath);
      text_out[length++] = body[at];
    }
  }
  text_out[length] = '\0';
}

void test_each_faq_structured_data_holds_the_visible_faq(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  static char json_text[FAQ_TEXT_SIZE];
  static char visible_text[FAQ_TEXT_SIZE];
  int faq_page_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(page);
    size_t faq_at = static_bodyFind(page, 0, "FAQPage");
    if (faq_at == page->m_bodyByteCount)
      continue;
    faq_page_count++;
    size_t script_end = static_bodyFind(page, faq_at, "</script>");
    TEST_ASSERT_TRUE_MESSAGE(script_end < page->m_bodyByteCount, page->mp_httpPath);
    size_t list_at = static_bodyFind(page, 0, "<div class=\"faq\">");
    TEST_ASSERT_TRUE_MESSAGE(list_at < page->m_bodyByteCount, page->mp_httpPath);
    size_t list_end = static_bodyFind(page, list_at, "</dl>");
    TEST_ASSERT_TRUE_MESSAGE(list_end < page->m_bodyByteCount, page->mp_httpPath);

    int entry_count = 0;
    size_t question_at = static_bodyFind(page, faq_at, "\"Question\"");
    size_t term_at = static_bodyFind(page, list_at, "<dt>");
    while (question_at < script_end)
    {
      size_t next_question_at = static_bodyFind(page, question_at + 1, "\"Question\"");
      size_t question_end = next_question_at < script_end ? next_question_at : script_end;
      TEST_ASSERT_TRUE_MESSAGE(term_at < list_end, page->mp_httpPath);
      size_t term_end = static_bodyFind(page, term_at, "</dt>");
      size_t next_term_at = static_bodyFind(page, term_at + 1, "<dt>");
      size_t entry_end = next_term_at < list_end ? next_term_at : list_end;
      size_t description_at = static_bodyFind(page, term_end, "<dd>");
      TEST_ASSERT_TRUE_MESSAGE(description_at < entry_end, page->mp_httpPath);
      size_t description_end = static_bodyFind(page, description_at, "</dd>");
      TEST_ASSERT_TRUE_MESSAGE(description_end < entry_end, page->mp_httpPath);

      size_t answer_at = static_readJsonValue(page, question_at, question_end, "\"name\"", json_text, sizeof(json_text));
      static_readVisibleText(page, term_at + 4, term_end, visible_text, sizeof(visible_text));
      TEST_ASSERT_EQUAL_STRING_MESSAGE(json_text, visible_text, page->mp_httpPath);
      answer_at = static_bodyFind(page, answer_at, "\"acceptedAnswer\"");
      TEST_ASSERT_TRUE_MESSAGE(answer_at < question_end, page->mp_httpPath);
      static_readJsonValue(page, answer_at, question_end, "\"text\"", json_text, sizeof(json_text));
      static_readVisibleText(page, description_at + 4, description_end, visible_text, sizeof(visible_text));
      TEST_ASSERT_EQUAL_STRING_MESSAGE(json_text, visible_text, page->mp_httpPath);

      entry_count++;
      question_at = next_question_at;
      term_at = next_term_at;
    }
    TEST_ASSERT_TRUE_MESSAGE(entry_count > 0, page->mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(term_at >= list_end, page->mp_httpPath);
  }
  TEST_ASSERT_EQUAL_INT(7, faq_page_count);
}

void test_each_page_names_its_own_canonical(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  int page_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(page);
    char canonical[256];
    snprintf(canonical, sizeof(canonical), "<link rel=\"canonical\" href=\"https://api.contrastcyber.com%s\">",
             SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(static_bodyFind(page, 0, canonical) < page->m_bodyByteCount, canonical);
    page_count++;
  }
  TEST_ASSERT_EQUAL_INT(14, page_count);
}

static const char* const PAGE_HEAD_LINES[] = {
  "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/static/favicon.svg\">",
  "<link rel=\"icon\" type=\"image/png\" sizes=\"32x32\" href=\"/static/favicon-32.png\">",
  "<link rel=\"icon\" type=\"image/png\" sizes=\"192x192\" href=\"/static/favicon-192.png\">",
  "<link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"/static/apple-touch-icon.png\">",
  "<meta name=\"theme-color\" content=\"#e9ebee\" media=\"(prefers-color-scheme: light)\">",
  "<meta name=\"theme-color\" content=\"#06101d\" media=\"(prefers-color-scheme: dark)\">",
};

void test_each_page_holds_the_icons_and_the_theme_colors(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  int page_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(page);
    size_t head_end = static_bodyFind(page, 0, "</head>");
    TEST_ASSERT_TRUE_MESSAGE(head_end < page->m_bodyByteCount, page->mp_httpPath);
    for (size_t k = 0; k < sizeof(PAGE_HEAD_LINES) / sizeof(PAGE_HEAD_LINES[0]); k++)
    {
      size_t line_at = static_bodyFind(page, 0, PAGE_HEAD_LINES[k]);
      TEST_ASSERT_TRUE_MESSAGE(line_at < head_end, PAGE_HEAD_LINES[k]);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(page->m_bodyByteCount,
        static_bodyFind(page, line_at + strlen(PAGE_HEAD_LINES[k]), PAGE_HEAD_LINES[k]), PAGE_HEAD_LINES[k]);
    }
    page_count++;
  }
  TEST_ASSERT_EQUAL_INT(14, page_count);
}

static const char* const PAGE_SHARE_TAGS[] = {
  "<meta name=\"description\" content=\"",
  "<meta property=\"og:title\" content=\"",
  "<meta property=\"og:description\" content=\"",
  "<meta property=\"og:type\" content=\"website\">",
  "<meta property=\"og:image\" content=\"https://api.contrastcyber.com/static/og-image.png\">",
  "<meta property=\"og:image:width\" content=\"1200\">",
  "<meta property=\"og:image:height\" content=\"630\">",
  "<meta property=\"og:image:alt\" content=\"",
  "<meta property=\"og:site_name\" content=\"ContrastAPI\">",
  "<meta name=\"twitter:card\" content=\"summary_large_image\">",
  "<meta name=\"twitter:title\" content=\"",
  "<meta name=\"twitter:description\" content=\"",
  "<meta name=\"twitter:image\" content=\"https://api.contrastcyber.com/static/og-image.png\">",
};

void test_each_listed_page_holds_its_share_tags_and_each_unlisted_one_noindex(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  int listed_count = 0;
  int unlisted_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(page);
    size_t head_end = static_bodyFind(page, 0, "</head>");
    TEST_ASSERT_TRUE_MESSAGE(head_end < page->m_bodyByteCount, page->mp_httpPath);
    size_t noindex_at = static_bodyFind(page, 0, "<meta name=\"robots\" content=\"noindex\">");
    if (static_isUnlistedPage(page->mp_httpPath))
    {
      TEST_ASSERT_TRUE_MESSAGE(noindex_at < head_end, page->mp_httpPath);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(page->m_bodyByteCount, static_bodyFind(page, 0, "property=\"og:"), page->mp_httpPath);
      unlisted_count++;
      continue;
    }
    TEST_ASSERT_EQUAL_size_t_MESSAGE(page->m_bodyByteCount, static_bodyFind(page, 0, "name=\"robots\""), page->mp_httpPath);
    for (size_t k = 0; k < sizeof(PAGE_SHARE_TAGS) / sizeof(PAGE_SHARE_TAGS[0]); k++)
      TEST_ASSERT_TRUE_MESSAGE(static_bodyFind(page, 0, PAGE_SHARE_TAGS[k]) < head_end, PAGE_SHARE_TAGS[k]);
    char og_url[256];
    snprintf(og_url, sizeof(og_url), "<meta property=\"og:url\" content=\"https://api.contrastcyber.com%s\">",
             page->mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(static_bodyFind(page, 0, og_url) < head_end, og_url);
    listed_count++;
  }
  TEST_ASSERT_EQUAL_INT(12, listed_count);
  TEST_ASSERT_EQUAL_INT(2, unlisted_count);
}

void test_nav_or_footer_links_every_page(void)
{
  size_t nav_byte_count = 0;
  size_t footer_byte_count = 0;
  unsigned char* nav = static_readWholeFile("web/pages/nav.html", &nav_byte_count);
  unsigned char* footer = static_readWholeFile("web/pages/footer.html", &footer_byte_count);
  TEST_ASSERT_NOT_NULL(nav);
  TEST_ASSERT_NOT_NULL(footer);
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    if (static_isUnlistedPage(SERVED_FILES[i].mp_httpPath))
      continue;
    char href[256];
    snprintf(href, sizeof(href), "href=\"%s\"", SERVED_FILES[i].mp_httpPath);
    bool is_linked = static_textFind((const char*)nav, nav_byte_count, 0, href) < nav_byte_count
                  || static_textFind((const char*)footer, footer_byte_count, 0, href) < footer_byte_count;
    TEST_ASSERT_TRUE_MESSAGE(is_linked, href);
  }
  free(nav);
  free(footer);
}

void test_each_page_of_class_page_loads_page_css(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  int page_class_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(page);
    bool has_page_class = static_bodyFind(page, 0, "class=\"page\"") < page->m_bodyByteCount;
    bool loads_page_css = static_bodyFind(page, 0, "href=\"/static/css/page.css?v=") < page->m_bodyByteCount;
    TEST_ASSERT_EQUAL_MESSAGE(has_page_class, loads_page_css, page->mp_httpPath);
    if (has_page_class)
      page_class_count++;
  }
  TEST_ASSERT_EQUAL_INT(12, page_class_count);
}

#define PAGES_TEST_MIN_FONT_REM 0.75
#define PAGES_TEST_MIN_FONT_PX  12.0

void test_no_stylesheet_sets_a_font_below_12px(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  int stylesheet_count = 0;
  int checked_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strncmp(SERVED_FILES[i].mp_contentType, "text/css", strlen("text/css")) != 0)
      continue;
    const PagesFile_t* sheet = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(sheet);
    stylesheet_count++;
    size_t at = 0;
    while ((at = static_bodyFind(sheet, at, "font-size:")) < sheet->m_bodyByteCount)
    {
      at += strlen("font-size:");
      char value[32];
      size_t value_len = 0;
      while (at + value_len < sheet->m_bodyByteCount && value_len + 1 < sizeof(value)
             && sheet->mp_body[at + value_len] != ';' && sheet->mp_body[at + value_len] != '}')
      {
        value[value_len] = (char)sheet->mp_body[at + value_len];
        value_len++;
      }
      value[value_len] = '\0';
      char* unit = NULL;
      double number = strtod(value, &unit);
      if (unit == value)
        continue;
      char message[96];
      snprintf(message, sizeof(message), "%s font-size:%s", SERVED_FILES[i].mp_httpPath, value);
      if (strncmp(unit, "rem", 3) == 0)
      {
        TEST_ASSERT_TRUE_MESSAGE(number >= PAGES_TEST_MIN_FONT_REM, message);
        checked_count++;
      }
      else if (strncmp(unit, "px", 2) == 0)
      {
        TEST_ASSERT_TRUE_MESSAGE(number >= PAGES_TEST_MIN_FONT_PX, message);
        checked_count++;
      }
    }
  }
  TEST_ASSERT_EQUAL_INT(2, stylesheet_count);
  TEST_ASSERT_TRUE_MESSAGE(checked_count > 50, "too few sizes read: the scan may have stopped matching");
}

static bool static_skipLiteral(const char* text, size_t* at, const char* literal)
{
  size_t literal_len = strlen(literal);
  if (strncmp(text + *at, literal, literal_len) != 0)
    return false;
  *at += literal_len;
  return true;
}

static bool static_skipToQuote(const char* text, size_t* at)
{
  while (text[*at] != '\0' && text[*at] != '"')
    (*at)++;
  return text[*at] == '"';
}

void test_each_faq_block_has_the_schema_shape(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  static char compact[65536];
  int faq_page_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (strcmp(SERVED_FILES[i].mp_contentType, "text/html; charset=utf-8") != 0)
      continue;
    const PagesFile_t* page = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL(page);
    size_t faq_at = static_bodyFind(page, 0, "FAQPage");
    if (faq_at == page->m_bodyByteCount)
      continue;
    faq_page_count++;
    size_t script_at = static_bodyFind(page, 0, "<script type=\"application/ld+json\">");
    TEST_ASSERT_TRUE_MESSAGE(script_at < faq_at, page->mp_httpPath);
    script_at += strlen("<script type=\"application/ld+json\">");
    size_t script_end = static_bodyFind(page, script_at, "</script>");
    TEST_ASSERT_TRUE_MESSAGE(script_end < page->m_bodyByteCount, page->mp_httpPath);

    const char* body = (const char*)page->mp_body;
    size_t compact_len = 0;
    bool is_in_string = false;
    for (size_t k = script_at; k < script_end; k++)
    {
      char c = body[k];
      if (c == '"')
        is_in_string = !is_in_string;
      if (!is_in_string && (c == ' ' || c == '\n' || c == '\t' || c == '\r'))
        continue;
      TEST_ASSERT_TRUE(compact_len + 1 < sizeof(compact));
      compact[compact_len++] = c;
    }
    compact[compact_len] = '\0';

    size_t at = 0;
    TEST_ASSERT_TRUE_MESSAGE(static_skipLiteral(compact, &at, "{\"@context\":\"https://schema.org\","), page->mp_httpPath);
    const char* faq_type = strstr(compact, "\"@type\":\"FAQPage\",\"mainEntity\":[");
    TEST_ASSERT_NOT_NULL_MESSAGE(faq_type, page->mp_httpPath);
    at = (size_t)(faq_type - compact) + strlen("\"@type\":\"FAQPage\",\"mainEntity\":[");
    int question_count = 0;
    for (;;)
    {
      TEST_ASSERT_TRUE_MESSAGE(static_skipLiteral(compact, &at, "{\"@type\":\"Question\",\"name\":\""), page->mp_httpPath);
      TEST_ASSERT_TRUE_MESSAGE(static_skipToQuote(compact, &at), page->mp_httpPath);
      TEST_ASSERT_TRUE_MESSAGE(static_skipLiteral(compact, &at, "\",\"acceptedAnswer\":{\"@type\":\"Answer\",\"text\":\""),
                               page->mp_httpPath);
      TEST_ASSERT_TRUE_MESSAGE(static_skipToQuote(compact, &at), page->mp_httpPath);
      TEST_ASSERT_TRUE_MESSAGE(static_skipLiteral(compact, &at, "\"}}"), page->mp_httpPath);
      question_count++;
      if (static_skipLiteral(compact, &at, ","))
        continue;
      TEST_ASSERT_TRUE_MESSAGE(static_skipLiteral(compact, &at, "]}"), page->mp_httpPath);
      break;
    }
    TEST_ASSERT_TRUE_MESSAGE(question_count > 0, page->mp_httpPath);
  }
  TEST_ASSERT_EQUAL_INT(7, faq_page_count);
}

void test_each_unlisted_page_stays_out_of_the_sitemap_and_the_index(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* sitemap = pages_findServedFile("/sitemap.xml");
  TEST_ASSERT_NOT_NULL(sitemap);
  static const char noindex[] = "<meta name=\"robots\" content=\"noindex\">";
  for (size_t i = 0; i < sizeof(UNLISTED_PAGE_PATHS) / sizeof(UNLISTED_PAGE_PATHS[0]); i++)
  {
    const PagesFile_t* page = pages_findServedFile(UNLISTED_PAGE_PATHS[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(page, UNLISTED_PAGE_PATHS[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("text/html; charset=utf-8", page->mp_contentType, UNLISTED_PAGE_PATHS[i]);
    char loc[256];
    snprintf(loc, sizeof(loc), "<loc>https://api.contrastcyber.com%s</loc>", UNLISTED_PAGE_PATHS[i]);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(sitemap->m_bodyByteCount, static_bodyFind(sitemap, 0, loc), loc);
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(page, noindex, strlen(noindex)), UNLISTED_PAGE_PATHS[i]);
  }
}

void test_welcome_page_sends_no_referrer_and_holds_its_texts(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* page = pages_findServedFile("/welcome");
  TEST_ASSERT_NOT_NULL(page);
  static const char* const texts[] = {
    "<meta name=\"referrer\" content=\"no-referrer\">",
    "<script src=\"/static/js/welcome.js?v=",
    "<h1>Your ContrastAPI <span>Pro key</span></h1>",
    "Getting your key\xE2\x80\xA6",
    "<input id=\"welcome-key-field\" type=\"text\" readonly",
    "spellcheck=\"false\" class=\"key-field\">",
    ">Copy</button>",
    "Save it now. It is shown only once; we keep only a hash.",
    "<a href=\"https://github.com/UPinar/contrastapi/blob/main/docs/API_Documentation.md\">API documentation</a>",
    "Contact support: <a href=\"mailto:contact@contrastcyber.com\">contact@contrastcyber.com</a>",
  };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(page, texts[i], strlen(texts[i])), texts[i]);
  TEST_ASSERT_EQUAL_UINT(page->m_bodyByteCount, static_bodyFind(page, 0, "for AI agents"));
}

void test_welcome_script_claims_the_key_and_keeps_nothing(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* script = pages_findServedFile("/static/js/welcome.js");
  TEST_ASSERT_NOT_NULL(script);
  static const char* const parts[] = {
    "'/api_key_claim'",
    "/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/",
    "var value = new URLSearchParams(window.location.hash.slice(1)).get('order_id');\n"
    "    if (value === null) {\n"
    "      value = new URLSearchParams(window.location.search).get('order_id');\n"
    "    }\n"
    "    if (window.location.search !== '' || window.location.hash !== '') {\n"
    "      history.replaceState(null, '', window.location.pathname);\n"
    "    }",
    "history.replaceState(null, '', window.location.pathname + '#order_id=' + orderId);",
    "var NOT_PAID_RETRY_COUNT = 120;",
    "var NOT_PAID_RETRY_DELAY_MS = 5000;",
    "if (notPaidCount < NOT_PAID_RETRY_COUNT) {\n"
    "        notPaidCount++;\n"
    "        keepOrderIdForReload();\n"
    "        showStatus(TEXT_WAITING);\n"
    "        setTimeout(claim, NOT_PAID_RETRY_DELAY_MS);",
    "'Waiting for the payment to confirm. This can take a few minutes. Keep this page open.'",
    "credentials: 'omit',",
    "cache: 'no-store'",
    ".textContent = ",
    "'This page needs the link from your payment receipt.'",
    "'We have not seen your payment yet. Reload this page in a minute.'",
  };
  for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(script, parts[i], strlen(parts[i])), parts[i]);
  static const char* const banned[] = {
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
    "localStorage", "sessionStorage", "cookie", "console.", "http:", "https:", "//",
  };
  for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++)
    TEST_ASSERT_EQUAL_UINT_MESSAGE(script->m_bodyByteCount, static_bodyFind(script, 0, banned[i]), banned[i]);
}

void test_pricing_page_offers_crypto_after_the_card_link(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* page = pages_findServedFile("/pricing");
  TEST_ASSERT_NOT_NULL(page);
  static const char script_tag[] = "<script src=\"/static/js/crypto_checkout.js?v=";
  TEST_ASSERT_TRUE(static_bodyHolds(page, script_tag, strlen(script_tag)));
  size_t end        = page->m_bodyByteCount;
  size_t card_at    = static_bodyFind(page, 0, "Pay with Card</a>");
  size_t button_at  = static_bodyFind(page, 0, "<button type=\"button\" id=\"crypto-checkout-btn\" class=\"tier-cta primary\">\u20bf Pay with Crypto</button>");
  size_t message_at = static_bodyFind(page, 0, "id=\"crypto-checkout-error\"");
  TEST_ASSERT_TRUE(card_at < end);
  TEST_ASSERT_TRUE(button_at < end);
  TEST_ASSERT_TRUE(message_at < end);
  TEST_ASSERT_TRUE(card_at < button_at);
  TEST_ASSERT_TRUE(button_at < message_at);
}

void test_crypto_checkout_script_posts_and_follows_the_invoice_url(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* script = pages_findServedFile("/static/js/crypto_checkout.js");
  TEST_ASSERT_NOT_NULL(script);
  static const char* const parts[] = {
    "'/crypto_checkout'",
    "method: 'POST'",
    "credentials: 'omit'",
    "cache: 'no-store'",
    "if (response.status !== 200) {\n"
    "      showFailure();",
    "window.location.href = invoiceUrl;",
    "typeof invoiceUrl === 'string' && invoiceUrl.indexOf('https://nowpayments.io/') === 0",
    "button.disabled = false;",
    "errorLine.hidden = false;",
    "document.getElementById('crypto-checkout-btn')",
    "document.getElementById('crypto-checkout-error')",
  };
  for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(script, parts[i], strlen(parts[i])), parts[i]);
  static const char* const banned[] = {
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
    "localStorage", "sessionStorage", "cookie", "console.", "alert(",
  };
  for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++)
    TEST_ASSERT_EQUAL_UINT_MESSAGE(script->m_bodyByteCount, static_bodyFind(script, 0, banned[i]), banned[i]);
}

void test_vendor_keys_page_sends_no_referrer_and_holds_its_texts(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* page = pages_findServedFile("/vendor-keys");
  TEST_ASSERT_NOT_NULL(page);
  static const char* const texts[] = {
    "<meta name=\"robots\" content=\"noindex\">",
    "<meta name=\"referrer\" content=\"no-referrer\">",
    "<link rel=\"canonical\" href=\"https://api.contrastcyber.com/vendor-keys\">",
    "<script src=\"/static/js/vendor_keys.js?v=",
    "<h1>Your <span>vendor keys</span></h1>",
    "<input id=\"vendor-shodan-key\" type=\"text\" autocomplete=\"off\" maxlength=\"128\" spellcheck=\"false\" autocapitalize=\"off\" data-1p-ignore data-lpignore=\"true\" data-bwignore",
    "<input id=\"vendor-abuseipdb-key\" type=\"text\" autocomplete=\"off\" maxlength=\"128\" spellcheck=\"false\" autocapitalize=\"off\" data-1p-ignore data-lpignore=\"true\" data-bwignore",
    "used for your own /ip_lookup calls and to check it on this page",
    "stored encrypted and never shown again",
    "Using a key under the vendor's terms is your responsibility.",
    "/privacy_my_data",
    "manage_url",
  };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(page, texts[i], strlen(texts[i])), texts[i]);
  TEST_ASSERT_EQUAL_UINT(page->m_bodyByteCount, static_bodyFind(page, 0, "for AI agents"));
  TEST_ASSERT_EQUAL_UINT(page->m_bodyByteCount, static_bodyFind(page, 0, "type=\"password\""));
}

void test_vendor_keys_script_reads_the_link_from_the_fragment_and_drops_it_from_the_address_bar(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* script = pages_findServedFile("/static/js/vendor_keys.js");
  TEST_ASSERT_NOT_NULL(script);
  static const char* const parts[] = {
    "'/vendor_key_edit'",
    "/^[0-9a-f]{64}$/",
    "new URLSearchParams(window.location.hash.slice(1)).get('l')",
    "history.replaceState(null, '', window.location.pathname);",
    "action: 'status', link: link",
    "action: 'apply', link: link",
    "credentials: 'omit',",
    "cache: 'no-store'",
    "message.split(':')[0]",
    "['link_expired', 'link_invalid']",
    "'_key'",
    "'_delete'",
    ".textContent = ",
    "This link no longer works. Ask /privacy_my_data for a new one.",
    "Too many requests. Try again later.",
    "Saved. This link is now used. Ask /privacy_my_data for a new link to change again.",
  };
  for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(script, parts[i], strlen(parts[i])), parts[i]);
  static const char* const banned[] = {
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
    "localStorage", "sessionStorage", "cookie", "console.", "http:", "https:", "//",
  };
  for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++)
    TEST_ASSERT_EQUAL_UINT_MESSAGE(script->m_bodyByteCount, static_bodyFind(script, 0, banned[i]), banned[i]);
}

void test_privacy_policy_url_names_a_served_page(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  const char* origin = "https://api.contrastcyber.com";
  size_t origin_len = strlen(origin);
  TEST_ASSERT_EQUAL_INT(0, strncmp(PRICING_PRIVACY_POLICY_URL, origin, origin_len));
  const char* path = PRICING_PRIVACY_POLICY_URL + origin_len;
  TEST_ASSERT_EQUAL_STRING("/privacy", path);
  TEST_ASSERT_NOT_NULL_MESSAGE(pages_findServedFile(path), path);
}

void test_legal_pages_state_the_retention_minutes(void)
{
  TEST_ASSERT_EQUAL_INT(75, RL_RETENTION_MAX_SECONDS / 60);
  TEST_ASSERT_EQUAL_INT(15, MAINTENANCE_INTERVAL_SECONDS / 60);
  TEST_ASSERT_EQUAL_INT(90, USAGELOG_RETENTION_DAYS);
  TEST_ASSERT_TRUE(pages_init(15));
  const PagesFile_t* privacy = pages_findServedFile("/privacy");
  const PagesFile_t* terms   = pages_findServedFile("/terms");
  TEST_ASSERT_NOT_NULL(privacy);
  TEST_ASSERT_NOT_NULL(terms);
  static const char* const privacy_texts[] = {
    "at most 75 minutes after that hour starts",
    "A cleanup job deletes old rows every 15 minutes",
    "If the server is down or the cleanup fails, a row can stay longer.",
    "<strong>Rate-limit rows:</strong> at most 75 minutes from the start of their hour.",
    "The rate-limit row is deleted within 75 minutes of the start of its hour.",
    "<strong>Usage log:</strong> about 90 days. A new file starts each day, and the last 90 are kept.",
    "An IP item holds the IP address you gave."
  };
  for (size_t i = 0; i < sizeof(privacy_texts) / sizeof(privacy_texts[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(privacy, privacy_texts[i], strlen(privacy_texts[i])), privacy_texts[i]);
  const char* terms_text = "at most 75 minutes from the start of its hour";
  TEST_ASSERT_TRUE_MESSAGE(static_bodyHolds(terms, terms_text, strlen(terms_text)), terms_text);
  TEST_ASSERT_EQUAL_size_t(privacy->m_bodyByteCount, static_bodyFind(privacy, 0, "@@"));
  TEST_ASSERT_EQUAL_size_t(terms->m_bodyByteCount, static_bodyFind(terms, 0, "@@"));
}

static bool static_isTextContentType(const char* content_type)
{
  static const char* const text_prefixes[] = { "text/", "application/json", "application/xml", "image/svg+xml" };
  for (size_t i = 0; i < sizeof(text_prefixes) / sizeof(text_prefixes[0]); i++)
  {
    if (strncmp(content_type, text_prefixes[i], strlen(text_prefixes[i])) == 0)
      return true;
  }
  return false;
}

#define PAGES_TEST_TEXT_FILE_COUNT 31

void test_no_served_text_file_holds_an_em_dash(void)
{
  TEST_ASSERT_TRUE(pages_init(15));
  static const char* const em_dash_forms[] = { "\xE2\x80\x94", "&mdash;", "&#8212;", "&#x2014;" };
  int text_file_count = 0;
  for (int i = 0; i < SERVED_FILE_COUNT; i++)
  {
    if (!static_isTextContentType(SERVED_FILES[i].mp_contentType))
      continue;
    const PagesFile_t* file = pages_findServedFile(SERVED_FILES[i].mp_httpPath);
    TEST_ASSERT_NOT_NULL_MESSAGE(file, SERVED_FILES[i].mp_httpPath);
    text_file_count++;
    for (size_t j = 0; j < sizeof(em_dash_forms) / sizeof(em_dash_forms[0]); j++)
    {
      size_t at = static_bodyFind(file, 0, em_dash_forms[j]);
      char message[160];
      snprintf(message, sizeof(message), "%s holds an em dash at byte %zu", SERVED_FILES[i].mp_httpPath, at);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(file->m_bodyByteCount, at, message);
    }
  }
  TEST_ASSERT_EQUAL_INT(PAGES_TEST_TEXT_FILE_COUNT, text_file_count);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(47, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_find_served_file_finds_nothing_before_init);
  RUN_TEST(test_find_file_by_path_finds_every_path_of_the_table);
  RUN_TEST(test_find_file_by_path_refuses_each_near_spelling);
  RUN_TEST(test_find_file_by_path_in_an_empty_table_finds_nothing);
  RUN_TEST(test_methods_are_get_and_head);
  RUN_TEST(test_send_writes_the_file_with_its_own_headers);
  RUN_TEST(test_send_of_a_body_with_a_nul_sends_every_byte);
  RUN_TEST(test_head_request_gets_the_get_head_and_no_body);
  RUN_TEST(test_render_fills_each_known_placeholder);
  RUN_TEST(test_render_refuses_an_unknown_placeholder);
  RUN_TEST(test_render_refuses_an_unclosed_placeholder);
  RUN_TEST(test_render_keeps_text_that_is_not_a_placeholder);
  RUN_TEST(test_render_reads_the_byte_count_it_is_given);
  RUN_TEST(test_render_refuses_output_that_does_not_fit);
  RUN_TEST(test_init_serves_the_files_of_the_table_and_no_other);
  RUN_TEST(test_each_embedded_file_holds_the_bytes_of_its_source);
  RUN_TEST(test_server_card_holds_the_values_of_the_running_server);
  RUN_TEST(test_each_page_holds_the_fragments_and_the_values_of_the_running_server);
  RUN_TEST(test_no_page_holds_an_inline_style_or_script);
  RUN_TEST(test_each_served_file_sends_its_whole_head);
  RUN_TEST(test_every_internal_link_reaches_a_served_file);
  RUN_TEST(test_a_pricing_list_item_holds_its_text_in_one_element);
  RUN_TEST(test_pricing_page_shows_the_pro_prices);
  RUN_TEST(test_pricing_page_shows_the_x402_credit_price);
  RUN_TEST(test_pricing_pro_card_lists_monitoring_first);
  RUN_TEST(test_terms_page_bills_monthly_or_yearly);
  RUN_TEST(test_terms_page_states_the_refund_policy);
  RUN_TEST(test_each_versioned_link_carries_the_version_of_its_file);
  RUN_TEST(test_each_faq_structured_data_holds_the_visible_faq);
  RUN_TEST(test_each_page_names_its_own_canonical);
  RUN_TEST(test_each_page_holds_the_icons_and_the_theme_colors);
  RUN_TEST(test_each_listed_page_holds_its_share_tags_and_each_unlisted_one_noindex);
  RUN_TEST(test_nav_or_footer_links_every_page);
  RUN_TEST(test_each_page_of_class_page_loads_page_css);
  RUN_TEST(test_each_faq_block_has_the_schema_shape);
  RUN_TEST(test_each_unlisted_page_stays_out_of_the_sitemap_and_the_index);
  RUN_TEST(test_welcome_page_sends_no_referrer_and_holds_its_texts);
  RUN_TEST(test_welcome_script_claims_the_key_and_keeps_nothing);
  RUN_TEST(test_pricing_page_offers_crypto_after_the_card_link);
  RUN_TEST(test_crypto_checkout_script_posts_and_follows_the_invoice_url);
  RUN_TEST(test_vendor_keys_page_sends_no_referrer_and_holds_its_texts);
  RUN_TEST(test_vendor_keys_script_reads_the_link_from_the_fragment_and_drops_it_from_the_address_bar);
  RUN_TEST(test_privacy_policy_url_names_a_served_page);
  RUN_TEST(test_legal_pages_state_the_retention_minutes);
  RUN_TEST(test_no_stylesheet_sets_a_font_below_12px);
  RUN_TEST(test_no_served_text_file_holds_an_em_dash);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
