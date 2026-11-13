#ifndef PAGES_H
#define PAGES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  const char*          mp_httpPath;
  const char*          mp_contentType;
  const char*          mp_cacheControl;
  const char*          mp_extraHeaders;
  const unsigned char* mp_body;
  size_t               m_bodyByteCount;
} PagesFile_t;

typedef struct {
  const char* mp_name;
  const char* mp_value;
} PagesValue_t;

typedef struct {
  const char*         mp_text;
  size_t              m_byteCount;
  const PagesValue_t* mp_values;
  int                 m_valueCount;
} PagesTemplate_t;

typedef struct {
  char*   mp_text;
  size_t  m_capacity;
  size_t  m_byteCount;
} PagesRendered_t;

extern const char* const pages_allowedMethods[];

bool               pages_isHttpMethodAllowed(const char* http_method);
const PagesFile_t* pages_findFileByPath     (const PagesFile_t* files, int file_count_to_search, const char* http_path);
void               pages_send               (int client_fd, const PagesFile_t* file);
bool               pages_render             (const PagesTemplate_t* page_template, PagesRendered_t* rendered_template);

typedef struct {
  const char*          mp_httpPath;
  const char*          mp_contentType;
  const char*          mp_cacheControl;
  const char*          mp_extraHeaders;
  const unsigned char* mp_asset;
  const uint64_t*      mp_assetByteCount;
  bool                 m_isTemplate;
} PagesSource_t;

extern const PagesSource_t pages_sources[];
extern const int           pages_sourceCount;

bool               pages_init               (int tool_count);
const PagesFile_t* pages_findServedFile     (const char* http_path);

#endif
