#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "pages.h"
#include "bytes.h"
#include "response.h"

#define PAGES_PLACEHOLDER_MARK_BYTE_COUNT 2

const char* const pages_allowedMethods[] = { "GET", "HEAD", NULL };

typedef struct {
  bool        m_isClosed;
  const char* mp_name;
  size_t      m_nameByteCount;
} PagesPlaceholder_t;

static bool               static_isPlaceholderStart             (const char* template_text, size_t template_byte_count, size_t template_index);
static PagesPlaceholder_t static_readPlaceholder                (const char* template_text, size_t template_byte_count, size_t template_index);
static size_t             static_countPlaceholderNameBytes      (const char* name_text, size_t remaining_byte_count);
static bool               static_isByteAllowedInPlaceholderName (char byte);
static const char*        static_findPlaceholderValue           (const PagesValue_t* values, int value_count, const char* name, size_t name_byte_count);
static bool               static_appendToRendered               (PagesRendered_t* rendered_template, const char* bytes, size_t added_byte_count);

bool pages_isHttpMethodAllowed(const char* http_method)
{
  assert(http_method != NULL);

  for (int i = 0; pages_allowedMethods[i] != NULL; i++)
  {
    if (strcmp(pages_allowedMethods[i], http_method) == 0)
      return true;
  }
  return false;
}

const PagesFile_t* pages_findFileByPath(const PagesFile_t* files, int file_count_to_search, const char* http_path)
{
  assert(files != NULL || file_count_to_search == 0);
  assert(http_path != NULL);

  for (int i = 0; i < file_count_to_search; i++)
  {
    if (strcmp(files[i].mp_httpPath, http_path) == 0)
      return &files[i];
  }
  return NULL;
}

void pages_send(int client_fd, const PagesFile_t* file)
{
  assert(file != NULL);

  response_sendContent(client_fd, file->mp_contentType, file->mp_cacheControl, file->mp_extraHeaders, file->mp_body, file->m_bodyByteCount);
}

bool pages_render(const PagesTemplate_t* page_template, PagesRendered_t* rendered_template)
{
  assert(page_template != NULL);
  assert(page_template->mp_text != NULL);
  assert(page_template->mp_values != NULL || page_template->m_valueCount == 0);
  assert(rendered_template != NULL);
  assert(rendered_template->mp_text != NULL);
  assert(rendered_template->m_capacity > 0);

  const char* template_text       = page_template->mp_text;
  size_t      template_byte_count = page_template->m_byteCount;
  rendered_template->m_byteCount = 0;

  size_t template_index = 0;
  while (template_index < template_byte_count)
  {
    if (!static_isPlaceholderStart(template_text, template_byte_count, template_index))
    {
      if (!static_appendToRendered(rendered_template, template_text + template_index, 1))
        goto refuse;

      template_index++;
      continue;
    }

    PagesPlaceholder_t placeholder = static_readPlaceholder(template_text, template_byte_count, template_index);
    if (!placeholder.m_isClosed)
      goto refuse;

    const char* value = static_findPlaceholderValue(page_template->mp_values, page_template->m_valueCount, placeholder.mp_name, placeholder.m_nameByteCount);
    if (value == NULL)
      goto refuse;

    if (!static_appendToRendered(rendered_template, value, strlen(value)))
      goto refuse;

    template_index += PAGES_PLACEHOLDER_MARK_BYTE_COUNT + placeholder.m_nameByteCount + PAGES_PLACEHOLDER_MARK_BYTE_COUNT;
  }

  rendered_template->mp_text[rendered_template->m_byteCount] = '\0';
  return true;

refuse:
  rendered_template->mp_text[0] = '\0';
  rendered_template->m_byteCount = 0;
  return false;
}

static bool static_isPlaceholderStart(const char* template_text, size_t template_byte_count, size_t template_index)
{
  return template_index + 1 < template_byte_count && template_text[template_index] == '@' && template_text[template_index + 1] == '@';
}

static PagesPlaceholder_t static_readPlaceholder(const char* template_text, size_t template_byte_count, size_t template_index)
{
  PagesPlaceholder_t placeholder = {
    .m_isClosed      = false,
    .mp_name         = NULL,
    .m_nameByteCount = 0,
  };
  size_t name_start_index = template_index + PAGES_PLACEHOLDER_MARK_BYTE_COUNT;
  size_t name_end_index   = name_start_index + static_countPlaceholderNameBytes(template_text + name_start_index, template_byte_count - name_start_index);

  if (name_end_index + 1 < template_byte_count && template_text[name_end_index] == '@' && template_text[name_end_index + 1] == '@')
  {
    placeholder.m_isClosed      = true;
    placeholder.mp_name         = template_text + name_start_index;
    placeholder.m_nameByteCount = name_end_index - name_start_index;
  }
  return placeholder;
}

static size_t static_countPlaceholderNameBytes(const char* name_text, size_t remaining_byte_count)
{
  size_t name_byte_count = 0;
  while (name_byte_count < remaining_byte_count && static_isByteAllowedInPlaceholderName(name_text[name_byte_count]))
    name_byte_count++;
  return name_byte_count;
}

static bool static_isByteAllowedInPlaceholderName(char byte)
{
  return (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9') || byte == '_';
}

static const char* static_findPlaceholderValue(const PagesValue_t* values, int value_count, const char* name, size_t name_byte_count)
{
  for (int i = 0; i < value_count; i++)
  {
    if (bytes_isEqual(name, name_byte_count, values[i].mp_name, false))
      return values[i].mp_value;
  }
  return NULL;
}

static bool static_appendToRendered(PagesRendered_t* rendered_template, const char* bytes, size_t added_byte_count)
{
  if (added_byte_count >= rendered_template->m_capacity - rendered_template->m_byteCount)
    return false;

  memcpy(rendered_template->mp_text + rendered_template->m_byteCount, bytes, added_byte_count);
  rendered_template->m_byteCount += added_byte_count;
  return true;
}
