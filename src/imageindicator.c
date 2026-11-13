#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "imageindicator.h"

static const char* const KIND_NAMES[IMAGEINDICATOR_KIND_COUNT] = {
  "c2pa_manifest",
  "ai_source_type",
  "ai_generator_parameters",
  "ai_generator_software",
  "gps_position",
  "gps_null_island",
  "identifier_present",
  "original_time_in_future",
  "modified_before_original",
  "gps_time_differs",
  "edit_history",
  "thumbnail",
  "no_capture_metadata",
};

static const ImageIndicatorSeverity_t KIND_SEVERITIES[IMAGEINDICATOR_KIND_COUNT] = {
  IMAGEINDICATOR_SEVERITY_INFO,
  IMAGEINDICATOR_SEVERITY_MODERATE,
  IMAGEINDICATOR_SEVERITY_MODERATE,
  IMAGEINDICATOR_SEVERITY_WEAK,
  IMAGEINDICATOR_SEVERITY_INFO,
  IMAGEINDICATOR_SEVERITY_WEAK,
  IMAGEINDICATOR_SEVERITY_INFO,
  IMAGEINDICATOR_SEVERITY_WEAK,
  IMAGEINDICATOR_SEVERITY_WEAK,
  IMAGEINDICATOR_SEVERITY_WEAK,
  IMAGEINDICATOR_SEVERITY_INFO,
  IMAGEINDICATOR_SEVERITY_INFO,
  IMAGEINDICATOR_SEVERITY_INFO,
};

static const char* const KIND_NOTES[IMAGEINDICATOR_KIND_COUNT] = {
  "The file carries a C2PA manifest. Its signature is not checked, so the manifest is a claim about who made the image, not proof.",
  "The digital source type names trained algorithmic media: the metadata says a trained model made or edited the image.",
  "A PNG text chunk carries generator parameters, as image generators write them.",
  "The software or the creator tool names a known image generator.",
  "The file carries a GPS position: where the file says the image was taken.",
  "The GPS position is latitude 0, longitude 0, a point in the Gulf of Guinea.",
  "A tag that can tie the image to a person or a device is present. Its value is not shown.",
  "The original time is more than a day ahead of the server's clock.",
  "The modify date is before the original time, which no single clock writes.",
  "The GPS time and the original time are more than an hour apart.",
  "The XMP history lists at least one edit.",
  "The file carries an embedded thumbnail. A thumbnail can show an earlier version of the image.",
  "The file names no camera make, no model and no original time. Absent metadata is not a sign of forgery: many tools strip it.",
};
_Static_assert(IMAGEINDICATOR_KIND_COUNT == 13, "KIND_NAMES, KIND_SEVERITIES and KIND_NOTES name each ImageIndicatorKind_t");

static const char* const SEVERITY_NAMES[IMAGEINDICATOR_SEVERITY_COUNT] = { "info", "weak", "moderate" };

static const char* const AI_GENERATOR_NAMES[] = {
  "stable diffusion",
  "midjourney",
  "dall-e",
  "firefly",
  "comfyui",
  "invokeai",
  "novelai",
  "fooocus",
};
static const size_t AI_GENERATOR_NAME_COUNT = sizeof(AI_GENERATOR_NAMES) / sizeof(AI_GENERATOR_NAMES[0]);

#define IMAGEINDICATOR_AI_SOURCE_TYPE_TEXT "trainedalgorithmicmedia"

#define IMAGEINDICATOR_TM_YEAR_BASE    1900
#define IMAGEINDICATOR_FIRST_YEAR      1970
#define IMAGEINDICATOR_MAX_OFFSET_HOUR 14

static bool static_hasPartIgnoringCase(const char* text, const char* lower_case_part);
static bool static_hasAiGeneratorName(const char* text);
static bool static_tryReadTime(const char* text, int64_t* epoch_out);
static bool static_tryReadTimeOffset(const char* text, int64_t* time_offset_sec_out);
static int  static_readNumber(const char* digits, int digit_count);

void imageindicator_find(const ExifClientResult_t* exif, ImageIndicatorResult_t* result_out)
{
  assert(exif != NULL);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));
  bool* is_present = result_out->ma_isIndicatorPresent;

  is_present[IMAGEINDICATOR_KIND_C2PA_MANIFEST]           = exif->m_hasC2paManifest;
  is_present[IMAGEINDICATOR_KIND_AI_SOURCE_TYPE]          = static_hasPartIgnoringCase(exif->ma_digitalSourceType, IMAGEINDICATOR_AI_SOURCE_TYPE_TEXT);
  is_present[IMAGEINDICATOR_KIND_AI_GENERATOR_PARAMETERS] = exif->m_hasGeneratorParameters;
  is_present[IMAGEINDICATOR_KIND_AI_GENERATOR_SOFTWARE]   = static_hasAiGeneratorName(exif->ma_software) || static_hasAiGeneratorName(exif->ma_creatorTool);
  is_present[IMAGEINDICATOR_KIND_GPS_POSITION]            = exif->m_hasGpsPosition;
  is_present[IMAGEINDICATOR_KIND_GPS_NULL_ISLAND]         = exif->m_hasGpsPosition && exif->m_gpsLatitude == 0.0 && exif->m_gpsLongitude == 0.0;
  for (int kind = 0; kind < EXIFCLIENT_IDENTIFIER_COUNT; kind++)
  {
    if (exif->ma_isIdentifierPresent[kind])
      is_present[IMAGEINDICATOR_KIND_IDENTIFIER] = true;
  }

  int64_t original_time = 0;
  int64_t offset_sec    = 0;
  int64_t modify_time   = 0;
  int64_t gps_time      = 0;
  bool has_original = static_tryReadTime(exif->ma_dateTimeOriginal, &original_time);
  bool has_offset   = static_tryReadTimeOffset(exif->ma_offsetTimeOriginal, &offset_sec);
  bool has_modify   = static_tryReadTime(exif->ma_modifyDate, &modify_time);
  bool has_gps_time = static_tryReadTime(exif->ma_gpsDateTime, &gps_time);
  int64_t original_utc = original_time - (has_offset ? offset_sec : 0);
  is_present[IMAGEINDICATOR_KIND_ORIGINAL_TIME_IN_FUTURE]  = has_original && original_utc > (int64_t)time(NULL) + IMAGEINDICATOR_FUTURE_SLACK_SEC;
  is_present[IMAGEINDICATOR_KIND_MODIFIED_BEFORE_ORIGINAL] = has_original && has_modify && modify_time < original_time;
  is_present[IMAGEINDICATOR_KIND_GPS_TIME_DIFFERS]         = has_original && has_offset && has_gps_time && llabs(gps_time - original_utc) > IMAGEINDICATOR_GPS_TIME_TOLERANCE_SEC;

  is_present[IMAGEINDICATOR_KIND_EDIT_HISTORY]        = exif->m_editHistoryEntryCount > 0;
  is_present[IMAGEINDICATOR_KIND_THUMBNAIL]           = exif->m_thumbnailByteCount > 0;
  is_present[IMAGEINDICATOR_KIND_NO_CAPTURE_METADATA] = exif->ma_cameraMake[0] == '\0' && exif->ma_cameraModel[0] == '\0' && exif->ma_dateTimeOriginal[0] == '\0';
}

const char* imageindicator_kindName(ImageIndicatorKind_t kind)
{
  assert(kind >= 0 && kind < IMAGEINDICATOR_KIND_COUNT);
  return KIND_NAMES[kind];
}

ImageIndicatorSeverity_t imageindicator_kindSeverity(ImageIndicatorKind_t kind)
{
  assert(kind >= 0 && kind < IMAGEINDICATOR_KIND_COUNT);
  return KIND_SEVERITIES[kind];
}

const char* imageindicator_kindNote(ImageIndicatorKind_t kind)
{
  assert(kind >= 0 && kind < IMAGEINDICATOR_KIND_COUNT);
  return KIND_NOTES[kind];
}

const char* imageindicator_severityName(ImageIndicatorSeverity_t severity)
{
  assert(severity >= 0 && severity < IMAGEINDICATOR_SEVERITY_COUNT);
  return SEVERITY_NAMES[severity];
}

static bool static_hasPartIgnoringCase(const char* text, const char* lower_case_part)
{
  size_t part_len = strlen(lower_case_part);
  for (size_t start = 0; text[start] != '\0'; start++)
  {
    size_t i = 0;
    while (i < part_len && text[start + i] != '\0' && tolower((unsigned char)text[start + i]) == (unsigned char)lower_case_part[i])
      i++;

    if (i == part_len)
      return true;
  }
  return false;
}

static bool static_hasAiGeneratorName(const char* text)
{
  for (size_t i = 0; i < AI_GENERATOR_NAME_COUNT; i++)
  {
    if (static_hasPartIgnoringCase(text, AI_GENERATOR_NAMES[i]))
      return true;
  }
  return false;
}

static bool static_tryReadTime(const char* text, int64_t* epoch_out)
{
  static const char PATTERN[] = "dddd:dd:dd dd:dd:dd";
  for (size_t i = 0; PATTERN[i] != '\0'; i++)
  {
    bool is_digit_wanted = PATTERN[i] == 'd';
    bool is_digit        = isdigit((unsigned char)text[i]);

    if (is_digit_wanted ? !is_digit : text[i] != PATTERN[i])
      return false;
  }

  struct tm when;
  memset(&when, 0, sizeof(when));
  when.tm_year = static_readNumber(text, 4) - IMAGEINDICATOR_TM_YEAR_BASE;
  when.tm_mon  = static_readNumber(text + 5, 2) - 1;
  when.tm_mday = static_readNumber(text + 8, 2);
  when.tm_hour = static_readNumber(text + 11, 2);
  when.tm_min  = static_readNumber(text + 14, 2);
  when.tm_sec  = static_readNumber(text + 17, 2);
  if (when.tm_year < IMAGEINDICATOR_FIRST_YEAR - IMAGEINDICATOR_TM_YEAR_BASE  ||
      when.tm_mon < 0   || when.tm_mon > 11                                   ||
      when.tm_mday < 1  || when.tm_mday > 31                                  ||
      when.tm_hour > 23 || when.tm_min > 59 || when.tm_sec > 60)
  {
    return false;
  }

  *epoch_out = (int64_t)timegm(&when);
  return true;
}

static bool static_tryReadTimeOffset(const char* text, int64_t* time_offset_sec_out)
{
  bool is_sign_ok   = text[0] == '+' || text[0] == '-';
  bool is_digits_ok = isdigit((unsigned char)text[1]) && isdigit((unsigned char)text[2]) && text[3] == ':' &&
                      isdigit((unsigned char)text[4]) && isdigit((unsigned char)text[5]) && text[6] == '\0';
  if (!is_sign_ok || !is_digits_ok)
    return false;

  int hour   = static_readNumber(text + 1, 2);
  int minute = static_readNumber(text + 4, 2);
  if (hour > IMAGEINDICATOR_MAX_OFFSET_HOUR || minute > 59)
    return false;

  int64_t magnitude = (int64_t)hour * 60 * 60 + (int64_t)minute * 60;
  *time_offset_sec_out = text[0] == '-' ? -magnitude : magnitude;

  return true;
}

static int static_readNumber(const char* digits, int digit_count)
{
  int number = 0;
  for (int i = 0; i < digit_count; i++)
    number = number * 10 + (digits[i] - '0');

  return number;
}
