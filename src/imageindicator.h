#ifndef IMAGEINDICATOR_H
#define IMAGEINDICATOR_H

#include <stdbool.h>

#include "exifclient.h"

typedef enum {
  IMAGEINDICATOR_KIND_C2PA_MANIFEST = 0,
  IMAGEINDICATOR_KIND_AI_SOURCE_TYPE,
  IMAGEINDICATOR_KIND_AI_GENERATOR_PARAMETERS,
  IMAGEINDICATOR_KIND_AI_GENERATOR_SOFTWARE,
  IMAGEINDICATOR_KIND_GPS_POSITION,
  IMAGEINDICATOR_KIND_GPS_NULL_ISLAND,
  IMAGEINDICATOR_KIND_IDENTIFIER,
  IMAGEINDICATOR_KIND_ORIGINAL_TIME_IN_FUTURE,
  IMAGEINDICATOR_KIND_MODIFIED_BEFORE_ORIGINAL,
  IMAGEINDICATOR_KIND_GPS_TIME_DIFFERS,
  IMAGEINDICATOR_KIND_EDIT_HISTORY,
  IMAGEINDICATOR_KIND_THUMBNAIL,
  IMAGEINDICATOR_KIND_NO_CAPTURE_METADATA,
  IMAGEINDICATOR_KIND_COUNT
} ImageIndicatorKind_t;

typedef enum {
  IMAGEINDICATOR_SEVERITY_INFO = 0,
  IMAGEINDICATOR_SEVERITY_WEAK,
  IMAGEINDICATOR_SEVERITY_MODERATE,
  IMAGEINDICATOR_SEVERITY_COUNT
} ImageIndicatorSeverity_t;

#define IMAGEINDICATOR_FUTURE_SLACK_SEC       (24 * 60 * 60)
#define IMAGEINDICATOR_GPS_TIME_TOLERANCE_SEC (60 * 60)

typedef struct {
  bool ma_isIndicatorPresent[IMAGEINDICATOR_KIND_COUNT];
} ImageIndicatorResult_t;

void                     imageindicator_find         (const ExifClientResult_t* exif, ImageIndicatorResult_t* result_out);
const char*              imageindicator_kindName     (ImageIndicatorKind_t kind);
ImageIndicatorSeverity_t imageindicator_kindSeverity (ImageIndicatorKind_t kind);
const char*              imageindicator_kindNote     (ImageIndicatorKind_t kind);
const char*              imageindicator_severityName (ImageIndicatorSeverity_t severity);

#endif
