#ifndef CVSS_H
#define CVSS_H

#define CVSS_VECTOR_MAX_LEN 128
#define CVSS_VERSION_LEN      4
#define CVSS_LABEL_LEN       20

typedef enum {
  CVSS_OK = 0,
  CVSS_ERR_EMPTY,
  CVSS_ERR_TOO_LONG,
  CVSS_ERR_NOT_V3,
  CVSS_ERR_UNKNOWN_METRIC,
  CVSS_ERR_UNKNOWN_VALUE,
  CVSS_ERR_DUPLICATE_METRIC,
  CVSS_ERR_MISSING_BASE_METRIC,
  CVSS_ERR_EMPTY_COMPONENT
} CvssParseStatus_t;

typedef struct {
  char ma_vector[CVSS_VECTOR_MAX_LEN];
} CVSSCALCULATORParams_t;

typedef struct {
  char   ma_vector[CVSS_VECTOR_MAX_LEN];
  char   ma_version[CVSS_VERSION_LEN];
  char   ma_baseSeverity[CVSS_LABEL_LEN];
  char   ma_attackVector[CVSS_LABEL_LEN];
  char   ma_attackComplexity[CVSS_LABEL_LEN];
  char   ma_privilegesRequired[CVSS_LABEL_LEN];
  char   ma_userInteraction[CVSS_LABEL_LEN];
  char   ma_scope[CVSS_LABEL_LEN];
  char   ma_confidentialityImpact[CVSS_LABEL_LEN];
  char   ma_integrityImpact[CVSS_LABEL_LEN];
  char   ma_availabilityImpact[CVSS_LABEL_LEN];
  double m_baseScore;
  double m_temporalScore;
  double m_environmentalScore;
} CvssResult_t;

CvssParseStatus_t cvss_parse(const char* vector, CvssResult_t* result_out);
const char*       cvss_parseStatusMessage(CvssParseStatus_t status);

#endif
