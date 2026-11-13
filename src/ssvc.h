#ifndef SSVC_H
#define SSVC_H

#define SSVC_DECISION_NAME_LEN 6

#define SSVC_REMEDIATION_ADVICE_LEN 37

#define SSVC_TREE_VERSION "2.0.3"

typedef enum {
  SSVC_MISSION_WELLBEING_LOW = 0,
  SSVC_MISSION_WELLBEING_MEDIUM,
  SSVC_MISSION_WELLBEING_HIGH,
  SSVC_MISSION_WELLBEING_LEVEL_COUNT
} SsvcMissionWellbeing_t;

typedef enum {
  SSVC_OK = 0,
  SSVC_ERR_EXPLOITATION,
  SSVC_ERR_AUTOMATABLE,
  SSVC_ERR_TECHNICAL_IMPACT
} SsvcStatus_t;

typedef struct {
  char ma_decisions[SSVC_MISSION_WELLBEING_LEVEL_COUNT][SSVC_DECISION_NAME_LEN + 1];
  char ma_remediationAdvice[SSVC_MISSION_WELLBEING_LEVEL_COUNT][SSVC_REMEDIATION_ADVICE_LEN + 1];
} SsvcResult_t;

SsvcStatus_t ssvc_evaluate(const char* exploitation, const char* automatable, const char* technical_impact, SsvcResult_t* result_out);  

#endif
