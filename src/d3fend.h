#ifndef D3FEND_H
#define D3FEND_H

#include "attack.h"

#define D3FEND_DEFENSE_ID_MAX_LEN        64
#define D3FEND_DEFENSE_LABEL_MAX_LEN    128
#define D3FEND_DEFENSE_TACTIC_MAX_LEN     7
#define D3FEND_DIGITAL_ARTIFACT_MAX_LEN 128

typedef struct {
  char ma_attackTechniqueId[ATTACK_TECHNIQUE_ID_MAX_LEN + 1];
} D3FENDFORATTACKParams_t;

typedef struct {
  char  ma_defenseId[D3FEND_DEFENSE_ID_MAX_LEN + 1];
  char  ma_defenseLabel[D3FEND_DEFENSE_LABEL_MAX_LEN + 1];
  char  ma_defenseTactic[D3FEND_DEFENSE_TACTIC_MAX_LEN + 1];
  char  ma_digitalArtifact[D3FEND_DIGITAL_ARTIFACT_MAX_LEN + 1];
  char* mp_parentDefenseLabels;
  char* mp_attackTechniqueIds;
} D3FENDFORATTACKItem_t;

typedef struct {
  char*                  mp_attackTechniques;
  int                    m_defenseCount;
  D3FENDFORATTACKItem_t* mp_defenses;
} D3FENDFORATTACKResult_t;

#endif
