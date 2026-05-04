"""MITRE ATLAS sync engine — fetches AI/ML attack catalog from upstream YAML.

Source: https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml
Format: YAML with `matrices[].techniques` and top-level `case-studies`.
Update cadence: quarterly. Idempotent — safe to re-run.
"""

import logging

import httpx
import yaml
from db import update_sync_status, upsert_atlas_case_study, upsert_atlas_technique
from domain.recon import _strip_control_chars

log = logging.getLogger("contrastapi")

ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
ATLAS_MAX_BYTES = 5 * 1024 * 1024  # 5 MB cap (current ~440 KB)
HTTP_TIMEOUT = 60
USER_AGENT = "ContrastAPI/1.0 (api.contrastcyber.com)"

_client = httpx.AsyncClient(
    timeout=httpx.Timeout(HTTP_TIMEOUT, connect=10.0),
    headers={"User-Agent": USER_AGENT, "Accept": "text/yaml"},
    follow_redirects=True,
)


def _stringify_date(value) -> str | None:
    """ATLAS YAML dates may be `datetime.date` after safe_load. Normalize to ISO string."""
    if value is None:
        return None
    return str(value)


def _clean(s) -> str | None:
    """Strip control + Unicode bidi chars from upstream-derived strings (Trojan-Source guard)."""
    if s is None:
        return None
    return _strip_control_chars(str(s))


async def sync_atlas() -> int:
    """Sync MITRE ATLAS catalog (techniques + case studies). Returns total upserted count."""
    log.info("ATLAS sync starting...")
    update_sync_status("atlas", 0, "in_progress")
    technique_count = 0
    case_study_count = 0

    try:
        resp = await _client.get(ATLAS_URL)
        resp.raise_for_status()
        if len(resp.content) > ATLAS_MAX_BYTES:
            log.error("ATLAS YAML exceeds %d bytes (%d) — refusing", ATLAS_MAX_BYTES, len(resp.content))
            update_sync_status("atlas", 0, "error")
            return 0

        data = yaml.safe_load(resp.content)

        if not isinstance(data, dict):
            log.error("ATLAS YAML root is not a mapping")
            update_sync_status("atlas", 0, "error")
            return 0

        for matrix in data.get("matrices") or []:
            if not isinstance(matrix, dict):
                continue
            for tech in matrix.get("techniques") or []:
                if not isinstance(tech, dict):
                    continue
                technique_id = tech.get("id")
                name = tech.get("name")
                if not technique_id or not name:
                    continue
                attack_ref = tech.get("ATT&CK-reference") or {}
                attack_id = attack_ref.get("id") if isinstance(attack_ref, dict) else None
                attack_url = attack_ref.get("url") if isinstance(attack_ref, dict) else None
                tactics = tech.get("tactics") or []
                if not isinstance(tactics, list):
                    tactics = []
                try:
                    upsert_atlas_technique(
                        technique_id,
                        name=_clean(name)[:512],
                        description=(_clean(tech.get("description")) or "").strip()[:16000] or None,
                        tactics=[_clean(t) for t in tactics if t],
                        maturity=_clean(tech.get("maturity")),
                        attack_reference_id=_clean(attack_id),
                        attack_reference_url=_clean(attack_url),
                        subtechnique_of=_clean(tech.get("subtechnique-of")),
                        created_date=_stringify_date(tech.get("created_date")),
                        modified_date=_stringify_date(tech.get("modified_date")),
                    )
                    technique_count += 1
                except Exception as e:
                    log.warning("ATLAS technique upsert failed for %s: %s", technique_id, type(e).__name__)

        for cs in data.get("case-studies") or []:
            if not isinstance(cs, dict):
                continue
            case_study_id = cs.get("id")
            name = cs.get("name")
            if not case_study_id or not name:
                continue
            procedure = cs.get("procedure") or []
            techniques_used: list[str] = []
            if isinstance(procedure, list):
                for step in procedure:
                    if isinstance(step, dict):
                        tid = step.get("technique")
                        if isinstance(tid, str) and tid:
                            techniques_used.append(_clean(tid))
            try:
                upsert_atlas_case_study(
                    case_study_id,
                    name=_clean(name)[:512],
                    description=(_clean(cs.get("summary") or cs.get("description")) or "").strip()[:16000] or None,
                    techniques_used=list(dict.fromkeys(techniques_used)),
                )
                case_study_count += 1
            except Exception as e:
                log.warning("ATLAS case study upsert failed for %s: %s", case_study_id, type(e).__name__)

    except Exception as e:
        log.error("ATLAS sync failed: %s", e)
        update_sync_status("atlas", technique_count + case_study_count, "error")
        return technique_count + case_study_count

    total = technique_count + case_study_count
    update_sync_status("atlas", total, "ok")
    log.info("ATLAS sync complete: %d techniques + %d case studies", technique_count, case_study_count)
    return total
