"""MITRE D3FEND sync engine — fetches pre-joined attack↔defense mappings.

Source: https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json
Format: SPARQL query result (head.vars + results.bindings).
Each binding row = one (attack ATT&CK T-code) ↔ (D3FEND defense) pair.
Update cadence: continuous (live SPARQL inference). Idempotent.
"""

import logging
from urllib.parse import urlparse

import httpx
from db import (
    get_cve_db,
    update_sync_status,
    upsert_d3fend_attack_mappings,
    upsert_d3fend_defense,
)
from domain.recon import _strip_control_chars

log = logging.getLogger("contrastapi")

D3FEND_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"
D3FEND_MAX_BYTES = 100 * 1024 * 1024  # 100 MB cap (current ~45 MB)
HTTP_TIMEOUT = 120
USER_AGENT = "ContrastAPI/1.0 (api.contrastcyber.com)"
ATTACK_MAPPING_CHUNK = 2000

VALID_TACTICS = {"Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"}

_client = httpx.AsyncClient(
    timeout=httpx.Timeout(HTTP_TIMEOUT, connect=10.0),
    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    follow_redirects=True,
)


def _slug_from_uri(uri: str | None) -> str | None:
    """Extract the fragment after '#' from a D3FEND ontology URI.

    'http://d3fend.mitre.org/ontologies/d3fend.owl#TokenBinding' -> 'TokenBinding'
    """
    if not isinstance(uri, str) or not uri:
        return None
    if "#" in uri:
        return uri.rsplit("#", 1)[1]
    parsed = urlparse(uri)
    if parsed.path:
        tail = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        return tail or None
    return None


def _binding_value(binding: dict, key: str) -> str | None:
    """Extract `value` field from a SPARQL JSON binding cell. None on missing or non-string.

    Applies `_strip_control_chars` to defend against Trojan-Source bidi/RTL
    injection in upstream MITRE D3FEND fields.
    """
    cell = binding.get(key)
    if isinstance(cell, dict):
        v = cell.get("value")
        if isinstance(v, str):
            return _strip_control_chars(v)
    return None


async def sync_d3fend() -> int:
    """Sync D3FEND defense catalog and attack mappings. Returns count of mapping rows upserted."""
    log.info("D3FEND sync starting...")
    update_sync_status("d3fend", 0, "in_progress")
    defense_count = 0
    mapping_count = 0

    try:
        resp = await _client.get(D3FEND_URL)
        resp.raise_for_status()
        if len(resp.content) > D3FEND_MAX_BYTES:
            log.error("D3FEND mappings exceed %d bytes (%d) — refusing", D3FEND_MAX_BYTES, len(resp.content))
            update_sync_status("d3fend", 0, "error")
            return 0
        data = resp.json()

        bindings = (data or {}).get("results", {}).get("bindings") or []
        if not isinstance(bindings, list):
            log.error("D3FEND mappings has no bindings list")
            update_sync_status("d3fend", 0, "error")
            return 0

        defenses_seen: dict[str, dict] = {}
        mapping_batch: list[dict] = []
        mapping_keys: set[tuple[str, str]] = set()

        for b in bindings:
            if not isinstance(b, dict):
                continue
            def_uri = _binding_value(b, "def_tech")
            def_label = _binding_value(b, "def_tech_label")
            def_tactic = _binding_value(b, "def_tactic_label")
            attack_id = _binding_value(b, "off_tech_id")
            if not def_uri or not def_label or not def_tactic or not attack_id:
                continue
            if def_tactic not in VALID_TACTICS:
                continue
            defense_id = _slug_from_uri(def_uri)
            if not defense_id:
                continue

            if defense_id not in defenses_seen:
                defenses_seen[defense_id] = {
                    "label": def_label,
                    "uri": def_uri,
                    "parent_label": _binding_value(b, "top_def_tech_label"),
                    "tactic": def_tactic,
                    "artifact": _binding_value(b, "def_artifact_label"),
                }

            mkey = (defense_id, attack_id)
            if mkey in mapping_keys:
                continue
            mapping_keys.add(mkey)
            mapping_batch.append(
                {
                    "defense_id": defense_id,
                    "attack_technique_id": attack_id,
                    "attack_label": _binding_value(b, "off_tech_label"),
                    "attack_tactic": _binding_value(b, "off_tactic_label"),
                }
            )

            if len(mapping_batch) >= ATTACK_MAPPING_CHUNK:
                mapping_count += upsert_d3fend_attack_mappings(mapping_batch)
                mapping_batch = []

        if mapping_batch:
            mapping_count += upsert_d3fend_attack_mappings(mapping_batch)

        for def_id, fields in defenses_seen.items():
            try:
                upsert_d3fend_defense(
                    def_id,
                    label=fields["label"][:512],
                    uri=fields["uri"][:1024],
                    parent_label=(fields["parent_label"] or None),
                    description=None,
                    tactic=fields["tactic"],
                    artifact=fields["artifact"],
                )
                defense_count += 1
            except Exception as e:
                log.warning("D3FEND defense upsert failed for %s: %s", def_id, type(e).__name__)

    except Exception as e:
        log.error("D3FEND sync failed: %s", e)
        update_sync_status("d3fend", mapping_count, "error")
        return mapping_count

    # Count distinct mappings actually persisted (PK dedup may collapse upstream rows)
    with get_cve_db() as con:
        distinct_mappings = con.execute("SELECT COUNT(*) FROM d3fend_attack_mappings").fetchone()[0]

    update_sync_status("d3fend", int(distinct_mappings), "ok")
    log.info(
        "D3FEND sync complete: %d defenses, %d distinct mappings (%d unique binding pairs processed)",
        defense_count,
        distinct_mappings,
        mapping_count,
    )
    return int(distinct_mappings)
