"""Tests for scripts/backfill_mitre_fields.py"""

import json
import sys
from pathlib import Path

# Make scripts/ importable from the test suite (app/ is already on sys.path via conftest)
_CONTRASTAPI_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _CONTRASTAPI_ROOT not in sys.path:
    sys.path.insert(0, _CONTRASTAPI_ROOT)

import scripts.backfill_mitre_fields as _backfill_mod  # noqa: E402 (loaded once)


def _mitre_record(cve_id, cwe="CWE-79", cvss=7.5, product="testpkg"):
    return {
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Test vuln"}],
                "problemTypes": [{"descriptions": [{"cweId": cwe}]}],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": cvss,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "baseSeverity": "HIGH",
                        }
                    }
                ],
                "affected": [
                    {"vendor": "testvendor", "product": product, "versions": [{"version": "1.0", "status": "affected"}]}
                ],
                "references": [{"url": f"https://example.com/{cve_id}"}],
            }
        },
    }


def _seed_empty_cve(cve_id):
    from db import get_cve_db

    with get_cve_db() as con:
        con.execute(
            "INSERT OR IGNORE INTO cves (cve_id, description) VALUES (?, NULL)",
            (cve_id,),
        )


class TestBackfillMitre:
    def test_backfill_dry_run_no_writes(self, monkeypatch, tmp_path):
        from db import get_cve_db

        _seed_empty_cve("CVE-2025-1001")

        monkeypatch.setattr(_backfill_mod, "_fetch_mitre_cve", lambda cid: _mitre_record(cid))

        state_file = tmp_path / "state.json"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "backfill",
                "--dry-run",
                "--limit",
                "1",
                "--state-file",
                str(state_file),
            ],
        )
        rc = _backfill_mod.main()
        assert rc == 0

        # State file must NOT be written in dry-run
        assert not state_file.exists()

        # DB row must remain unchanged
        with get_cve_db() as con:
            row = con.execute("SELECT cwe_id, cvss_v3 FROM cves WHERE cve_id=?", ("CVE-2025-1001",)).fetchone()
        assert row[0] is None
        assert row[1] is None

    def test_backfill_fills_empty_fields(self, monkeypatch, tmp_path):
        from db import get_cve, get_cve_db

        _seed_empty_cve("CVE-2025-1002")

        monkeypatch.setattr(_backfill_mod, "_fetch_mitre_cve", lambda cid: _mitre_record(cid))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "backfill",
                "--limit",
                "1",
                "--state-file",
                str(tmp_path / "state.json"),
            ],
        )
        rc = _backfill_mod.main()
        assert rc == 0

        row = get_cve("CVE-2025-1002")
        assert row["cwe_id"] == "CWE-79"
        assert row["cvss_v3"] == 7.5

        with get_cve_db() as con:
            src = con.execute("SELECT source FROM cve_sources WHERE cve_id=?", ("CVE-2025-1002",)).fetchone()
        assert src is not None and src[0] == "mitre"

    def test_backfill_preserves_strong_fields(self, monkeypatch, tmp_path):
        from db import get_cve, upsert_cve

        # Partial strong fields: cvss+cwe set but affected_products NULL → EMPTY_CVE_SQL selects it
        upsert_cve(
            {
                "cve_id": "CVE-2025-1003",
                "cvss_v3": 9.8,
                "cwe_id": "CWE-22",
            }
        )

        monkeypatch.setattr(
            _backfill_mod,
            "_fetch_mitre_cve",
            lambda cid: _mitre_record(cid, cwe="CWE-99", cvss=2.0),
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "backfill",
                "--state-file",
                str(tmp_path / "state.json"),
            ],
        )
        _backfill_mod.main()

        row = get_cve("CVE-2025-1003")
        # Strong fields preserved by upsert_cve_if_absent COALESCE logic
        assert row["cvss_v3"] == 9.8
        assert row["cwe_id"] == "CWE-22"
        # Weak field (affected_products) was NULL → now populated from fetch
        assert row["affected_products"] is not None and len(row["affected_products"]) > 0

    def test_backfill_idempotent_on_rerun(self, monkeypatch, tmp_path):
        from db import get_cve_db

        _seed_empty_cve("CVE-2025-1004")

        monkeypatch.setattr(_backfill_mod, "_fetch_mitre_cve", lambda cid: _mitre_record(cid))

        state_file = str(tmp_path / "state.json")
        for _ in range(2):
            monkeypatch.setattr(
                sys,
                "argv",
                [
                    "backfill",
                    "--limit",
                    "1",
                    "--reset",
                    "--state-file",
                    state_file,
                ],
            )
            _backfill_mod.main()

        with get_cve_db() as con:
            count = con.execute("SELECT COUNT(*) FROM cve_products WHERE cve_id=?", ("CVE-2025-1004",)).fetchone()[0]
        # Only one product row despite two runs
        assert count == 1

    def test_backfill_resume_from_state_file(self, monkeypatch, tmp_path):
        for cid in ("CVE-2025-1005", "CVE-2025-1006", "CVE-2025-1009"):
            _seed_empty_cve(cid)

        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"last_cve_id": "CVE-2025-1007"}))

        fetched: list[str] = []

        def _mock_fetch(cid):
            fetched.append(cid)
            return _mitre_record(cid)

        monkeypatch.setattr(_backfill_mod, "_fetch_mitre_cve", _mock_fetch)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "backfill",
                "--state-file",
                str(state_file),
            ],
        )
        _backfill_mod.main()

        assert "CVE-2025-1005" not in fetched
        assert "CVE-2025-1006" not in fetched
        assert "CVE-2025-1009" in fetched

    def test_backfill_skips_malformed_cve_id(self, monkeypatch, tmp_path):
        from db import get_cve_db

        # Inject a malformed row directly (bypasses validate_cve_id in normal path)
        with get_cve_db() as con:
            con.execute("INSERT OR IGNORE INTO cves (cve_id, description) VALUES (?, NULL)", ("CVE-BOGUS",))

        _seed_empty_cve("CVE-2025-1100")

        fetched: list[str] = []

        def _mock_fetch(cid):
            fetched.append(cid)
            return _mitre_record(cid)

        monkeypatch.setattr(_backfill_mod, "_fetch_mitre_cve", _mock_fetch)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "backfill",
                "--state-file",
                str(tmp_path / "state.json"),
            ],
        )
        _backfill_mod.main()

        assert "CVE-BOGUS" not in fetched
        assert "CVE-2025-1100" in fetched

    def test_backfill_handles_fetch_failure(self, monkeypatch, tmp_path):
        monkeypatch.setattr(_backfill_mod, "_fetch_mitre_cve", lambda cid: None)

        _seed_empty_cve("CVE-2025-1010")

        state_file = tmp_path / "state.json"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "backfill",
                "--limit",
                "1",
                "--state-file",
                str(state_file),
            ],
        )
        rc = _backfill_mod.main()
        assert rc == 0

        # State must advance past the failed CVE
        saved = json.loads(state_file.read_text())
        assert saved["last_cve_id"] == "CVE-2025-1010"
