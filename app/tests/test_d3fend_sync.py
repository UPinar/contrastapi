"""Tests for D3FEND mappings sync — sync_d3fend()."""

import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import httpx
import pytest

ONTOLOGY_HASH = "4909a5bb66b75d2c359624398848936fb56a6b246bcd5cfcd277977a1277753a"
VERSION_OK = {"version": "1.6.0", "ontology_hash_sha256": ONTOLOGY_HASH}


def _binding(def_uri, def_label, parent, def_tactic, def_artifact, off_id, off_label, off_tactic):
    """Build one SPARQL binding row in the format the upstream returns."""
    return {
        "def_tech": {"type": "uri", "value": def_uri},
        "def_tech_label": {"type": "literal", "value": def_label},
        "def_tech_parent_label": {"type": "literal", "value": parent},
        "def_tactic_label": {"type": "literal", "value": def_tactic},
        "def_artifact_label": {"type": "literal", "value": def_artifact},
        "off_tech_id": {"type": "literal", "value": off_id},
        "off_tech_label": {"type": "literal", "value": off_label},
        "off_tactic_label": {"type": "literal", "value": off_tactic},
    }


_TOKEN_BINDING = "http://d3fend.mitre.org/ontologies/d3fend.owl#TokenBinding"
_FILE_HASHING = "http://d3fend.mitre.org/ontologies/d3fend.owl#FileHashing"

# Upstream serves mappings one ATT&CK technique at a time; each response carries
# only that technique's rows. Four distinct (defense, technique) pairs in total.
SAMPLE_BY_TECHNIQUE = {
    "T1550.001": [
        _binding(
            _TOKEN_BINDING,
            "Token Binding",
            "Credential Hardening",
            "Harden",
            "Access Token",
            "T1550.001",
            "Application Access Token",
            "Lateral Movement",
        ),
        _binding(
            _FILE_HASHING,
            "File Hashing",
            "File Analysis",
            "Detect",
            "File",
            "T1550.001",
            "Application Access Token",
            "Lateral Movement",
        ),
    ],
    "T1539": [
        _binding(
            _TOKEN_BINDING,
            "Token Binding",
            "Credential Hardening",
            "Harden",
            "Access Token",
            "T1539",
            "Steal Web Session Cookie",
            "Credential Access",
        ),
    ],
    "T1059": [
        _binding(
            _FILE_HASHING,
            "File Hashing",
            "File Analysis",
            "Detect",
            "File",
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
        ),
    ],
}


class _StreamCtx:
    """Stand-in for httpx's streaming context manager."""

    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *exc):
        return False


def _resp(payload, *, ok=True, body=None, headers=None, chunk=4096):
    """One fake response. `headers`, when given, REPLACES the default header set."""
    data = body if body is not None else json.dumps(payload).encode()
    r = MagicMock()
    r.headers = {"content-length": str(len(data))} if headers is None else dict(headers)
    if ok:
        r.raise_for_status.return_value = None
    else:
        r.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found", request=httpx.Request("GET", "https://d3fend.mitre.org/"), response=httpx.Response(404)
        )

    async def _aiter():
        for i in range(0, max(len(data), 1), chunk):
            yield data[i : i + chunk]

    r.aiter_raw = _aiter
    return r


class _FakeClient:
    """Dispatches on URL: version -> technique index -> per-technique mappings."""

    follow_redirects = False

    def __init__(
        self,
        *,
        by_technique=None,
        version=None,
        deprecated=(),
        failing=(),
        index_ids=None,
        malformed=None,
        technique_resp=None,
    ):
        self.by_technique = SAMPLE_BY_TECHNIQUE if by_technique is None else by_technique
        self.version = VERSION_OK if version is None else version
        self.deprecated = set(deprecated)
        self.failing = set(failing)
        self.index_ids = index_ids
        self.malformed = malformed or {}
        self.technique_resp = technique_resp
        self.calls = []
        self.request_headers = []

    @property
    def technique_calls(self):
        return [u for u in self.calls if "/offensive-technique/attack/" in u]

    def stream(self, method, url, **kwargs):
        self.calls.append(url)
        self.request_headers.append(kwargs.get("headers"))
        if url.endswith("/api/version.json"):
            return _StreamCtx(_resp(self.version))
        if url.endswith("/offensive-technique/all.json"):
            ids = self.index_ids if self.index_ids is not None else list(self.by_technique)
            graph = []
            for tid in ids:
                entry = {"@id": f"d3f:{tid}", "d3f:attack-id": tid, "rdfs:label": tid}
                if tid in self.deprecated:
                    entry["owl:deprecated"] = True
                graph.append(entry)
            return _StreamCtx(_resp({"@graph": graph}))
        tid = url.rsplit("/", 1)[-1].removesuffix(".json")
        if tid in self.failing:
            # A valid body on a failed status: the HTTP gate must be what rejects this,
            # not the shape gate downstream.
            return _StreamCtx(_resp({"off_to_def": {"results": {"bindings": []}}}, ok=False))
        if tid in self.malformed:
            return _StreamCtx(_resp(self.malformed[tid]))
        if self.technique_resp is not None:
            return _StreamCtx(self.technique_resp())
        return _StreamCtx(_resp({"off_to_def": {"results": {"bindings": self.by_technique.get(tid, [])}}}))


def _run(client, **overrides):
    from d3fend import sync as d3_sync

    patches = [patch.object(d3_sync, "_client", client), patch.object(d3_sync, "CRAWL_DELAY_SECONDS", 0)]
    patches += [patch.object(d3_sync, k, v) for k, v in overrides.items()]
    for p in patches:
        p.start()
    try:
        return asyncio.run(d3_sync.sync_d3fend())
    finally:
        for p in reversed(patches):
            p.stop()


def _status():
    from db import get_sync_status

    return get_sync_status()["d3fend"]


def _pin():
    return _status()["checkpoint"]


# --- happy path -------------------------------------------------------------


def test_sync_d3fend_writes_defenses():
    assert _run(_FakeClient()) == 4

    from db import get_d3fend_defense

    tb = get_d3fend_defense("TokenBinding")
    assert tb is not None
    assert tb["label"] == "Token Binding"
    assert tb["uri"].endswith("#TokenBinding")
    assert tb["parent_label"] == "Credential Hardening"
    assert tb["tactic"] == "Harden"
    assert tb["artifact"] == "Access Token"
    assert set(tb["attack_techniques"]) == {"T1550.001", "T1539"}


def test_sync_d3fend_reverse_lookup():
    _run(_FakeClient())

    from db import get_d3fend_defenses_for_attack

    defenses = get_d3fend_defenses_for_attack("T1550.001")
    assert {d["defense_id"] for d in defenses} == {"TokenBinding", "FileHashing"}
    assert {d["defense_id"] for d in get_d3fend_defenses_for_attack("T1059")} == {"FileHashing"}
    assert get_d3fend_defenses_for_attack("T9999") == []


def test_sync_d3fend_search_by_tactic():
    _run(_FakeClient())

    from db import search_d3fend_defenses

    assert {d["defense_id"] for d in search_d3fend_defenses(tactic="Harden")} == {"TokenBinding"}
    assert {d["defense_id"] for d in search_d3fend_defenses(tactic="Detect")} == {"FileHashing"}


def test_sync_d3fend_coverage():
    _run(_FakeClient())

    from db import get_d3fend_coverage

    cov = get_d3fend_coverage(["T1550.001", "T1059", "T9999"])
    assert cov["coverage_by_tactic"] == {"Harden": 1, "Detect": 1}
    assert "T9999" in cov["undefended_techniques"]
    assert set(cov["defended_techniques"]) == {"T1550.001", "T1059"}


def test_sync_d3fend_marks_status_ok_and_pins_release():
    _run(_FakeClient())

    st = _status()
    assert st["status"] == "ok"
    assert st["records_count"] == 4
    assert st["checkpoint"].startswith(f"{ONTOLOGY_HASH}|")


def test_sync_d3fend_legacy_parent_field_still_read():
    """Upstream renamed top_def_tech_label -> def_tech_parent_label; accept both."""
    row = _binding(
        _TOKEN_BINDING,
        "Token Binding",
        "Credential Hardening",
        "Harden",
        "Access Token",
        "T1539",
        "Steal Web Session Cookie",
        "Credential Access",
    )
    row["top_def_tech_label"] = row.pop("def_tech_parent_label")
    assert _run(_FakeClient(by_technique={"T1539": [row]})) == 1

    from db import get_d3fend_defense

    assert get_d3fend_defense("TokenBinding")["parent_label"] == "Credential Hardening"


def test_sync_d3fend_requests_identity_encoding():
    """A compressed body is expanded before any size check could see it."""
    from d3fend import sync as d3_sync

    assert d3_sync._client.headers.get("accept-encoding") == "identity"


def test_sync_d3fend_client_does_not_follow_redirects():
    """Redirect following would let a hostile upstream aim ~700 GETs at internal hosts."""
    from d3fend import sync as d3_sync

    assert d3_sync._client.follow_redirects is False


# --- release gate -----------------------------------------------------------


def test_sync_d3fend_version_gate_skips_crawl(caplog):
    """Unchanged release must not trigger a single technique fetch."""
    import logging

    _run(_FakeClient())

    second = _FakeClient()
    with caplog.at_level(logging.WARNING, logger="contrastapi"):
        assert _run(second) == 4
    assert second.calls == ["https://d3fend.mitre.org/api/version.json"]
    assert _status()["status"] == "ok"
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING], "an unchanged release logged a warning"


def test_sync_d3fend_new_version_triggers_crawl():
    _run(_FakeClient())

    bumped = _FakeClient(version={"ontology_hash_sha256": "deadbeef" * 8})
    assert _run(bumped) == 4
    assert len(bumped.technique_calls) == 3
    assert _pin().startswith("deadbeef" * 8 + "|")


def test_sync_d3fend_stale_pin_forces_recrawl():
    """An upstream replaying one release must not be able to freeze us forever."""
    _run(_FakeClient())

    aged = _FakeClient()
    assert _run(aged, PIN_MAX_AGE=timedelta(seconds=0)) == 4
    assert len(aged.technique_calls) == 3, "expired pin did not force a re-crawl"


def test_sync_d3fend_release_key_falls_back_when_hash_field_moves():
    """1.6.0 already renamed one field; a moved hash key must not blank the pin."""
    client = _FakeClient(version={"ontology_version": "1.7.0"})
    assert _run(client) == 4
    assert _pin().startswith("1.7.0|")


def test_sync_d3fend_release_key_skips_blank_field():
    """An empty hash field must fall through, not be pinned as a release."""
    client = _FakeClient(version={"ontology_hash_sha256": "   ", "version": "1.8.0"})
    assert _run(client) == 4
    assert _pin().startswith("1.8.0|")


def test_sync_d3fend_release_key_skips_a_value_sqlite_cannot_store():
    """A lone surrogate decodes from JSON but cannot be written to the pin; the next field must be used instead."""
    client = _FakeClient(version={"ontology_hash_sha256": "a" + chr(0xD800), "version": "1.9.0"})
    assert _run(client) == 4, "a release the pin write cannot store failed the whole run"
    assert _pin().startswith("1.9.0|")


def test_sync_d3fend_release_key_skips_a_field_that_cleans_to_nothing():
    """A field made only of control characters is as blank as spaces: the next field must be used."""
    client = _FakeClient(version={"ontology_hash_sha256": chr(27) * 3, "version": "1.9.1"})
    assert _run(client) == 4, "a release field that cleans to nothing failed the run"
    assert _pin().startswith("1.9.1|")


def test_sync_d3fend_clean_release_trims_hidden_whitespace_and_is_idempotent():
    """Whitespace a control character hid is trimmed, and cleaning a cleaned release changes nothing.

    Without the second, a pin never reads back equal to what was pinned.
    """
    from d3fend import sync as d3_sync

    cases = (
        ("abc " + chr(27), "abc"),  # a control character hiding a trailing space
        (" " + chr(0x202A) + " abc", "abc"),  # a bidi control hiding a leading space
        ("a" * 127 + " b", "a" * 127),  # the length cap exposing a trailing space
        (chr(9) + chr(0) + " v1 " + chr(0) + chr(9), "v1"),
        (" " * 200 + "v2", "v2"),
        (chr(27) + " " * 200 + "v2", "v2"),  # a control character in front of a run longer than the cap
    )
    for raw, want in cases:
        once = d3_sync._clean_release(raw)
        assert once == want, (raw, once)
        assert d3_sync._clean_release(once) == once, (raw, once)


def test_sync_d3fend_pinned_release_matches_itself_on_the_next_run():
    """A release whose cleaning exposed a trailing space must still pass the version gate on the next run."""
    hostile = {"ontology_hash_sha256": "abc " + chr(27)}
    assert _run(_FakeClient(version=hostile)) == 4
    again = _FakeClient(version=hostile)
    assert _run(again) == 4
    assert again.technique_calls == [], "the pinned release did not match itself, so the run re-crawled"


def test_sync_d3fend_no_release_marker_errors_without_crawling():
    """No marker means we cannot tell changed from unchanged — fail loud, keep the pin."""
    _run(_FakeClient())
    pinned = _pin()

    blind = _FakeClient(version={"unrelated": "x"})
    assert _run(blind) == 0
    assert blind.calls == ["https://d3fend.mitre.org/api/version.json"]
    assert _status()["status"] == "error"
    assert _pin() == pinned


def test_sync_d3fend_release_change_during_crawl_is_not_pinned():
    """A release that rolls mid-crawl leaves us holding a mix — never pin that."""
    _run(_FakeClient())
    pinned = _pin()

    class _Rolling(_FakeClient):
        def stream(self, method, url, **kwargs):
            if url.endswith("/api/version.json") and self.technique_calls:
                self.calls.append(url)
                return _StreamCtx(_resp({"ontology_hash_sha256": "rolled" * 8}))
            return super().stream(method, url, **kwargs)

    assert _run(_Rolling(version={"ontology_hash_sha256": "e" * 64})) == 0
    assert _status()["status"] == "error"
    assert _pin() == pinned


# --- the silent-freeze class ------------------------------------------------


def test_sync_d3fend_partial_crawl_does_not_advance_release_pin():
    """A crawl that lost techniques must never pin: pinning would freeze us on missing data."""
    _run(_FakeClient())
    pinned = _pin()

    partial = _FakeClient(version={"ontology_hash_sha256": "b" * 64}, failing=["T1539"])
    assert _run(partial) == 0
    assert len(partial.technique_calls) == 3  # crawl went on past the failure

    assert _status()["status"] == "error"
    assert _pin() == pinned, "partial crawl advanced the pin — silent freeze"

    retry = _FakeClient(version={"ontology_hash_sha256": "b" * 64})
    assert _run(retry) == 4
    assert len(retry.technique_calls) == 3


def test_sync_d3fend_empty_crawl_does_not_advance_release_pin():
    """Every technique answering with zero bindings is a broken upstream, not a valid release."""
    _run(_FakeClient())
    pinned = _pin()

    empty = _FakeClient(
        version={"ontology_hash_sha256": "c" * 64},
        by_technique={"T1550.001": [], "T1539": [], "T1059": []},
    )
    assert _run(empty) == 0
    assert _status()["status"] == "error"
    assert _pin() == pinned


def test_sync_d3fend_defense_write_failure_blocks_the_pin():
    """Mappings without their defence rows is a half-written release — do not pin it."""
    from d3fend import sync as d3_sync

    client = _FakeClient()
    with patch.object(d3_sync, "upsert_d3fend_defense", side_effect=RuntimeError("disk full")):
        assert _run(client) == 0
    assert _status()["status"] == "error"
    assert _pin() is None


@pytest.mark.parametrize(
    "payload",
    [
        {"off_to_def": "maintenance"},
        {"off_to_def": {"results": "maintenance"}},
        {"off_to_def": {"results": {"bindings": "maintenance"}}},
    ],
)
def test_sync_d3fend_malformed_payload_is_counted_not_raised(payload):
    """Every wrong shape must be a failed technique, never an escaping exception."""
    client = _FakeClient(malformed={"T1539": payload})
    assert _run(client) == 0
    assert len(client.technique_calls) == 3  # crawl continued past the bad shape
    assert _status()["status"] == "error"  # never left stuck at in_progress
    assert _pin() is None


def test_sync_d3fend_unexpected_exception_never_leaves_in_progress():
    """The outer guard is the whole point of C2: nothing may escape sync_d3fend()."""
    from d3fend import sync as d3_sync

    _run(_FakeClient())
    pinned = _pin()

    with patch.object(d3_sync, "_live_technique_ids", side_effect=TypeError("boom")):
        assert _run(_FakeClient(version={"ontology_hash_sha256": "a" * 64})) == 0

    st = _status()
    assert st["status"] == "error"
    assert st["checkpoint"] == pinned


def test_sync_d3fend_unexpected_exception_without_a_pin_still_records_error():
    """The first run has no pin to carry, yet an escaped error must still leave status=error, not in_progress."""
    from d3fend import sync as d3_sync

    with patch.object(d3_sync, "_live_technique_ids", side_effect=TypeError("boom")):
        assert _run(_FakeClient()) == 0

    assert _status()["status"] == "error"
    assert _pin() is None


def test_sync_d3fend_does_not_pin_checkpoint_when_index_fails():
    """A failed crawl must leave the checkpoint alone so the next run retries."""
    _run(_FakeClient())
    pinned = _pin()

    class _BrokenIndex(_FakeClient):
        def stream(self, method, url, **kwargs):
            if url.endswith("/offensive-technique/all.json"):
                self.calls.append(url)
                return _StreamCtx(_resp({"@graph": []}, ok=False))
            return super().stream(method, url, **kwargs)

    _run(_BrokenIndex(version={"ontology_hash_sha256": "feedface" * 8}))

    assert _status()["status"] == "error"
    assert _pin() == pinned


def test_sync_d3fend_version_probe_failure_keeps_pin():
    _run(_FakeClient())
    pinned = _pin()

    class _BrokenVersion(_FakeClient):
        def stream(self, method, url, **kwargs):
            self.calls.append(url)
            return _StreamCtx(_resp(VERSION_OK, ok=False))

    assert _run(_BrokenVersion()) == 0
    assert _status()["status"] == "error"
    assert _pin() == pinned


def test_sync_d3fend_empty_index_errors_and_keeps_pin():
    """Pinned at the index gate itself: an empty list must stop before any crawl bookkeeping."""
    _run(_FakeClient())
    pinned = _pin()

    empty = _FakeClient(version={"ontology_hash_sha256": "d" * 64}, index_ids=[])
    assert _run(empty) == 0
    assert empty.technique_calls == []
    assert empty.calls[-1].endswith("/offensive-technique/all.json"), "crawl bookkeeping ran on an empty index"
    assert _status()["status"] == "error"
    assert _pin() == pinned


def test_sync_d3fend_in_progress_write_keeps_pin():
    """The ~700-request crawl runs while this row is live; blanking it loses the pin."""
    from d3fend import sync as d3_sync

    _run(_FakeClient())
    pinned = _pin()
    seen = []

    real = d3_sync.update_sync_status

    def _spy(source, count, status="ok", checkpoint=None):
        seen.append((status, checkpoint))
        return real(source, count, status, checkpoint)

    with patch.object(d3_sync, "update_sync_status", _spy):
        _run(_FakeClient(version={"unrelated": "x"}))

    assert seen[0] == ("in_progress", pinned), f"in_progress write dropped the pin: {seen[0]}"


# --- upstream-controlled budget and input ----------------------------------


def test_sync_d3fend_refuses_oversized_technique_index():
    """Upstream decides how many requests we make — cap it."""
    from d3fend import sync as d3_sync

    _run(_FakeClient())
    pinned = _pin()

    huge = [f"T{1000 + i}" for i in range(d3_sync.MAX_TECHNIQUES + 1)]
    client = _FakeClient(index_ids=huge, version={"ontology_hash_sha256": "9" * 64})
    assert _run(client) == 0
    assert client.technique_calls == []
    assert _status()["status"] == "error"
    assert _pin() == pinned


def test_sync_d3fend_index_cap_is_inclusive():
    """Exactly MAX_TECHNIQUES is allowed; the boundary must not drift."""
    from d3fend import sync as d3_sync

    ids = [f"T{1000 + i}" for i in range(d3_sync.MAX_TECHNIQUES)]
    client = _FakeClient(index_ids=ids, by_technique={})
    _run(client)
    assert client.technique_calls, "the boundary value was refused"


def test_sync_d3fend_rejects_malformed_attack_ids_from_index():
    """Ids reach a URL path — only exactly T#### / T####.### may be fetched."""
    hostile = [
        "T1539",
        "../../version",
        "T1/../admin",
        "T1?x=1",
        "not-an-id",
        "T1055/../../../../admin/flush",  # only the trailing anchor stops this one
        "T1055 ",
        "T1055?callback=http://169.254.169.254/",
        "T1055\n",  # re.match + $ would accept a trailing newline
        "T1055\nX-Injected: 1",
        "T\u0661\u0662\u0663\u0664",  # Arabic-Indic digits: \d would accept these
        "T\uff11\uff12\uff13\uff14",  # full-width digits
    ]
    client = _FakeClient(index_ids=hostile)
    _run(client)
    assert [u.rsplit("/", 1)[-1] for u in client.technique_calls] == ["T1539.json"]


def test_sync_d3fend_rejects_malformed_attack_ids_inside_bindings():
    """Ids in the body reach the DB and customer responses — validate them too."""
    row = _binding(
        _TOKEN_BINDING,
        "Token Binding",
        "Credential Hardening",
        "Harden",
        "Access Token",
        "T1539/../../admin",
        "Steal Web Session Cookie",
        "Credential Access",
    )
    assert _run(_FakeClient(by_technique={"T1539": [row]})) == 0

    from db import get_d3fend_defense

    assert get_d3fend_defense("TokenBinding") is None


def test_sync_d3fend_aborts_after_consecutive_failures():
    """A dead or banning upstream must stop the crawl, not absorb ~700 more requests."""
    from d3fend import sync as d3_sync

    ids = [f"T{2000 + i}" for i in range(d3_sync.MAX_CONSECUTIVE_FAILURES + 25)]
    client = _FakeClient(index_ids=ids, failing=ids)
    assert _run(client) == 0
    assert len(client.technique_calls) == d3_sync.MAX_CONSECUTIVE_FAILURES
    assert _status()["status"] == "error"


def test_sync_d3fend_aborts_on_scattered_failures():
    """Alternating success/failure must not reset its way past the total-failure cap."""
    from d3fend import sync as d3_sync

    ids = [f"T{3000 + i}" for i in range(d3_sync.MAX_FAILED_TECHNIQUES * 2 + 50)]
    client = _FakeClient(index_ids=ids, by_technique={}, failing=ids[::2])
    assert _run(client) == 0
    assert len(client.technique_calls) < len(ids), "scattered failures never aborted the crawl"
    assert _status()["status"] == "error"


def test_sync_d3fend_scattered_failures_do_not_abort_early():
    """The consecutive counter must reset on success, or a healthy crawl dies at 20 stragglers."""
    from d3fend import sync as d3_sync

    ids = [f"T{4000 + i}" for i in range(200)]
    stragglers = ids[::6]  # ~33 failures, never 20 in a row, under the total cap
    assert len(stragglers) < d3_sync.MAX_FAILED_TECHNIQUES
    client = _FakeClient(index_ids=ids, by_technique={}, failing=stragglers)
    _run(client)
    assert len(client.technique_calls) == len(ids), "scattered failures aborted a crawl that should finish"


def _padded_payload(nbytes):
    """A VALID technique response padded past `nbytes`, so only the cap can reject it."""
    payload = {"off_to_def": {"results": {"bindings": SAMPLE_BY_TECHNIQUE["T1539"]}}, "pad": ""}
    body = json.dumps(payload).encode()
    payload["pad"] = "p" * max(0, nbytes - len(body))
    return payload


def test_sync_d3fend_size_cap_counts_cumulative_bytes():
    """Every chunk stays under the cap; only the running TOTAL crosses it.

    The body is valid JSON, so a per-chunk (non-cumulative) counter would let the
    whole response through and the sync would succeed — which is the mutation this pins.
    """
    client = _FakeClient(technique_resp=lambda: _resp(_padded_payload(40_000), headers={}, chunk=1_000))
    assert _run(client, D3FEND_MAX_BYTES=10_000) == 0
    assert _status()["status"] == "error"


def test_sync_d3fend_size_cap_allows_a_body_under_the_cap():
    """Control for the test above: the same shape passes when it fits."""
    client = _FakeClient(technique_resp=lambda: _resp(_padded_payload(2_000), headers={}, chunk=1_000))
    assert _run(client, D3FEND_MAX_BYTES=10_000) > 0
    assert _status()["status"] == "ok"


def test_sync_d3fend_size_cap_accepts_a_body_of_exactly_the_cap():
    """The cap is a maximum, not a strict bound: a body of exactly D3FEND_MAX_BYTES passes, one byte more does not."""
    body = json.dumps({"off_to_def": {"results": {"bindings": SAMPLE_BY_TECHNIQUE["T1539"]}}}).encode()
    body += b" " * (2_000 - len(body))
    undeclared = _FakeClient(technique_resp=lambda: _resp(None, body=body, headers={}, chunk=64))
    assert _run(undeclared, D3FEND_MAX_BYTES=len(body) - 1) == 0, "a body one byte over the cap was read"
    declared = {"content-length": str(len(body))}
    client = _FakeClient(technique_resp=lambda: _resp(None, body=body, headers=declared, chunk=64))
    assert _run(client, D3FEND_MAX_BYTES=len(body)) > 0
    assert _status()["status"] == "ok"


def test_sync_d3fend_rejects_compressed_response():
    """We ask for identity; a body that comes back encoded is refused unread."""
    good = {"off_to_def": {"results": {"bindings": SAMPLE_BY_TECHNIQUE["T1539"]}}}
    client = _FakeClient(technique_resp=lambda: _resp(good, headers={"content-encoding": "gzip"}))
    assert _run(client) == 0, "an encoded body was parsed instead of refused"
    assert _status()["status"] == "error"


def test_sync_d3fend_rejects_oversized_declared_length():
    """An honest Content-Length above the cap is refused before a byte is read."""
    good = {"off_to_def": {"results": {"bindings": SAMPLE_BY_TECHNIQUE["T1539"]}}}
    client = _FakeClient(technique_resp=lambda: _resp(good, headers={"content-length": "999999999"}))
    assert _run(client) == 0, "an oversized declared length was read anyway"
    assert _status()["status"] == "error"


def test_sync_d3fend_non_ascii_content_length_is_not_read_as_a_length():
    """A Content-Length in non-ASCII digits is not read: it must neither fail the fetch nor refuse the body."""
    good = {"off_to_def": {"results": {"bindings": SAMPLE_BY_TECHNIQUE["T1539"]}}}
    for declared in (chr(0xB2), chr(0x0669) * 9):  # superscript two (int() raises), Arabic-Indic 999999999
        client = _FakeClient(technique_resp=lambda d=declared: _resp(good, headers={"content-length": d}))
        assert _run(client, PIN_MAX_AGE=timedelta(seconds=0)) > 0, f"content-length {declared!r} decided the fetch"
        assert len(client.technique_calls) == 3


def test_sync_d3fend_deeply_nested_json_fails_one_technique_not_the_crawl(caplog):
    """Nesting past the decoder's recursion limit is a bad response, not a crash that ends the whole crawl."""
    import logging

    from d3fend import sync as d3_sync

    real_loads = json.loads
    deep_bodies = []

    def loads(data, *args, **kwargs):
        # On 3.12 the C decoder refuses 10 000 nested arrays but not 8 000, and CI runs a newer interpreter:
        # raise the way a deep enough document does, whatever this interpreter's limit is.
        if data.startswith(b"[["):
            deep_bodies.append(len(data))
            raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")
        return real_loads(data, *args, **kwargs)

    class _DeepNesting(_FakeClient):
        def stream(self, method, url, **kwargs):
            if url.endswith("/attack/T1550.001.json"):
                self.calls.append(url)
                return _StreamCtx(_resp(None, body=b"[" * 100_000))
            return super().stream(method, url, **kwargs)

    client = _DeepNesting()
    with caplog.at_level(logging.WARNING, logger="contrastapi"), patch.object(d3_sync.json, "loads", loads):
        assert _run(client) == 0
    assert len(client.technique_calls) == 3, "one deeply nested response ended the crawl"
    assert any("technique fetch failed for T1550.001" in r.getMessage() for r in caplog.records)
    assert deep_bodies == [100_000], "the stand-in decoder never ran, so this interpreter's limit decided the test"


def test_sync_d3fend_non_json_body_fails_one_technique_not_the_crawl(caplog):
    """A maintenance page where JSON should be is one failed technique, logged as invalid JSON."""
    import logging

    class _NonJsonBody(_FakeClient):
        def stream(self, method, url, **kwargs):
            if url.endswith("/attack/T1550.001.json"):
                self.calls.append(url)
                return _StreamCtx(_resp(None, body=b"<html>maintenance</html>"))
            return super().stream(method, url, **kwargs)

    client = _NonJsonBody()
    with caplog.at_level(logging.WARNING, logger="contrastapi"):
        assert _run(client) == 0
    assert len(client.technique_calls) == 3, "one non-JSON response ended the crawl"
    assert any("fetch failed for T1550.001: invalid JSON" in r.getMessage() for r in caplog.records)


# --- untrusted field handling ----------------------------------------------


def test_sync_d3fend_caps_field_lengths():
    """Upstream strings land in the DB and in customer responses — they must be bounded."""
    row = _binding(
        _TOKEN_BINDING,
        "L" * 5000,
        "P" * 5000,
        "Harden",
        "A" * 5000,
        "T1539",
        "O" * 5000,
        "C" * 5000,
    )
    _run(_FakeClient(by_technique={"T1539": [row]}))

    from db import get_d3fend_defense, get_d3fend_defenses_for_attack

    d = get_d3fend_defense("TokenBinding")
    assert len(d["label"]) == 512
    assert len(d["parent_label"]) == 512
    assert len(d["artifact"]) == 512
    m = get_d3fend_defenses_for_attack("T1539")[0]
    assert len(m["attack_label"]) == 512
    assert len(m["attack_tactic"]) == 512


def test_sync_d3fend_caps_uri_length():
    long_uri = "http://d3fend.mitre.org/ontologies/d3fend.owl#" + "U" * 5000
    row = _binding(
        long_uri,
        "Token Binding",
        "Credential Hardening",
        "Harden",
        "Access Token",
        "T1539",
        "Steal Web Session Cookie",
        "Credential Access",
    )
    _run(_FakeClient(by_technique={"T1539": [row]}))

    from db import search_d3fend_defenses

    stored = search_d3fend_defenses(tactic="Harden")[0]
    assert len(stored["defense_id"]) == 512
    assert len(stored["uri"]) == 1024


def test_sync_d3fend_strips_control_chars_from_upstream_fields():
    """Trojan-Source bidi overrides and ANSI must not survive into stored rows."""
    row = _binding(
        _TOKEN_BINDING,
        "\u202eToken Binding",
        "Credential Hardening",
        "Harden",
        "Access\x00Token",
        "T1539",
        "Steal\x1b[2K Cookie",
        "Credential Access",
    )
    _run(_FakeClient(by_technique={"T1539": [row]}))

    from db import get_d3fend_defense, get_d3fend_defenses_for_attack

    d = get_d3fend_defense("TokenBinding")
    assert d["label"] == "Token Binding"
    assert d["artifact"] == "AccessToken"
    assert get_d3fend_defenses_for_attack("T1539")[0]["attack_label"] == "Steal[2K Cookie"


def test_sync_d3fend_lone_surrogate_in_a_field_drops_the_field():
    """A lone surrogate decodes from JSON but sqlite cannot store it: drop that field, not the whole run."""
    row = _binding(
        _TOKEN_BINDING,
        "Token Binding",
        "Credential Hardening",
        "Harden",
        "Access Token",
        "T1539",
        "Steal Web Session Cookie" + chr(0xDC00),
        "Credential Access",
    )
    assert _run(_FakeClient(by_technique={**SAMPLE_BY_TECHNIQUE, "T1539": [row]})) == 4

    from db import get_d3fend_defenses_for_attack

    stored = get_d3fend_defenses_for_attack("T1539")[0]
    assert stored["attack_label"] is None
    assert stored["attack_tactic"] == "Credential Access"


def test_sync_d3fend_lone_surrogate_in_a_required_field_skips_the_binding():
    """A required field sqlite cannot store makes its binding unusable: skip that binding, not the run."""
    row = _binding(
        _TOKEN_BINDING,
        "Token Binding" + chr(0xDC00),
        "Credential Hardening",
        "Harden",
        "Access Token",
        "T1539",
        "Steal Web Session Cookie",
        "Credential Access",
    )
    assert _run(_FakeClient(by_technique={**SAMPLE_BY_TECHNIQUE, "T1539": [row]})) == 3
    assert _status()["status"] == "ok"

    from db import get_d3fend_defenses_for_attack

    assert get_d3fend_defenses_for_attack("T1539") == []


def test_sync_d3fend_keeps_legitimate_non_ascii_upstream_text():
    """Only text sqlite cannot store is dropped; accented and Greek letters must reach the row and the pin."""
    label = "Steal Web Session Cookie " + chr(0xE9) + chr(0x3B2)  # e-acute, beta
    row = _binding(
        _TOKEN_BINDING,
        "Token Binding",
        "Credential Hardening",
        "Harden",
        "Access Token",
        "T1539",
        label,
        "Credential Access",
    )
    client = _FakeClient(
        version={"ontology_hash_sha256": "1.9.0-" + chr(0x3B2)},
        by_technique={**SAMPLE_BY_TECHNIQUE, "T1539": [row]},
    )
    assert _run(client) == 4
    assert _pin().startswith("1.9.0-" + chr(0x3B2) + "|")

    from db import get_d3fend_defenses_for_attack

    assert get_d3fend_defenses_for_attack("T1539")[0]["attack_label"] == label


def test_sync_d3fend_unparseable_defense_uri_skips_the_binding_not_the_run():
    """urlparse raises on some URIs (an unclosed IPv6 bracket); that binding is skipped and the rest are stored."""
    bad = _binding(
        "http://[::1/Foo",
        "Foo",
        "Parent",
        "Harden",
        "Artifact",
        "T1539",
        "Steal Web Session Cookie",
        "Credential Access",
    )
    upstream = {**SAMPLE_BY_TECHNIQUE, "T1539": [bad, *SAMPLE_BY_TECHNIQUE["T1539"]]}
    assert _run(_FakeClient(by_technique=upstream)) == 4, "one unparseable defense URI ended the run"
    assert _status()["status"] == "ok"


def test_sync_d3fend_invalid_tactic_skipped():
    payload = {
        "T1234": [
            _binding(
                "http://d3fend.mitre.org/ontologies/d3fend.owl#BogusDefense",
                "Bogus",
                "Bogus Parent",
                "NotARealTactic",
                "Thing",
                "T1234",
                "Bogus Attack",
                "Bogus Tactic",
            ),
        ],
    }
    assert _run(_FakeClient(by_technique=payload)) == 0

    from db import get_d3fend_defense

    assert get_d3fend_defense("BogusDefense") is None


def test_sync_d3fend_index_order_and_dedup_preserved():
    from d3fend import sync as d3_sync

    index = {
        "@graph": [
            {"d3f:attack-id": "T1059"},
            {"d3f:attack-id": "T1539"},
            {"d3f:attack-id": "T1059"},
            {"d3f:attack-id": "T1550.001", "owl:deprecated": True},
        ]
    }
    assert d3_sync._live_technique_ids(index) == ["T1059", "T1539"]


def test_sync_d3fend_skips_deprecated_techniques():
    client = _FakeClient(deprecated=["T1059"])
    _run(client)
    assert not any(u.endswith("T1059.json") for u in client.technique_calls)

    from db import get_d3fend_defenses_for_attack

    assert get_d3fend_defenses_for_attack("T1059") == []


def test_sync_d3fend_aborts_when_upstream_row_budget_is_exceeded():
    """Upstream could answer every technique with a fresh defence forever — bound the rows."""
    client = _FakeClient()
    assert _run(client, MAX_MAPPING_PAIRS=1) == 0
    assert len(client.technique_calls) < 3, "row budget never stopped the crawl"
    assert _status()["status"] == "error"


def test_sync_d3fend_row_budget_broken_by_the_last_technique_still_blocks_the_pin():
    """With nothing left unfetched, the technique that broke the budget must itself count as failed."""
    client = _FakeClient()
    assert _run(client, MAX_MAPPING_PAIRS=3) == 0, "a crawl over the row budget was pinned"
    assert len(client.technique_calls) == 3
    assert _status()["status"] == "error"
    assert _pin() is None


def test_sync_d3fend_empty_index_reports_the_index_gate(caplog):
    """Two layers catch an empty index; the message must say which one actually fired."""
    import logging

    with caplog.at_level(logging.ERROR, logger="contrastapi"):
        _run(_FakeClient(index_ids=[]))
    assert any("listed no live techniques" in r.getMessage() for r in caplog.records)


# --- pin state: baseline and timestamp ----------------------------------------


def _add_stale_mapping_rows(count):
    """Rows no current crawl produces: an older release, or the retired bulk endpoint."""
    from db import upsert_d3fend_attack_mappings

    upsert_d3fend_attack_mappings(
        [{"defense_id": f"RetiredDefense{i}", "attack_technique_id": "T1003"} for i in range(count)]
    )


def test_sync_d3fend_pin_records_crawled_pair_count():
    """The pin carries what the crawl parsed, so a re-crawl of this release has a baseline of its own kind."""
    from d3fend import sync as d3_sync

    assert _run(_FakeClient()) == 4
    release, crawled_at, mapping_pairs = d3_sync._parse_checkpoint(_pin())
    assert release == ONTOLOGY_HASH
    assert crawled_at is not None
    assert mapping_pairs == 4


def test_sync_d3fend_retain_threshold_follows_last_crawl_not_table_rows():
    """Rows are upserted, never deleted: a threshold on the table total ratchets up for good."""
    _run(_FakeClient())  # pins the release with 4 parsed pairs
    first_pin = _pin()
    _add_stale_mapping_rows(10)  # the table now also holds 10 rows no crawl produces

    recrawl = _FakeClient()  # same release, so the retain ratio applies
    assert _run(recrawl, PIN_MAX_AGE=timedelta(seconds=0)) == 14, "a complete re-crawl was held to the table total"
    assert _status()["status"] == "ok"
    assert _pin() != first_pin and _pin().endswith("|4")


def test_sync_d3fend_first_crawl_ignores_preexisting_table_rows():
    """On a first deploy the table holds the retired bulk endpoint's rows, which are no baseline."""
    _add_stale_mapping_rows(20)

    assert _run(_FakeClient()) == 24, "the first crawl was held to rows from another source"
    assert _status()["status"] == "ok"
    assert _pin().endswith("|4")


def test_sync_d3fend_naive_pin_timestamp_triggers_recrawl():
    """An offset-less stamp must read as not fresh, not raise on every run and lock the source."""
    from db import update_sync_status

    # Relative to now: a fixed date expires past PIN_MAX_AGE and re-crawls whatever the parser does.
    naive_stamp = (datetime.now(UTC) - timedelta(days=1)).replace(tzinfo=None).isoformat()
    update_sync_status("d3fend", 0, "ok", checkpoint=f"{ONTOLOGY_HASH}|{naive_stamp}")

    client = _FakeClient()
    assert _run(client) == 4
    assert len(client.technique_calls) == 3, "an offset-less stamp locked the source instead of re-crawling"
    assert _status()["status"] == "ok"


def test_sync_d3fend_parse_checkpoint_handles_pipes_legacy_and_bad_fields():
    from d3fend import sync as d3_sync

    parse = d3_sync._parse_checkpoint
    stamp = "2026-09-13T10:00:00+00:00"

    release, crawled_at, mapping_pairs = parse(f"a|b|{stamp}|7")  # upstream release value containing '|'
    assert (release, crawled_at.isoformat(), mapping_pairs) == ("a|b", stamp, 7)
    assert parse(f"rel|{stamp}")[2] is None  # two-field pin written before pair counts existed
    assert parse("rel") == ("rel", None, None)  # bare release
    assert parse(None) == (None, None, None)
    assert parse("rel|2026-09-13T10:00:00|7")[1] is None  # offset-less stamp
    assert parse(f"rel|{stamp}|7x")[2] is None  # junk pair count
    assert parse(f"rel|{stamp}|{chr(0x0667)}")[2] is None  # non-ASCII digit, which int() would accept


def test_sync_d3fend_parse_checkpoint_reads_the_pin_back_as_untrusted():
    """The pin is a DB value anything could have written: clean the release, bound the pair count."""
    from d3fend import sync as d3_sync

    parse = d3_sync._parse_checkpoint
    stamp = "2026-09-13T10:00:00+00:00"
    cap = d3_sync.MAX_MAPPING_PAIRS

    assert parse(f"rel|{stamp}|{cap}")[2] == cap
    assert parse(f"rel|{stamp}|{cap + 1}")[2] is None  # more than any crawl of ours pins
    assert parse(f"rel|{stamp}|{'9' * 5000}")[2] is None  # int() raises on a digit string this long
    assert parse("a" + chr(10) + "b" + chr(0x202E) + f"|{stamp}|7")[0] == "ab"  # cleaned like an upstream release
    assert parse("r" + chr(27) + "el") == ("rel", None, None)
    assert parse("r" * 300 + f"|{stamp}|7")[0] == "r" * 128


def test_sync_d3fend_oversized_pin_count_does_not_lock_a_new_release():
    """A pin count too large for the float retain ratio must not fail every run, a new release's included."""
    from db import update_sync_status

    update_sync_status("d3fend", 0, "ok", checkpoint=f"older-release|{datetime.now(UTC).isoformat()}|{'9' * 400}")

    assert _run(_FakeClient()) == 4
    assert _pin().startswith(ONTOLOGY_HASH + "|")


# --- guards pinned by review round 4 ------------------------------------------


def test_sync_d3fend_one_pair_baseline_still_rejects_an_empty_crawl():
    """A one-pair baseline rounds the ratio down to zero; the floor must still refuse a crawl that parsed nothing."""
    from db import update_sync_status

    pin = f"{ONTOLOGY_HASH}|{datetime.now(UTC).isoformat()}|1"
    update_sync_status("d3fend", 0, "ok", checkpoint=pin)

    empty = _FakeClient(by_technique={"T1550.001": [], "T1539": []})  # same release, so the ratio applies
    assert _run(empty, PIN_MAX_AGE=timedelta(seconds=0)) == 0
    assert _status()["status"] == "error"
    assert _pin() == pin


def test_sync_d3fend_unparseable_pin_timestamp_triggers_recrawl():
    """A stamp that is not a date must read as not fresh, not raise on every run and lock the source."""
    from db import update_sync_status

    update_sync_status("d3fend", 0, "ok", checkpoint=f"{ONTOLOGY_HASH}|not-a-date|4")

    assert _run(_FakeClient()) == 4
    assert _status()["status"] == "ok"


def test_sync_d3fend_unparseable_stamp_recrawl_is_still_held_to_the_ratio():
    """A stamp that cannot be read forces the re-crawl; it does not waive the ratio for the same release."""
    from db import update_sync_status

    pin = f"{ONTOLOGY_HASH}|not-a-date|10"
    update_sync_status("d3fend", 0, "ok", checkpoint=pin)

    assert _run(_FakeClient(by_technique=_upstream_with_pairs(8))) == 0
    assert _status()["status"] == "error", "the run took the fresh-pin shortcut instead of re-crawling"
    assert _pin() == pin


def test_sync_d3fend_future_pin_timestamp_triggers_recrawl():
    """A stamp in the future would read as fresh forever and switch PIN_MAX_AGE off; it must re-crawl instead."""
    from db import update_sync_status

    tomorrow = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    for stamp in ("9999-12-31T00:00:00+00:00", tomorrow):  # far future, and a clock stepped back one day
        update_sync_status("d3fend", 0, "ok", checkpoint=f"{ONTOLOGY_HASH}|{stamp}|4")
        client = _FakeClient()
        assert _run(client) == 4
        assert len(client.technique_calls) == 3, f"a future stamp {stamp} kept the pin fresh"


def test_sync_d3fend_byte_cap_stops_reading_the_stream():
    """The wire cap must stop the read; a check after the loop would buffer the whole body first."""
    chunks_read = []

    def counted_resp():
        resp = _resp(_padded_payload(40_000), headers={}, chunk=1_000)
        raw = resp.aiter_raw

        async def counting_aiter_raw():
            async for chunk in raw():
                chunks_read.append(len(chunk))
                yield chunk

        resp.aiter_raw = counting_aiter_raw
        return resp

    assert _run(_FakeClient(technique_resp=counted_resp), D3FEND_MAX_BYTES=10_000) == 0
    assert len(chunks_read) <= 3 * 11, f"read {len(chunks_read)} chunks; the cap stops each response at chunk 11"


def test_sync_d3fend_refuses_every_non_identity_encoding():
    """Refusal is anything-but-identity, not a list of known codecs."""
    good = {"off_to_def": {"results": {"bindings": SAMPLE_BY_TECHNIQUE["T1539"]}}}
    refused = ("zstd", "br", "deflate", "gzip, gzip", "x-gzip", "identity, gzip", "gzip, identity", "GZIP", "x-custom")
    for encoding in refused:
        client = _FakeClient(technique_resp=lambda enc=encoding: _resp(good, headers={"content-encoding": enc}))
        assert _run(client) == 0, f"{encoding!r} was parsed instead of refused"


def test_sync_d3fend_release_recheck_failure_does_not_pin():
    """The post-crawl re-check is what confirms the release; if it cannot be read, the pin must not advance."""
    _run(_FakeClient())
    pinned = _pin()

    class _RecheckDown(_FakeClient):
        def stream(self, method, url, **kwargs):
            if url.endswith("/api/version.json") and self.technique_calls:
                self.calls.append(url)
                return _StreamCtx(_resp(VERSION_OK, ok=False))
            return super().stream(method, url, **kwargs)

    assert _run(_RecheckDown(version={"ontology_hash_sha256": "f" * 64})) == 0
    assert _status()["status"] == "error"
    assert _pin() == pinned


def test_sync_d3fend_release_recheck_without_a_marker_does_not_pin(caplog):
    """A re-check that answers but names no release confirms nothing, exactly like one that fails."""
    import logging

    _run(_FakeClient())
    pinned = _pin()

    class _RecheckBlank(_FakeClient):
        def stream(self, method, url, **kwargs):
            if url.endswith("/api/version.json") and self.technique_calls:
                self.calls.append(url)
                return _StreamCtx(_resp({"unrelated": "x"}))
            return super().stream(method, url, **kwargs)

    with caplog.at_level(logging.ERROR, logger="contrastapi"):
        assert _run(_RecheckBlank(version={"ontology_hash_sha256": "f" * 64})) == 0
    assert _status()["status"] == "error"
    assert _pin() == pinned
    assert any("re-check did not confirm the crawled release" in r.getMessage() for r in caplog.records)


def test_sync_d3fend_fail_survives_a_status_write_error():
    """`_fail` runs on the error path; if its own status write raises, the sync must still return 0, not raise."""
    from d3fend import sync as d3_sync

    real_update = d3_sync.update_sync_status

    def error_write_raises(source, count, status="ok", checkpoint=None):
        if status == "error":
            raise RuntimeError("database is locked")
        return real_update(source, count, status, checkpoint)

    with patch.object(d3_sync, "update_sync_status", error_write_raises):
        assert _run(_FakeClient(version={"unrelated": "x"})) == 0


def test_sync_d3fend_release_key_is_stripped_and_capped():
    """The release key comes from upstream and reaches the pin and log lines: control chars out, length capped."""
    # ESC, newline, NUL, right-to-left override, carriage return, tab, DEL, left-to-right isolate and override.
    # Planted mid-value, where strip() cannot reach them.
    controls = (chr(27), chr(10), chr(0), chr(0x202E), chr(13), chr(9), chr(127), chr(0x2066), chr(0x202D))
    hostile = "v" + "".join(controls) + "1" + "a" * 300
    assert _run(_FakeClient(version={"ontology_hash_sha256": hostile})) == 4
    assert _pin().rsplit("|", 2)[0] == "v1" + "a" * 126


# --- pin policy: new release vs re-crawl of the pinned release ----------------


def _upstream_with_pairs(count):
    """Technique files that parse to exactly `count` distinct pairs, one per technique."""
    by_technique = {}
    for i in range(count):
        attack_id = f"T{1100 + i}"
        defense_uri = f"http://d3fend.mitre.org/ontologies/d3fend.owl#Defense{i}"
        by_technique[attack_id] = [
            _binding(defense_uri, f"Defense {i}", "Parent", "Harden", "Artifact", attack_id, "Label", "Tactic")
        ]
    return by_technique


def test_sync_d3fend_new_release_with_far_fewer_mappings_is_pinned(caplog):
    """A new release has no retain ratio: rows are never deleted, so a smaller release removes nothing."""
    import logging

    _run(_FakeClient())

    only_one = {"T1550.001": [], "T1539": SAMPLE_BY_TECHNIQUE["T1539"], "T1059": []}
    shrunk = _FakeClient(version={"ontology_hash_sha256": "f" * 64}, by_technique=only_one)
    with caplog.at_level(logging.WARNING, logger="contrastapi"):
        assert _run(shrunk) == 4, "a complete crawl of a new release was held to the pinned release's count"
    assert _status()["status"] == "ok"
    assert _pin().startswith("f" * 64 + "|")
    assert _pin().endswith("|1")
    drops = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "below the retain ratio of the pinned release" in r.getMessage()
    ]
    assert drops, "the drop was pinned silently"
    assert drops[0].startswith("D3FEND release " + "f" * 12 + " parsed 1 pairs"), drops[0]
    assert "pinned release " + ONTOLOGY_HASH[:12] + " (4)" in drops[0], drops[0]


def test_sync_d3fend_no_drop_warning_when_the_recheck_fails(caplog):
    """The drop warning announces a pin; a crawl whose release re-check fails pins nothing and must not raise it."""
    import logging

    _run(_FakeClient())

    class _RecheckDown(_FakeClient):
        def stream(self, method, url, **kwargs):
            if url.endswith("/api/version.json") and self.technique_calls:
                self.calls.append(url)
                return _StreamCtx(_resp(VERSION_OK, ok=False))
            return super().stream(method, url, **kwargs)

    only_one = {"T1550.001": [], "T1539": SAMPLE_BY_TECHNIQUE["T1539"], "T1059": []}
    down = _RecheckDown(version={"ontology_hash_sha256": "f" * 64}, by_technique=only_one)
    with caplog.at_level(logging.WARNING, logger="contrastapi"):
        assert _run(down) == 0
    assert not [r for r in caplog.records if "below the retain ratio" in r.getMessage()]


def test_sync_d3fend_new_release_within_retain_ratio_pins_without_a_warning(caplog):
    """The drop warning measures the pinned crawl, not the table: a new release of similar size must not raise it."""
    import logging

    from db import update_sync_status

    _add_stale_mapping_rows(20)
    update_sync_status("d3fend", 0, "ok", checkpoint=f"older-release|{datetime.now(UTC).isoformat()}|10")

    with caplog.at_level(logging.WARNING, logger="contrastapi"):
        assert _run(_FakeClient(by_technique=_upstream_with_pairs(9))) == 20 + 9
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_sync_d3fend_recrawl_within_retain_ratio_advances_the_pin():
    """A re-crawl of the pinned release may lose a little: 9 of a pinned 10 is inside a 0.9 ratio."""
    from db import update_sync_status

    update_sync_status("d3fend", 0, "ok", checkpoint=f"{ONTOLOGY_HASH}|{datetime.now(UTC).isoformat()}|10")

    assert _run(_FakeClient(by_technique=_upstream_with_pairs(9)), PIN_MAX_AGE=timedelta(seconds=0)) == 9
    assert _status()["status"] == "ok"
    assert _pin().endswith("|9")


def test_sync_d3fend_recrawl_below_retain_ratio_keeps_the_old_pin(caplog):
    """Same release, same content: 8 of a pinned 10 is below a 0.9 ratio, so the crawl did not succeed."""
    import logging

    from db import update_sync_status

    pin = f"{ONTOLOGY_HASH}|{datetime.now(UTC).isoformat()}|10"
    update_sync_status("d3fend", 0, "ok", checkpoint=pin)

    with caplog.at_level(logging.WARNING, logger="contrastapi"):
        assert _run(_FakeClient(by_technique=_upstream_with_pairs(8)), PIN_MAX_AGE=timedelta(seconds=0)) == 0
    assert _status()["status"] == "error"
    assert _pin() == pin
    messages = [r.getMessage() for r in caplog.records]
    assert any("8 mappings parsed (needed 9)" in m for m in messages), "the failure line lost its counts"
    assert not any("below the retain ratio" in m for m in messages), "a crawl that pinned nothing warned of a pin"


@pytest.mark.parametrize("read_error", [RuntimeError, sqlite3.OperationalError])
def test_sync_d3fend_pin_read_failure_keeps_the_pin(caplog, read_error):
    """With no pin read there is none to carry: any status write would store None over the pin and its count."""
    import logging

    from d3fend import sync as d3_sync

    _run(_FakeClient())
    before = _status()

    unreadable = patch.object(d3_sync, "get_sync_checkpoint", side_effect=read_error("database is locked"))
    with caplog.at_level(logging.ERROR, logger="contrastapi"), unreadable:
        assert _run(_FakeClient(version={"ontology_hash_sha256": "a" * 64})) == 0
    assert _status() == before, "a status write happened after the pin read failed"
    assert any("could not read its release pin" in r.getMessage() for r in caplog.records)
