"""MITRE D3FEND sync engine — fetches attack↔defense mappings per ATT&CK technique.

Source: https://d3fend.mitre.org/api/offensive-technique/attack/{ATTACK_ID}.json
Format: SPARQL query result under ``off_to_def`` (head.vars + results.bindings).
Each binding row = one (attack ATT&CK T-code) ↔ (D3FEND defense) pair.

D3FEND 1.6.0 (released 2026-08-31) removed the pre-joined bulk endpoint
``/api/ontology/inference/d3fend-full-mappings.json``; mappings are now served one
technique at a time. A full crawl is ~700 requests, so it runs only when
``/api/version.json`` reports a release we have not ingested yet — the steady-state
sync is a single request. Idempotent.

Upstream is untrusted: it chooses how many requests we make, how many bytes we
read and what we store. Hence the belt here — identity-only transfer with a cap on
*wire* bytes, an id pattern that is checked before anything reaches a URL, whole-crawl
byte/time/row budgets, and a release pin that advances only after a crawl with no failures
(a re-crawl of the pinned release must also keep close to its count). The pin also expires, so an upstream
that keeps replaying one release cannot use the version gate as a switch to freeze our data indefinitely.
"""

import asyncio
import json
import logging
import re
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import httpx
from db import (
    get_cve_db,
    get_sync_checkpoint,
    update_sync_status,
    upsert_d3fend_attack_mappings,
    upsert_d3fend_defense,
)
from domain.recon import _strip_control_chars

log = logging.getLogger("contrastapi")

D3FEND_BASE = "https://d3fend.mitre.org"
D3FEND_VERSION_URL = f"{D3FEND_BASE}/api/version.json"
D3FEND_INDEX_URL = f"{D3FEND_BASE}/api/offensive-technique/all.json"
D3FEND_TECHNIQUE_URL = D3FEND_BASE + "/api/offensive-technique/attack/{attack_id}.json"

D3FEND_MAX_BYTES = 8 * 1024 * 1024  # per response, counted on the wire (largest live ~0.6 MB)
HTTP_TIMEOUT = 30
USER_AGENT = "ContrastAPI/1.0 (api.contrastcyber.com)"
ATTACK_MAPPING_CHUNK = 2000
CRAWL_DELAY_SECONDS = 0.2  # polite pacing: ~700 sequential requests per release

MAX_TECHNIQUES = 2000  # upstream lists ~700; refuse an index that would blow the budget
MAX_CONSECUTIVE_FAILURES = 20  # upstream is down or banning us — stop, do not keep hammering
MAX_FAILED_TECHNIQUES = 100  # scattered failures never reset their way past the abort
MAX_MAPPING_PAIRS = 100_000  # live set is ~4k
MAX_DEFENSES = 5_000  # live set is ~500
MAX_CRAWL_BYTES = 256 * 1024 * 1024  # whole crawl, not per response
MAX_CRAWL_SECONDS = 900  # systemd gives the sync unit 30 min for every source together
MIN_RETAIN_RATIO = 0.9  # a re-crawl of the pinned release parsing far less than that crawl did not succeed
PIN_MAX_AGE = timedelta(days=30)  # re-verify even when upstream claims nothing changed

FIELD_MAX = 512
URI_MAX = 1024

# Upstream ATT&CK ids, e.g. 'T1055' or 'T1055.014'. Explicit 0-9 (not \d, which accepts
# other Unicode digit scripts) and fullmatch (not match, whose $ tolerates a trailing
# newline) — both bypasses put attacker text straight into a URL path and a log line.
ATTACK_ID_RE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")

VALID_TACTICS = {"Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"}

_client = httpx.AsyncClient(
    timeout=httpx.Timeout(HTTP_TIMEOUT, connect=10.0),
    headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        # Identity only: a compressed body is expanded by httpx before any size check
        # could see it, so a small chained-encoding payload can become gigabytes.
        "Accept-Encoding": "identity",
    },
    follow_redirects=False,  # upstream must not be able to aim these ~700 GETs elsewhere
)


class _D3fendFetchError(RuntimeError):
    """Upstream returned a response we refuse to parse."""


class _D3fendAbort(RuntimeError):
    """A whole-crawl budget was exhausted; stop, do not treat as one bad technique."""


# "This one request did not work": a transport or HTTP error, or a response we refuse. httpx.InvalidURL
# is NOT an httpx.HTTPError, so a bad id would otherwise kill the whole crawl. ValueError is a net for
# upstream values httpx rejects without wrapping: it builds the request for a redirect even with redirects
# off, and a relative Location urljoin cannot parse, or a non-ASCII IPv6 zone id, raises one there. Its
# cost: a bug of ours raising one inside a fetch reads as a failed technique, which still keeps the pin.
_FETCH_ERRORS = (httpx.HTTPError, httpx.InvalidURL, ValueError, _D3fendFetchError)


class _CrawlBudget:
    """Whole-crawl byte and wall-clock ceiling, independent of the per-response cap."""

    def __init__(self, max_bytes: int = MAX_CRAWL_BYTES, max_seconds: float = MAX_CRAWL_SECONDS):
        self.max_bytes = max_bytes
        self.used_bytes = 0
        self.deadline = time.monotonic() + max_seconds

    def spend(self, count: int) -> None:
        self.used_bytes += count
        if self.used_bytes > self.max_bytes:
            raise _D3fendAbort(f"crawl byte budget exhausted ({self.used_bytes} > {self.max_bytes})")

    def check_clock(self) -> None:
        if time.monotonic() > self.deadline:
            raise _D3fendAbort("crawl wall-clock deadline exceeded")


def _safe_detail(exc: Exception) -> str:
    """Exception text fit for a log line: control chars stripped, length capped."""
    return _strip_control_chars(str(exc))[:200]


def _slug_from_uri(uri: str | None) -> str | None:
    """Extract the fragment after '#' from a D3FEND ontology URI.

    'http://d3fend.mitre.org/ontologies/d3fend.owl#TokenBinding' -> 'TokenBinding'
    """
    if not isinstance(uri, str) or not uri:
        return None
    if "#" in uri:
        return uri.rsplit("#", 1)[1]
    try:
        parsed = urlparse(uri)
    except ValueError:  # e.g. an unclosed IPv6 bracket; one bad binding must not end the run
        return None
    if parsed.path:
        tail = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        return tail or None
    return None


def _utf8_encodable(value: str) -> bool:
    """False for a string holding a lone surrogate: JSON can decode one, sqlite cannot store it."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _binding_value(binding: dict, key: str) -> str | None:
    """Extract `value` field from a SPARQL JSON binding cell. None on missing, non-string or unstorable.

    Applies `_strip_control_chars` to defend against Trojan-Source bidi/RTL
    injection in upstream MITRE D3FEND fields. A value sqlite cannot store (a lone
    surrogate) is dropped like a missing one; kept, it makes the row write raise and fails the run.
    """
    cell = binding.get(key)
    if isinstance(cell, dict):
        v = cell.get("value")
        if isinstance(v, str) and _utf8_encodable(v):
            return _strip_control_chars(v)
    return None


def _capped(value: str | None, limit: int = FIELD_MAX) -> str | None:
    """Length-cap an upstream string; these land in the DB and in customer responses."""
    if value is None:
        return None
    return value[:limit]


async def _fetch_json(url: str, budget: _CrawlBudget | None = None) -> dict:
    """GET a D3FEND JSON document, capped on *wire* bytes as they stream in.

    Counting decoded bytes would be too late: httpx expands a compressed body before
    handing it over, and a chained Content-Encoding turns kilobytes into gigabytes in
    a single chunk. So we ask for identity, refuse anything else, and read raw.
    """
    chunks: list[bytes] = []
    total = 0
    async with _client.stream("GET", url) as resp:
        resp.raise_for_status()
        encoding = resp.headers.get("content-encoding", "").strip().lower()
        if encoding and encoding != "identity":
            raise _D3fendFetchError(f"refusing content-encoding {encoding[:40]!r}")
        declared = resp.headers.get("content-length", "")
        # ASCII digits only, as in _parse_checkpoint: isdigit() also passes a superscript digit (int() raises)
        # and other scripts' digits (int() reads them). A length we do not read cannot refuse the body; the
        # wire count below still caps it.
        if declared.isascii() and declared.isdigit() and int(declared) > D3FEND_MAX_BYTES:
            raise _D3fendFetchError(f"declared length {declared} exceeds {D3FEND_MAX_BYTES} bytes")
        async for chunk in resp.aiter_raw():
            total += len(chunk)
            if total > D3FEND_MAX_BYTES:
                raise _D3fendFetchError(f"response exceeds {D3FEND_MAX_BYTES} bytes")
            chunks.append(chunk)
    if budget is not None:
        budget.spend(total)
    try:
        data = json.loads(b"".join(chunks))
    except (ValueError, RecursionError) as e:  # nesting deep enough exhausts the decoder's recursion limit
        raise _D3fendFetchError(f"invalid JSON: {_safe_detail(e)}") from e
    if not isinstance(data, dict):
        raise _D3fendFetchError("payload is not a JSON object")
    return data


def _clean_release(value: str) -> str:
    """The one cleaning a release value gets, whether it arrives from upstream or back out of a stored pin.

    Control characters are removed before trimming, so whitespace they hid is trimmed too. Cleaning a clean
    value changes nothing, which is what lets a pin this sync wrote read back equal to the release it pinned.
    """
    return _strip_control_chars(value).strip()[:128].rstrip()


def _release_key(version: dict) -> str | None:
    """Pin value identifying the upstream release.

    Falls back to the next field when one moves, cleans to nothing, or holds a value sqlite cannot store.
    """
    for key in ("ontology_hash_sha256", "ontology_version", "version"):
        value = version.get(key)
        if isinstance(value, str) and _utf8_encodable(value):
            cleaned = _clean_release(value)
            if cleaned:
                return cleaned
    return None


def _format_checkpoint(release: str, crawled_at: datetime, mapping_pairs: int) -> str:
    return f"{release}|{crawled_at.isoformat()}|{mapping_pairs}"


def _parse_checkpoint(raw: str | None) -> tuple[str | None, datetime | None, int | None]:
    """Split a stored pin into (release, last full crawl, mapping pairs that crawl parsed).

    Fields are read from the right, so in a current pin a release value that itself contains
    '|' survives. A missing, unparseable, offset-less or future timestamp comes back as None, which
    the gate treats as not fresh and answers with a re-crawl: subtracting an offset-less value from
    an aware now() would raise on every run and lock the source, and a future one would read as fresh
    forever and switch PIN_MAX_AGE off. After the clock steps back, every run re-crawls until one of
    those crawls pins or the clock passes the stamp. Two-field pins written before pair counts
    existed, and bare releases, carry no pair count.
    The pin is read back as untrusted as upstream: the release gets the same cleaning, and a pair
    count above MAX_MAPPING_PAIRS is no baseline, since no crawl of ours pins more. Its length is
    checked before int(), which raises on a long enough digit string; a huge count would also
    overflow the float retain ratio and fail every run, a new release's included.
    """
    if not raw:
        return None, None, None
    parts = raw.rsplit("|", 2)
    if len(parts) == 1:
        return _clean_release(raw), None, None
    release, stamp = _clean_release(parts[0]), parts[1]
    pairs_text = parts[2] if len(parts) == 3 else ""
    try:
        crawled_at = datetime.fromisoformat(stamp)
    except ValueError:
        crawled_at = None
    if crawled_at is not None and (crawled_at.tzinfo is None or crawled_at > datetime.now(UTC)):
        crawled_at = None
    mapping_pairs = None
    if pairs_text.isascii() and pairs_text.isdigit() and len(pairs_text) <= len(str(MAX_MAPPING_PAIRS)):
        mapping_pairs = int(pairs_text)
        if mapping_pairs > MAX_MAPPING_PAIRS:
            mapping_pairs = None
    return release, crawled_at, mapping_pairs


def _bindings_of(payload: dict) -> list:
    """Pull ``off_to_def.results.bindings`` out, rejecting every wrong shape loudly."""
    off_to_def = payload.get("off_to_def")
    if not isinstance(off_to_def, dict):
        raise _D3fendFetchError("off_to_def is not an object")
    results = off_to_def.get("results")
    if not isinstance(results, dict):
        raise _D3fendFetchError("results is not an object")
    bindings = results.get("bindings")
    if not isinstance(bindings, list):
        raise _D3fendFetchError("bindings is not a list")
    return bindings


def _live_technique_ids(index: dict) -> list[str]:
    """ATT&CK ids from the technique index: deprecated dropped, malformed dropped, order kept."""
    out: list[str] = []
    seen: set[str] = set()
    rejected = 0
    for entry in index.get("@graph") or []:
        if not isinstance(entry, dict) or entry.get("owl:deprecated"):
            continue
        attack_id = entry.get("d3f:attack-id")
        if isinstance(attack_id, list):
            attack_id = attack_id[0] if attack_id else None
        if not isinstance(attack_id, str) or not ATTACK_ID_RE.fullmatch(attack_id):
            rejected += 1
            continue
        if attack_id not in seen:
            seen.add(attack_id)
            out.append(attack_id)
    if rejected:
        log.warning("D3FEND index: %d entries rejected as malformed attack ids", rejected)
    return out


def _ingest_bindings(
    bindings: list,
    defenses_seen: dict[str, dict],
    mapping_keys: set[tuple[str, str]],
    mapping_batch: list[dict],
) -> None:
    """Fold one technique's SPARQL bindings into the accumulating defense/mapping sets."""
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
        # The body carries ids too, and they reach the DB and customer responses.
        if not ATTACK_ID_RE.fullmatch(attack_id):
            continue
        defense_id = _slug_from_uri(def_uri)
        if not defense_id:
            continue
        defense_id = defense_id[:FIELD_MAX]

        if defense_id not in defenses_seen:
            defenses_seen[defense_id] = {
                "label": _capped(def_label),
                "uri": _capped(def_uri, URI_MAX),
                # 1.6.0 renamed top_def_tech_label -> def_tech_parent_label
                "parent_label": _capped(
                    _binding_value(b, "def_tech_parent_label") or _binding_value(b, "top_def_tech_label")
                ),
                "tactic": def_tactic,
                "artifact": _capped(_binding_value(b, "def_artifact_label")),
            }

        mkey = (defense_id, attack_id)
        if mkey in mapping_keys:
            continue
        mapping_keys.add(mkey)
        mapping_batch.append(
            {
                "defense_id": defense_id,
                "attack_technique_id": attack_id,
                "attack_label": _capped(_binding_value(b, "off_tech_label")),
                "attack_tactic": _capped(_binding_value(b, "off_tactic_label")),
            }
        )


def _stored_mapping_count() -> int:
    with get_cve_db() as con:
        return int(con.execute("SELECT COUNT(*) FROM d3fend_attack_mappings").fetchone()[0])


def _fail(previous_checkpoint: str | None, message: str, *args) -> int:
    """Record a loud, non-advancing failure: status=error with the old pin intact."""
    log.error(message, *args)
    try:
        update_sync_status("d3fend", _stored_mapping_count(), "error", checkpoint=previous_checkpoint)
    except Exception as e:  # the failure handler must not become the failure
        log.error("D3FEND could not record failure status: %s", type(e).__name__)
    return 0


async def _crawl(attack_ids: list[str]) -> tuple[dict[str, dict], set[tuple[str, str]], int]:
    """Fetch every technique. Returns (defenses, mapping keys, failed count)."""
    defenses_seen: dict[str, dict] = {}
    mapping_batch: list[dict] = []
    mapping_keys: set[tuple[str, str]] = set()
    budget = _CrawlBudget()
    failed = 0
    consecutive = 0

    for i, attack_id in enumerate(attack_ids):
        if i and CRAWL_DELAY_SECONDS:
            await asyncio.sleep(CRAWL_DELAY_SECONDS)
        try:
            budget.check_clock()
            payload = await _fetch_json(D3FEND_TECHNIQUE_URL.format(attack_id=attack_id), budget)
            bindings = _bindings_of(payload)
        except _D3fendAbort as e:
            failed += len(attack_ids) - i
            log.error("D3FEND crawl aborted: %s", _safe_detail(e))
            break
        except _FETCH_ERRORS as e:
            failed += 1
            consecutive += 1
            log.warning("D3FEND technique fetch failed for %s: %s", attack_id, _safe_detail(e))
            if consecutive >= MAX_CONSECUTIVE_FAILURES or failed >= MAX_FAILED_TECHNIQUES:
                failed += len(attack_ids) - i - 1
                log.error("D3FEND crawl aborted after %d failures (%d consecutive)", failed, consecutive)
                break
            continue

        consecutive = 0
        _ingest_bindings(bindings, defenses_seen, mapping_keys, mapping_batch)
        if len(mapping_keys) > MAX_MAPPING_PAIRS or len(defenses_seen) > MAX_DEFENSES:
            # The technique that broke the budget counts as failed too, not only the ones never fetched:
            # otherwise a budget broken by the last technique would leave failed at 0 and let the pin advance.
            failed += len(attack_ids) - i
            log.error(
                "D3FEND crawl aborted: upstream row budget exceeded (%d pairs, %d defenses)",
                len(mapping_keys),
                len(defenses_seen),
            )
            break
        if len(mapping_batch) >= ATTACK_MAPPING_CHUNK:
            upsert_d3fend_attack_mappings(mapping_batch)
            mapping_batch = []

    if mapping_batch:
        upsert_d3fend_attack_mappings(mapping_batch)
    return defenses_seen, mapping_keys, failed


async def sync_d3fend() -> int:
    """Sync D3FEND defense catalog and attack mappings.

    Returns the number of stored mapping rows, or 0 on any failure path.
    """
    log.info("D3FEND sync starting...")
    # Read the pin BEFORE any status write — update_sync_status rewrites the whole row,
    # so every later write has to carry the checkpoint forward explicitly. If the read
    # itself fails there is no checkpoint to carry: any write, _fail's included, would
    # store None over the pin and its pair count, so nothing is written.
    try:
        previous_checkpoint = get_sync_checkpoint("d3fend")
    except Exception as e:
        log.error(
            "D3FEND sync failed: could not read its release pin, status not written: %s: %s",
            type(e).__name__,
            _safe_detail(e),
        )
        return 0
    try:
        previous_stored = _stored_mapping_count()
        update_sync_status("d3fend", previous_stored, "in_progress", checkpoint=previous_checkpoint)

        try:
            version = await _fetch_json(D3FEND_VERSION_URL)
        except _FETCH_ERRORS as e:
            return _fail(previous_checkpoint, "D3FEND version probe failed: %s", _safe_detail(e))

        release = _release_key(version)
        if not release:
            # Without a release marker we cannot tell "unchanged" from "changed", and
            # crawling ~700 URLs every cycle to find out is the worse failure.
            return _fail(previous_checkpoint, "D3FEND version.json carries no release marker")

        previous_release, previous_crawl, previous_pairs = _parse_checkpoint(previous_checkpoint)
        pin_fresh = previous_crawl is not None and datetime.now(UTC) - previous_crawl < PIN_MAX_AGE
        if release == previous_release and pin_fresh:
            update_sync_status("d3fend", previous_stored, "ok", checkpoint=previous_checkpoint)
            log.info(
                "D3FEND sync complete: release %s unchanged, %d mappings retained (0 techniques fetched)",
                release[:12],
                previous_stored,
            )
            return previous_stored

        try:
            index = await _fetch_json(D3FEND_INDEX_URL)
        except _FETCH_ERRORS as e:
            return _fail(previous_checkpoint, "D3FEND technique index fetch failed: %s", _safe_detail(e))

        attack_ids = _live_technique_ids(index)
        if not attack_ids:
            return _fail(previous_checkpoint, "D3FEND technique index listed no live techniques")
        if len(attack_ids) > MAX_TECHNIQUES:
            return _fail(
                previous_checkpoint,
                "D3FEND technique index listed %d techniques, above the %d cap — refusing",
                len(attack_ids),
                MAX_TECHNIQUES,
            )

        log.info("D3FEND crawling %d live techniques for release %s", len(attack_ids), release[:12])
        defenses_seen, mapping_keys, failed = await _crawl(attack_ids)

        defense_errors = 0
        for def_id, fields in defenses_seen.items():
            try:
                upsert_d3fend_defense(
                    def_id,
                    label=fields["label"],
                    uri=fields["uri"],
                    parent_label=(fields["parent_label"] or None),
                    description=None,
                    tactic=fields["tactic"],
                    artifact=fields["artifact"],
                )
            except Exception as e:
                defense_errors += 1
                log.warning("D3FEND defense upsert failed for %s: %s", def_id, type(e).__name__)

        # Advance the release pin ONLY after a crawl that lost nothing: no failed technique and no
        # failed defense write. Pinning a crawl we know is partial would mark missing data as current
        # until the next release or PIN_MAX_AGE — a silent freeze.
        # A re-crawl of the PINNED release (pin expired, or its stamp unreadable) must also keep close
        # to what that crawl parsed: same release, same content, so a large drop means this crawl did
        # not succeed. A NEW release has no ratio. Rows are only ever upserted, so a smaller release
        # removes nothing customers see and at worst delays new mappings until PIN_MAX_AGE forces a
        # re-crawl, while a ratio against any earlier count (the table total, or one inflated crawl)
        # can lock a legitimately smaller release out for good. No pinned count means no baseline.
        # A new release below the retain threshold still pins, but with a warning, so the drop stays visible.
        retain_threshold = max(1, int(previous_pairs * MIN_RETAIN_RATIO)) if previous_pairs else 1
        required = retain_threshold if release == previous_release else 1
        if failed or defense_errors or len(mapping_keys) < required:
            return _fail(
                previous_checkpoint,
                "D3FEND crawl incomplete: %d/%d techniques failed, %d defense writes failed, "
                "%d mappings parsed (needed %d) — release pin not advanced",
                failed,
                len(attack_ids),
                defense_errors,
                len(mapping_keys),
                required,
            )

        # The technique files sit behind a CDN and the release could have rolled mid-crawl;
        # pinning a release we did not actually finish reading would freeze us on a mix.
        try:
            confirmed = _release_key(await _fetch_json(D3FEND_VERSION_URL))
        except _FETCH_ERRORS as e:
            return _fail(previous_checkpoint, "D3FEND release re-check failed: %s", _safe_detail(e))
        if confirmed != release:
            return _fail(previous_checkpoint, "D3FEND re-check did not confirm the crawled release — pin not advanced")

        if len(mapping_keys) < retain_threshold:
            log.warning(
                "D3FEND release %s parsed %d pairs, below the retain ratio of the pinned release %s (%d) — "
                "pinning it anyway: a new release carries no retain ratio",
                release[:12],
                len(mapping_keys),
                (previous_release or "")[:12],
                previous_pairs,
            )
        stored = _stored_mapping_count()
        update_sync_status(
            "d3fend", stored, "ok", checkpoint=_format_checkpoint(release, datetime.now(UTC), len(mapping_keys))
        )
        log.info(
            "D3FEND sync complete: %d defenses, %d distinct mappings (%d pairs across %d techniques)",
            len(defenses_seen),
            stored,
            len(mapping_keys),
            len(attack_ids),
        )
        return stored
    except Exception as e:
        # Nothing may escape: an uncaught error would leave sync_status pinned at
        # 'in_progress', which every freshness detector reads as neither ok nor error.
        return _fail(previous_checkpoint, "D3FEND sync failed: %s: %s", type(e).__name__, _safe_detail(e))
