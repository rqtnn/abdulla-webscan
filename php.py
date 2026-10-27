#!/usr/bin/env python3
"""
php2shell-exposure — single-file exposure assessment toolkit.

Scope: authorized targets only (owns / contract / bug bounty in-scope / lab).
No remote RCE, no payloads, no shells, no heap grooming, no internet-wide scan.

Dependencies (standard library only for the core; optional for richer probes):
    pip install httpx dnspython

Usage:
    python php2shell_exposure.py \
        --targets targets.txt \
        --i-own-this mylab.example.com \
        --out results/

    python php2shell_exposure.py \
        --targets targets.txt \
        --auth-file auth.json \
        --bounty-hosts bounty.txt \
        --out results/

    python php2shell_exposure.py --self-test
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import datetime as dt
import hashlib
import io
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

# ----------------------------------------------------------------------------
# Optional dependency handling — degrade gracefully, never crash on import.
# ----------------------------------------------------------------------------

try:
    import httpx  # type: ignore
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

try:
    import dns.resolver  # type: ignore
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False


TOOL_NAME = "php2shell-exposure"
TOOL_VERSION = "1.2.0"

FIXED_UPSTREAM = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

ADVISORY_URL = "https://www.php.net/archive/2026.php"

PHP_VERSION_RE = re.compile(
    r"\bPHP[/ ](\d+\.\d+\.\d+(?:[-+~][A-Za-z0-9.+~_-]+)?)", re.IGNORECASE
)

ASAN_PATTERNS = {
    "heap-use-after-free": re.compile(r"ERROR: AddressSanitizer: heap-use-after-free"),
    "heap-buffer-overflow": re.compile(r"ERROR: AddressSanitizer: heap-buffer-overflow"),
    "stack-buffer-overflow": re.compile(r"ERROR: AddressSanitizer: stack-buffer-overflow"),
    "global-buffer-overflow": re.compile(r"ERROR: AddressSanitizer: global-buffer-overflow"),
    "double-free": re.compile(r"ERROR: AddressSanitizer: attempting double-free"),
    "SEGV": re.compile(r"ERROR: AddressSanitizer: SEGV"),
}

OOM_ANOMALY_RE = re.compile(r"&array\(\d+\)")
RECURSION_RE = re.compile(r"\*RECURSION\*")


# ----------------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------------


class ScopeError(ValueError):
    pass


class AuthorizationError(PermissionError):
    pass


# ----------------------------------------------------------------------------
# Authorization
# ----------------------------------------------------------------------------


AuthMode = Literal["owns", "contract", "bugbounty", "lab"]


@dataclass(frozen=True)
class AuthorizationRecord:
    mode: AuthMode
    target_host: str
    signed_by: str
    signed_at_utc: str
    expires_at_utc: str
    reference: str = ""
    scope_notes: str = ""
    signature_sha256: str = ""

    def is_valid(self) -> tuple[bool, str]:
        try:
            expires = dt.datetime.fromisoformat(self.expires_at_utc.replace("Z", "+00:00"))
        except ValueError:
            return False, f"unparseable expires_at_utc: {self.expires_at_utc}"
        if dt.datetime.now(dt.timezone.utc) > expires:
            return False, f"authorization expired at {self.expires_at_utc}"
        if self.mode == "bugbounty" and not self.reference.startswith("http"):
            return False, "bugbounty mode requires policy URL in reference"
        if self.mode == "contract" and not self.reference:
            return False, "contract mode requires contract reference"
        return True, "ok"


def _record_signature(rec: AuthorizationRecord) -> str:
    payload = "|".join([
        rec.mode, rec.target_host, rec.signed_by,
        rec.signed_at_utc, rec.expires_at_utc, rec.reference,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_authorization_file(path: Path) -> dict[str, AuthorizationRecord]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, AuthorizationRecord] = {}
    for entry in raw.get("records", []):
        rec = AuthorizationRecord(**entry)
        expected = _record_signature(rec)
        if rec.signature_sha256 and rec.signature_sha256 != expected:
            raise AuthorizationError(
                f"signature mismatch for {rec.target_host}: "
                f"expected {expected}, got {rec.signature_sha256}"
            )
        ok, msg = rec.is_valid()
        if not ok:
            raise AuthorizationError(f"{rec.target_host}: {msg}")
        out[rec.target_host.lower()] = rec
    return out


def enforce_authorization(
    host: str,
    auth_records: dict[str, AuthorizationRecord],
    owned_hosts: set[str],
) -> AuthorizationRecord:
    host = host.lower()
    if host in owned_hosts:
        now = dt.datetime.now(dt.timezone.utc)
        return AuthorizationRecord(
            mode="owns",
            target_host=host,
            signed_by="operator-cli",
            signed_at_utc=now.isoformat(),
            expires_at_utc=(now + dt.timedelta(hours=24)).isoformat(),
            reference="--i-own-this",
        )
    if host in auth_records:
        return auth_records[host]
    raise AuthorizationError(
        f"target {host} has no authorization record; refusing to probe"
    )


# ----------------------------------------------------------------------------
# Targets
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    url: str
    host: str
    scheme: str
    port: int
    path: str
    authorization_note: str = ""

    @property
    def base(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


def parse_target(raw: str, authorization_note: str = "") -> Target:
    raw = raw.strip()
    if not raw or any(ord(c) < 33 for c in raw) or "\\" in raw:
        raise ScopeError("empty URL, whitespace, control character or backslash")
    try:
        p = urlsplit(raw)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ScopeError("explicit http:// or https:// URL required")
        if p.username is not None or p.password is not None or p.fragment:
            raise ScopeError("credentials and fragments forbidden")
        host = p.hostname.encode("idna").decode().lower()
        port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ScopeError("invalid port")
        netloc = f"[{host}]" if ":" in host else host
        netloc += f":{port}"
        url = urlunsplit((p.scheme, netloc, p.path or "/", p.query, ""))
        return Target(url, host, p.scheme, port, p.path or "/", authorization_note)
    except (ValueError, UnicodeError) as exc:
        raise ScopeError(str(exc)) from exc


def load_targets_file(path: Path, note: str = "") -> list[Target]:
    out: dict[str, Target] = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            t = parse_target(line, note)
        except ScopeError as exc:
            raise ScopeError(f"{path}:{n}: {exc}") from exc
        out[t.url] = t
    if not out:
        raise ScopeError("no targets loaded")
    if len(out) > 4096:
        raise ScopeError("target list limit is 4096")
    return list(out.values())


def expand_cidr(cidr: str, note: str = "", max_hosts: int = 256) -> list[Target]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ScopeError(str(exc)) from exc
    if net.num_addresses > max_hosts:
        raise ScopeError(f"CIDR exceeds {max_hosts} total addresses")
    return [
        parse_target(f"https://[{ip}]" if net.version == 6 else f"https://{ip}", note)
        for ip in net.hosts()
    ]


# ----------------------------------------------------------------------------
# Target classification
# ----------------------------------------------------------------------------


TargetClass = Literal[
    "OWNED_ASSET", "CONTRACT_SCOPED", "BOUNTY_IN_SCOPE",
    "LOOPBACK", "PRIVATE_RANGE", "RESERVED", "UNOWNED_PUBLIC", "UNRESOLVED",
]


def _resolve_ips(host: str) -> tuple[str, ...]:
    try:
        ipaddress.ip_address(host)
        return (host,)
    except ValueError:
        pass
    if not _HAS_DNS:
        return ()
    try:
        return tuple(str(a) for a in dns.resolver.resolve(host, "A", lifetime=3.0))
    except Exception:
        return ()


def _ip_class(ip: str) -> TargetClass | None:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "LOOPBACK"
    if addr.is_private:
        return "PRIVATE_RANGE"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "RESERVED"
    return None


@dataclass
class TargetClassification:
    host: str
    category: TargetClass
    resolved_ips: tuple[str, ...]
    reason: str
    probe_permitted: bool


def classify_target(
    target: Target,
    owned_hosts: set[str],
    bounty_hosts: set[str],
    contract_hosts: set[str],
) -> TargetClassification:
    host = target.host.lower()
    ips = _resolve_ips(host)
    if host in owned_hosts:
        return TargetClassification(host, "OWNED_ASSET", ips, "in --i-own-this", True)
    if host in contract_hosts:
        return TargetClassification(host, "CONTRACT_SCOPED", ips, "in auth.json", True)
    if host in bounty_hosts:
        return TargetClassification(host, "BOUNTY_IN_SCOPE", ips, "in bounty list", True)
    if not ips:
        return TargetClassification(host, "UNRESOLVED", ips, "DNS resolution failed", False)
    classes = [_ip_class(ip) for ip in ips]
    if all(c == "LOOPBACK" for c in classes):
        return TargetClassification(host, "LOOPBACK", ips, "all A loopback", True)
    if all(c in ("PRIVATE_RANGE", "LOOPBACK") for c in classes):
        return TargetClassification(host, "PRIVATE_RANGE", ips, "all A private", True)
    if all(c is not None for c in classes):
        return TargetClassification(host, "RESERVED", ips, "all A reserved", False)
    return TargetClassification(host, "UNOWNED_PUBLIC", ips,
                                "public host, no authorization — REFUSED", False)


# ----------------------------------------------------------------------------
# HTTP probe
# ----------------------------------------------------------------------------


@dataclass
class ProbeResult:
    url: str
    host: str
    reachable: bool = False
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    redirect_out_of_scope: bool = False
    body_snippet: str | None = None
    error: str | None = None
    elapsed_ms: float = 0.0


DEFAULT_POLICY = {
    "allow_redirect_same_host_only": True,
    "connect_timeout_sec": 5.0,
    "read_timeout_sec": 8.0,
    "min_gap_sec_per_host": 2.0,
    "max_concurrency": 1,
    "user_agent": f"{TOOL_NAME}/{TOOL_VERSION} (authorized assessment)",
    "max_response_bytes": 65536,
    "collect_body": False,
}


def _probe_headers(policy: dict[str, Any]) -> dict[str, str]:
    return {
        "User-Agent": policy["user_agent"],
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }


async def probe_one(
    target: Target,
    policy: dict[str, Any],
    client: "httpx.AsyncClient",
) -> ProbeResult:
    res = ProbeResult(url=target.url, host=target.host)
    headers = _probe_headers(policy)
    started = 0.0
    try:
        import time as _t
        started = _t.perf_counter()
        r = await client.request("HEAD", target.url, headers=headers)
        if r.status_code in (405, 501):
            r = await client.request(
                "GET", target.url, headers={**headers, "Range": "bytes=0-2047"}
            )
        res.status = r.status_code
        res.reachable = True
        res.headers = {k.lower(): v for k, v in r.headers.items()}

        chain = [str(r.url)]
        redirects = 0
        current = r
        while current.is_redirect and redirects < 5:
            loc = current.headers.get("location", "")
            nxt = httpx.URL(str(current.url)).join(loc)
            chain.append(str(nxt))
            same_host = nxt.host == target.host
            if policy["allow_redirect_same_host_only"] and not same_host:
                res.redirect_out_of_scope = True
                break
            current = await client.request("HEAD", str(nxt), headers=headers)
            redirects += 1
        res.redirect_chain = chain

        if policy["collect_body"] and current.method != "HEAD":
            body = current.content or b""
            limit = int(policy["max_response_bytes"])
            res.body_snippet = body[:limit].decode("utf-8", errors="replace")

        import time as _t2
        res.elapsed_ms = (_t2.perf_counter() - started) * 1000.0
    except Exception as exc:
        res.error = f"{type(exc).__name__}: {exc}"
    return res


async def probe_all(
    targets: list[Target],
    policy: dict[str, Any],
) -> list[ProbeResult]:
    if not _HAS_HTTPX:
        print("[!] httpx not installed; run: pip install httpx", file=sys.stderr)
        return [ProbeResult(url=t.url, host=t.host, error="httpx missing") for t in targets]

    timeout = httpx.Timeout(
        connect=policy["connect_timeout_sec"],
        read=policy["read_timeout_sec"],
        write=5.0,
        pool=5.0,
    )
    sem = asyncio.Semaphore(int(policy["max_concurrency"]))
    gap = float(policy["min_gap_sec_per_host"])
    last_hit: dict[str, float] = {}

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=False,
        trust_env=False,
    ) as client:
        async def _one(t: Target) -> ProbeResult:
            async with sem:
                key = f"{t.host}:{t.port}"
                now = asyncio.get_event_loop().time()
                wait = max(0.0, last_hit.get(key, 0.0) + gap - now)
                if wait > 0:
                    await asyncio.sleep(wait)
                last_hit[key] = asyncio.get_event_loop().time()
                return await probe_one(t, policy, client)

        return await asyncio.gather(*(_one(t) for t in targets))


# ----------------------------------------------------------------------------
# PHP fingerprint
# ----------------------------------------------------------------------------


@dataclass
class PhpFingerprint:
    version: str | None = None
    version_source: str | None = None
    confidence: str = "NONE"
    sapi_hint: str | None = None
    sapi_confidence: str = "NONE"
    server: str | None = None
    powered_by: str | None = None


def fingerprint_php(probe: ProbeResult) -> PhpFingerprint:
    fp = PhpFingerprint()
    if not probe.reachable:
        return fp
    fp.server = probe.headers.get("server")
    fp.powered_by = probe.headers.get("x-powered-by")

    for source, value, conf in [
        ("X-Powered-By", fp.powered_by or "", "MEDIUM"),
        ("Server", fp.server or "", "LOW"),
        ("Body", probe.body_snippet or "", "LOW"),
    ]:
        m = PHP_VERSION_RE.search(value)
        if m:
            fp.version = m.group(1)
            fp.version_source = source
            fp.confidence = conf
            break

    if fp.powered_by and "php" in fp.powered_by.lower():
        if "fpm" in fp.powered_by.lower():
            fp.sapi_hint = "fpm"
            fp.sapi_confidence = "LOW"
    return fp


# ----------------------------------------------------------------------------
# Version classification (CVE-2026-109618 / -109619)
# ----------------------------------------------------------------------------


@dataclass
class CveClassification:
    version: str | None
    classification: str
    reason: str
    confidence: str


def classify_version(
    version: str | None,
    confidence: str,
    vendor_backport: bool | None = None,
) -> CveClassification:
    def _r(c: str, reason: str, conf: str = "LOW") -> CveClassification:
        return CveClassification(version, c, reason, conf)

    if not version:
        return _r("UNKNOWN", "no PHP version evidence")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        return _r("NEEDS_MANUAL_REVIEW", "non-release or vendor-specific version")
    parsed = tuple(int(x) for x in version.split("."))
    if vendor_backport is True:
        return _r("VENDOR_REPORTED_PATCHED",
                  "operator reports vendor backport; not independently verified")
    fixed = FIXED_UPSTREAM.get(parsed[:2])
    if fixed is None:
        return _r("NEEDS_MANUAL_REVIEW",
                  "branch outside verified upstream version table")
    conf = confidence if confidence in ("HIGH", "MEDIUM", "LOW") else "LOW"
    if parsed >= fixed:
        return _r("LIKELY_PATCHED",
                  f"version >= {'.'.join(map(str, fixed))}; original CVE pair only",
                  conf)
    return _r("POTENTIALLY_AFFECTED",
              "version below original-pair fix; check vendor backports", conf)


# ----------------------------------------------------------------------------
# ASan / PHPT parsing
# ----------------------------------------------------------------------------


@dataclass
class AsanParse:
    findings: list[str] = field(default_factory=list)
    oom_anomaly: bool = False
    recursion_marker: bool = False
    fatal_oom: bool = False


def parse_asan_log(text: str) -> AsanParse:
    res = AsanParse()
    for name, pat in ASAN_PATTERNS.items():
        if pat.search(text):
            res.findings.append(name)
    res.oom_anomaly = bool(OOM_ANOMALY_RE.search(text))
    res.recursion_marker = bool(RECURSION_RE.search(text))
    res.fatal_oom = ("Allowed memory size" in text) or ("Out of memory" in text)
    return res


# ----------------------------------------------------------------------------
# Evidence hashing
# ----------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest(outputs: dict[str, Any], authorization_note: str) -> dict[str, Any]:
    entries = []
    for label, payload in outputs.items():
        if isinstance(payload, (dict, list)):
            raw = json.dumps(payload, sort_keys=True, default=str).encode()
        elif isinstance(payload, str):
            raw = payload.encode()
        elif isinstance(payload, bytes):
            raw = payload
        else:
            raw = str(payload).encode()
        entries.append({"label": label, "sha256": sha256_bytes(raw), "bytes": len(raw)})
    return {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "tool": f"{TOOL_NAME}/{TOOL_VERSION}",
        "authorization_note": authorization_note,
        "artifacts": entries,
    }


# ----------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------


@dataclass
class ReportRow:
    url: str
    host: str
    target_class: str
    status: int | None
    php_version: str | None
    version_source: str | None
    version_confidence: str
    sapi_hint: str | None
    server: str | None
    classification: str
    classification_reason: str
    classification_confidence: str
    remote_exploitation_proven: bool = False
    impact_claim_source: str = "upstream_advisory"
    notes: str = ""


@dataclass
class Report:
    generated_utc: str
    tool_version: str
    scope_note: str
    rows: list[ReportRow] = field(default_factory=list)
    refused: list[dict[str, Any]] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


def _csv_escape(v: Any) -> Any:
    if v is None:
        return ""
    s = str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def report_to_json(rep: Report) -> str:
    return json.dumps(asdict(rep), indent=2, ensure_ascii=False) + "\n"


def report_to_csv(rep: Report) -> str:
    buf = io.StringIO()
    if not rep.rows:
        return ""
    fields = list(asdict(rep.rows[0]).keys())
    w = csv.DictWriter(buf, fieldnames=fields)
    w.writeheader()
    for r in rep.rows:
        w.writerow({k: _csv_escape(getattr(r, k)) for k in fields})
    return buf.getvalue()


def report_to_markdown(rep: Report) -> str:
    def esc(v: Any) -> str:
        s = str(v if v is not None else "—")
        for a, b in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"),
                     ("|", r"\|"), ("\n", " "), ("\r", " ")):
            s = s.replace(a, b)
        return s

    lines = [
        "# PHP2Shell Exposure Assessment",
        "",
        f"- **Generated UTC:** {esc(rep.generated_utc)}",
        f"- **Tool:** {esc(rep.tool_version)}",
        f"- **Scope:** {esc(rep.scope_note)}",
        "",
        "## Probe Results",
        "",
        "| URL | Class | HTTP | PHP | Source | Conf | CVE Class | Notes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rep.rows:
        lines.append("| " + " | ".join(esc(x) for x in (
            r.url, r.target_class, r.status, r.php_version, r.version_source,
            r.version_confidence, r.classification, r.notes,
        )) + " |")

    if rep.refused:
        lines += ["", "## Refused Targets (no authorization)", ""]
        for r in rep.refused:
            lines.append(f"- `{esc(r['host'])}` — {esc(r['reason'])}")

    lines += ["", "## Evidence Manifest", "", "```json",
              json.dumps(rep.manifest, indent=2, default=str), "```"]

    lines += ["", "## Limitations", ""]
    for lim in rep.limitations:
        lines.append(f"- {esc(lim)}")

    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def _load_host_file(p: Path | None) -> set[str]:
    if p is None:
        return set()
    return {
        line.strip().lower()
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def _load_policy(p: Path | None) -> dict[str, Any]:
    pol = dict(DEFAULT_POLICY)
    if p is not None:
        pol.update(json.loads(p.read_text(encoding="utf-8")))
    return pol


async def _run(args: argparse.Namespace) -> int:
    scope_note = args.scope_note or "no authorization note supplied"

    # Authorization inputs
    owned_hosts = _load_host_file(args.owned_assets)
    for h in (args.i_own_this or []):
        owned_hosts.add(h.lower())
    bounty_hosts = _load_host_file(args.bounty_hosts)
    auth_records: dict[str, AuthorizationRecord] = {}
    if args.auth_file:
        try:
            auth_records = load_authorization_file(args.auth_file)
        except (AuthorizationError, json.JSONDecodeError) as exc:
            print(f"[auth] {exc}", file=sys.stderr)
            return 2

    # Targets
    try:
        if args.cidr:
            targets = expand_cidr(args.cidr, scope_note)
        else:
            targets = load_targets_file(args.targets, scope_note)
    except ScopeError as exc:
        print(f"[scope] {exc}", file=sys.stderr)
        return 2

    # Classification + authorization gate
    authorized: list[Target] = []
    refused: list[dict[str, Any]] = []
    contract_hosts = set(auth_records.keys())
    for t in targets:
        cls = classify_target(t, owned_hosts, bounty_hosts, contract_hosts)
        if cls.category == "UNOWNED_PUBLIC":
            refused.append({"host": t.host, "category": cls.category,
                            "reason": cls.reason})
            continue
        if not cls.probe_permitted:
            refused.append({"host": t.host, "category": cls.category,
                            "reason": cls.reason})
            continue
        try:
            enforce_authorization(t.host, auth_records, owned_hosts)
        except AuthorizationError as exc:
            refused.append({"host": t.host, "category": cls.category,
                            "reason": str(exc)})
            continue
        authorized.append(t)

    if refused:
        print(f"[!] {len(refused)} target(s) refused — no authorization",
              file=sys.stderr)
        for r in refused:
            print(f"    - {r['host']}: {r['reason']}", file=sys.stderr)
    if not authorized:
        print("[abort] zero authorized targets. exiting.", file=sys.stderr)
        return 3

    print(f"[*] probing {len(authorized)} authorized target(s) "
          f"(HEAD-only, rate-limited, no body by default)...")

    policy = _load_policy(args.policy)
    if args.allow_body:
        policy["collect_body"] = True

    probes = await probe_all(authorized, policy)

    vendor_backport_map: dict[str, bool] = {}
    if args.vendor_backport_file:
        try:
            vendor_backport_map = {
                k.lower(): bool(v)
                for k, v in json.loads(args.vendor_backport_file.read_text()).items()
            }
        except Exception as exc:
            print(f"[warn] vendor-backport file: {exc}", file=sys.stderr)

    rows: list[ReportRow] = []
    for pr in probes:
        fp = fingerprint_php(pr)
        vb = vendor_backport_map.get(pr.host)
        cls = classify_version(fp.version, fp.confidence, vb)
        notes = ""
        if pr.error:
            notes = pr.error
        elif pr.redirect_out_of_scope:
            notes = "redirect_out_of_scope"
        rows.append(ReportRow(
            url=pr.url, host=pr.host,
            target_class="AUTHORIZED",
            status=pr.status,
            php_version=fp.version,
            version_source=fp.version_source,
            version_confidence=fp.confidence,
            sapi_hint=fp.sapi_hint,
            server=fp.server,
            classification=cls.classification,
            classification_reason=cls.reason,
            classification_confidence=cls.confidence,
            notes=notes,
        ))

    outputs: dict[str, Any] = {
        "probes": [asdict(p) for p in probes],
    }
    if args.asan_log:
        text = Path(args.asan_log).read_text(encoding="utf-8", errors="replace")
        asan = parse_asan_log(text)
        outputs["asan"] = asdict(asan)

    manifest = build_manifest(outputs, scope_note)

    rep = Report(
        generated_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        tool_version=f"{TOOL_NAME}/{TOOL_VERSION}",
        scope_note=scope_note,
        rows=rows,
        refused=refused,
        manifest=manifest,
        limitations=[
            "remote_exploitation_proven = false unless separately established",
            "version headers may be spoofed or obscured by proxy/CDN",
            "Server header does not prove SAPI (FPM vs mod_php)",
            "vendor backport status only as operator-supplied",
            "CVE-2026-115560 (session upload progress) is separate — "
            "configuration review required, not covered by version triage",
            "no POST/PUT/PATCH/DELETE, no payloads, no RCE validation",
            f"upstream advisory reference: {ADVISORY_URL}",
        ],
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(report_to_json(rep), encoding="utf-8")
    (out_dir / "report.md").write_text(report_to_markdown(rep), encoding="utf-8")
    csv_text = report_to_csv(rep)
    if csv_text:
        (out_dir / "report.csv").write_text(csv_text, encoding="utf-8")
    (out_dir / "manifest.json").write_text(
        json.dumps(rep.manifest, indent=2, default=str), encoding="utf-8"
    )
    print(f"[+] reports written to {out_dir}/")
    return 0


# ----------------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------------


def _self_test() -> int:
    failures = 0

    def check(name: str, cond: bool, extra: str = "") -> None:
        nonlocal failures
        status = "ok " if cond else "FAIL"
        print(f"[{status}] {name}{(' — ' + extra) if extra and not cond else ''}")
        if not cond:
            failures += 1

    # targets
    t = parse_target("https://example.com/x")
    check("parse https", t.port == 443 and t.host == "example.com")
    try:
        parse_target("example.com")
        check("reject no-scheme", False)
    except ScopeError:
        check("reject no-scheme", True)

    # authorization
    rec = AuthorizationRecord(
        mode="owns", target_host="example.com",
        signed_by="x", signed_at_utc="2026-01-01T00:00:00Z",
        expires_at_utc="2099-01-01T00:00:00Z",
    )
    ok, _ = rec.is_valid()
    check("auth record valid", ok)
    expired = AuthorizationRecord(
        mode="owns", target_host="x",
        signed_by="x", signed_at_utc="2020-01-01T00:00:00Z",
        expires_at_utc="2020-06-01T00:00:00Z",
    )
    ok, _ = expired.is_valid()
    check("auth record expired rejected", not ok)

    # version classification
    check("8.4.27 likely patched",
          classify_version("8.4.27", "MEDIUM").classification == "LIKELY_PATCHED")
    check("8.4.26 potentially affected",
          classify_version("8.4.26", "MEDIUM").classification == "POTENTIALLY_AFFECTED")
    check("7.4.33 manual review",
          classify_version("7.4.33", "MEDIUM").classification == "NEEDS_MANUAL_REVIEW")
    check("None unknown",
          classify_version(None, "NONE").classification == "UNKNOWN")

    # fingerprint
    pr = ProbeResult(url="https://x", host="x", reachable=True,
                     status=200, headers={"x-powered-by": "PHP/8.4.26"})
    fp = fingerprint_php(pr)
    check("fingerprint x-powered-by", fp.version == "8.4.26" and fp.confidence == "MEDIUM")

    # asan
    a = parse_asan_log("ERROR: AddressSanitizer: heap-use-after-free on 0x0")
    check("asan uaf detected", "heap-use-after-free" in a.findings)
    b = parse_asan_log("&array(5342)\n")
    check("oom anomaly detected", b.oom_anomaly)
    c = parse_asan_log("*RECURSION*\n")
    check("recursion marker", c.recursion_marker)

    # report formats
    rows = [ReportRow(
        url="https://x", host="x", target_class="AUTHORIZED", status=200,
        php_version="8.4.26", version_source="X-Powered-By",
        version_confidence="MEDIUM", sapi_hint=None, server="nginx",
        classification="POTENTIALLY_AFFECTED", classification_reason="x",
        classification_confidence="MEDIUM",
    )]
    rep = Report(
        generated_utc="2026-10-27T00:00:00Z",
        tool_version=f"{TOOL_NAME}/{TOOL_VERSION}",
        scope_note="self-test", rows=rows,
        manifest=build_manifest({"x": "y"}, "self-test"),
        limitations=["test"],
    )
    j = report_to_json(rep)
    check("json report", '"rows"' in j)
    m = report_to_markdown(rep)
    check("markdown report", "PHP2Shell Exposure Assessment" in m)
    csv_text = report_to_csv(rep)
    check("csv report", "url,host,target_class" in csv_text)

    # csv formula injection
    rows2 = [ReportRow(
        url="=cmd|' /c calc'!A0", host="x", target_class="AUTHORIZED",
        status=200, php_version=None, version_source=None,
        version_confidence="NONE", sapi_hint=None, server=None,
        classification="UNKNOWN", classification_reason="", classification_confidence="LOW",
    )]
    rep2 = Report(
        generated_utc="2026-10-27T00:00:00Z",
        tool_version=f"{TOOL_NAME}/{TOOL_VERSION}", scope_note="t",
        rows=rows2, manifest={}, limitations=[],
    )
    check("csv formula escape", report_to_csv(rep2).startswith("url,host") and "'=cmd" in report_to_csv(rep2))

    # classification
    unowned = classify_target(
        parse_target("https://example.com"),
        owned_hosts=set(), bounty_hosts=set(), contract_hosts=set(),
    )
    check("public host refused", unowned.category == "UNOWNED_PUBLIC")

    print()
    if failures:
        print(f"SELF-TEST FAILED ({failures} failure(s))")
        return 1
    print("SELF-TEST PASSED")
    return 0


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{TOOL_VERSION} — authorized exposure assessment",
    )
    p.add_argument("--targets", type=Path, help="targets file, one URL per line")
    p.add_argument("--cidr", help="explicit CIDR (/24 or narrower)")
    p.add_argument("--owned-assets", type=Path, help="file of hosts you personally own")
    p.add_argument("--i-own-this", action="append", default=[],
                   help="declare host you personally own (repeatable)")
    p.add_argument("--auth-file", type=Path, help="auth.json with signed records")
    p.add_argument("--bounty-hosts", type=Path, help="file of in-scope bounty hosts")
    p.add_argument("--policy", type=Path, help="policy.json overrides")
    p.add_argument("--scope-note", default="", help="authorization note for reports")
    p.add_argument("--vendor-backport-file", type=Path,
                   help="json {host: true|false}")
    p.add_argument("--asan-log", type=Path, help="optional ASan/PHPT log")
    p.add_argument("--allow-body", action="store_true",
                   help="permit small GET body collection")
    p.add_argument("--out", default="results", help="output directory")
    p.add_argument("--self-test", action="store_true", help="run offline self-test")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")

    args = p.parse_args(argv)

    if args.self_test:
        return _self_test()

    if not args.targets and not args.cidr:
        p.error("either --targets or --cidr is required")

    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())