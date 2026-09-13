#!/usr/bin/env python3
"""
agentscan.py — Authorized-scope scanner for exposed AI / agent services.

Finds AI/agent services (LLM inference, agent platforms, automation, MCP, web
UIs) listening on standard ports that reply WITHOUT authentication, and prints
the read-only curl commands to interact with each one.

It is READ-ONLY by design: only GET requests (plus a single MCP JSON-RPC
`initialize` handshake, which sends no data) are issued. It never POSTs prompts,
never uploads, never writes, never executes model output.

USAGE
    agentscan.py --targets targets.txt --authorized [options]

    # single host, common AI ports
    agentscan.py -t 10.0.0.5 --authorized

    # subnet
    agentscan.py -t 10.0.0.0/24 --authorized --rate 100 --json out.json

    # only Ollama + Flowise + n8n ports
    agentscan.py -t host.txt --authorized --ports 11434,3000,5678

AUTHORIZATION
    --authorized is mandatory. Only run against assets you own or have explicit
    written permission to test. Internet-wide scanning of third parties is NOT
    supported by this tool's intended use.
"""

import argparse
import concurrent.futures as cf
import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
import threading
import time
from datetime import datetime

from . import signatures as SIG

# --------------------------------------------------------------------------
VERSION = "1.0.0"

BANNER = r"""
 █████╗  ██████╗ ███████╗███╗   ██╗████████╗███████╗ ██████╗  █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
      made by JohnDoeAnon in collaboration with AnonymousITALIA
"""

MISSING = object()
MAX_BODY = 262144          # 256 KiB cap per response
UA = "Mozilla/5.0 (compatible; AgentScope/1.0; +authorized-security-audit)"


# ----------------------------- helpers ------------------------------------
class RateLimiter:
    """Global token-bucket-ish limiter: at most `rps` requests per second."""

    def __init__(self, rps):
        self.interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self.lock = threading.Lock()
        self.next_time = 0.0

    def wait(self):
        if self.interval <= 0:
            return
        with self.lock:
            now = time.monotonic()
            if now < self.next_time:
                sleep_for = self.next_time - now
                self.next_time += self.interval
            else:
                sleep_for = 0.0
                self.next_time = now + self.interval
        if sleep_for > 0:
            time.sleep(sleep_for)


def json_get(obj, dotted):
    """Get a dotted path from parsed JSON. Returns MISSING if absent."""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return MISSING
        elif isinstance(cur, dict):
            if part not in cur:
                return MISSING
            cur = cur[part]
        else:
            return MISSING
    return cur


def get_header(headers, name):
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return None


def looks_like_login(body):
    low = body[:4000].lower()
    return ("<form" in low and "password" in low) or "sign in" in low or "signin" in low


def command_path(cmd):
    """Extract the request path from a command template containing {url}.

    '{url}/api/tags'              -> '/api/tags'
    '{url}/api/show -d \\'..\\''   -> '/api/show'
    '{url}/'                      -> '/'
    """
    i = cmd.find("{url}")
    if i == -1:
        return None
    rest = cmd[i + len("{url}"):].strip()
    if not rest:
        return "/"
    out = []
    for ch in rest:
        if ch.isspace() or ch in "'\"":
            break
        out.append(ch)
    return "".join(out) or "/"


def _status_is_active(st):
    """An endpoint counts as ACTIVE when it answers meaningfully rather than 404.

    2xx/3xx -> serves data or redirects; 401/403 -> exists but auth; 405 ->
    exists but wrong HTTP method (so the API function is present).
    """
    return st is not None and ((200 <= st < 400) or st in (401, 403, 405))


def build_commands(commands, base, status=None):
    """Substitute {url} in each command template (str.replace, NOT .format, so
    literal JSON braces survive). `commands` is a list of (description, cmd)."""
    out = []
    for desc, cmd in commands:
        out.append({"description": desc,
                    "command": cmd.replace("{url}", base),
                    "url": base, "status": status})
    return out


def _probe_path(host, port, path, schemes, timeout, limiter, path_cache):
    """GET a path once per target, caching (status, body). Never raises."""
    if path in path_cache:
        return path_cache[path]
    limiter.wait()
    res = fetch(host, port, path, schemes, timeout, "GET", None, None)
    val = (res[1], res[3]) if res else (-1, "")
    path_cache[path] = val
    if res is not None:
        _maybe_dump(host, port, path, res[1], res[3])
    return val


# Aggressive path-sweep configuration: mode -> (prefixes, request budget/service)
SWEEP = {"mode": "normal"}
SWEEP_PLAN = {
    "normal": (SIG.SWEEP_PREFIXES_NORMAL, 120),
    "aggressive": (SIG.SWEEP_PREFIXES_ALL, 1500),
}


def _sweep(host, port, schemes, timeout, limiter, path_cache, endpoints, have_get,
           mode):
    """Brute-force common API sub-paths under known prefixes (GET only).

    Interleaves segment-outer / prefix-inner so the budget is spread across all
    prefixes. Keeps only paths that answer; never repeats a cached path.
    """
    prefixes, budget = SWEEP_PLAN.get(mode, SWEEP_PLAN["normal"])
    used = 0
    # standalone well-known paths first (graphql, swagger, actuator, ...)
    for path in SIG.SWEEP_EXTRA_PATHS:
        if path in have_get or path in path_cache:
            continue
        if used >= budget:
            break
        used += 1
        st, body = _probe_path(host, port, path, schemes, timeout, limiter,
                               path_cache)
        if _status_is_active(st):
            endpoints["GET " + path] = {
                "path": path, "method": "GET", "status": st,
                "source": "sweep", "description": "discovered by path sweep",
                "snippet": _snip(body)}
            have_get.add(path)
    if SWEEP.get("budget"):
        budget = SWEEP["budget"]
    for seg in SIG.SWEEP_SEGMENTS:
        for pre in prefixes:
            path = "{}/{}".format(pre.rstrip("/"), seg)
            if path in have_get or path in path_cache:
                continue
            if used >= budget:
                return
            used += 1
            st, body = _probe_path(host, port, path, schemes, timeout, limiter,
                                   path_cache)
            if _status_is_active(st):
                endpoints["GET " + path] = {
                    "path": path, "method": "GET", "status": st,
                    "source": "sweep", "description": "discovered by path sweep",
                    "snippet": _snip(body)}
                have_get.add(path)


# Response-body dumping for 200 responses (inspection aid). Enabled by
# --dump-response; writes one file per (host, port, path) that returned 2xx.
DUMP = {"enabled": False, "dir": None, "lock": threading.Lock(), "seen": set()}


def _maybe_dump(host, port, path, status, body):
    if not DUMP["enabled"] or not body:
        return
    if not (200 <= status < 300):
        return
    key = (host, port, path)
    with DUMP["lock"]:
        if key in DUMP["seen"]:
            return
        DUMP["seen"].add(key)
    safe_path = (path.strip("/") or "root").replace("/", "_")
    safe_host = host.replace(":", "_")
    fname = "{}_{}_{}.txt".format(safe_host, port, safe_path)[:180]
    try:
        os.makedirs(DUMP["dir"], exist_ok=True)
        with open(os.path.join(DUMP["dir"], fname), "w", encoding="utf-8",
                  errors="replace") as fh:
            fh.write("url: {}://{}:{}{}\n".format("http", host, port, path))
            fh.write("status: {}\n\n".format(status))
            fh.write(body)
    except Exception:
        pass


def verify_commands(host, port, schemes, timeout, limiter, commands, base,
                    path_cache, verify=True):
    """Probe each command's endpoint and return ONLY the ones that are live.

    Endpoints returning 404 (or failing to connect) are dropped, so every
    command printed in the report is actually usable against this target.
    """
    if not verify:
        return build_commands(commands, base)
    out = []
    for desc, cmd in commands:
        path = command_path(cmd)
        if path is None:
            continue
        st, _ = _probe_path(host, port, path, schemes, timeout, limiter, path_cache)
        if _status_is_active(st):
            out.append({"description": desc,
                        "command": cmd.replace("{url}", base),
                        "url": base, "status": st})
    return out


def discover_endpoints(host, port, schemes, timeout, limiter, sig, path_cache,
                       verify=True, evidence=None):
    """Enumerate the API endpoints a detected service actually exposes.

    Sources, merged and de-duplicated:
      0. Paths already confirmed live during fingerprinting (evidence).
      1. OpenAPI (/openapi.json) — full route list with real HTTP methods
         (works for vLLM, LangServe, hayhooks, OpenLLM, LiteLLM, Letta, ...).
      2. The per-service catalog in signatures.ENDPOINT_CATALOG + command paths.
      3. The shared OpenAI-compatible surface when /v1/models is live, plus the
         dynamic sub-resource /v1/models/{first_model_id}.

    Only GET is requested. A POST-only route appears as HTTP 405 (proving the
    function exists) — nothing is ever POSTed. Only paths that answer are kept.

    Guard: SPA servers (Gradio/Streamlit/...) answer 200 HTML for *any* path, so
    probing a catalog there would list everything. A single canary path detects
    this and disables speculative catalog probing for that service.
    """
    if not verify:
        return []
    endpoints = {}

    # 0) paths confirmed during fingerprinting
    for e in (evidence or []):
        if e.get("result") == "match" and _status_is_active(e["status"]):
            endpoints["GET " + e["path"]] = {
                "path": e["path"], "method": "GET", "status": e["status"],
                "source": "detection", "snippet": e.get("snippet", ""),
                "description": "confirmed during fingerprinting"}

    # canary: if a nonexistent path returns 2xx, this server has a catch-all
    rst, _ = _probe_path(host, port, "/__agentscan_404_canary__", schemes,
                         timeout, limiter, path_cache)
    catch_all = rst is not None and 200 <= rst < 300

    if not catch_all:
        # 1) OpenAPI auto-discovery
        spec_found = False
        st, body = _probe_path(host, port, "/openapi.json", schemes, timeout,
                               limiter, path_cache)
        if _status_is_active(st) and st < 400 and body:
            try:
                spec = json.loads(body)
            except Exception:
                spec = None
            if isinstance(spec, dict) and isinstance(spec.get("paths"), dict):
                spec_found = True
                for p, methods in spec["paths"].items():
                    if not isinstance(methods, dict):
                        continue
                    for m, meta in methods.items():
                        mu = m.upper()
                        if mu not in ("GET", "POST", "PUT", "PATCH", "DELETE",
                                      "HEAD", "OPTIONS"):
                            continue
                        desc = ""
                        if isinstance(meta, dict):
                            desc = meta.get("summary") or meta.get("operationId") or ""
                        endpoints["{} {}".format(mu, p)] = {
                            "path": p, "method": mu, "status": None,
                            "source": "openapi", "description": str(desc)[:80]}

        # 2) catalog + command paths (generic list only if we have nothing else)
        catalog = []
        if sig is not None:
            catalog += list(SIG.ENDPOINT_CATALOG.get(sig.get("service", ""), []))
            for desc, cmd in sig.get("commands", []):
                cp = command_path(cmd)
                if cp:
                    catalog.append((cp, desc))
        if not catalog:
            catalog = list(SIG.GENERIC_ENDPOINTS)

        have_get = {e["path"] for e in endpoints.values() if e["method"] == "GET"}
        for path, desc in catalog:
            if path in have_get:
                continue
            st, body = _probe_path(host, port, path, schemes, timeout, limiter,
                                   path_cache)
            if _status_is_active(st):
                endpoints["GET " + path] = {
                    "path": path, "method": "GET", "status": st,
                    "source": "probe", "description": desc,
                    "snippet": _snip(body)}
                have_get.add(path)

        # 2b) aggressive path sweep, only when there is no OpenAPI spec
        if not spec_found and SWEEP["mode"] != "off":
            _sweep(host, port, schemes, timeout, limiter, path_cache, endpoints,
                   have_get, SWEEP["mode"])

        # 3) OpenAI-compatible surface, when /v1/models is live on this service
        v1_st, v1_body = path_cache.get("/v1/models", (None, ""))
        if _status_is_active(v1_st):
            for path, desc in SIG.OPENAI_COMPAT_ENDPOINTS:
                if path in have_get:
                    continue
                st, body = _probe_path(host, port, path, schemes, timeout, limiter,
                                       path_cache)
                if _status_is_active(st):
                    endpoints["GET " + path] = {
                        "path": path, "method": "GET", "status": st,
                        "source": "probe", "description": desc,
                        "snippet": _snip(body)}
                    have_get.add(path)
            # dynamic sub-resource: /v1/models/{first_model_id}
            try:
                models = json.loads(v1_body).get("data") if v1_body else None
                if isinstance(models, list) and models and isinstance(models[0], dict):
                    mid = str(models[0].get("id") or "").strip().strip("/")
                    if mid:
                        p = "/v1/models/" + mid
                        st, body = _probe_path(host, port, p, schemes, timeout,
                                               limiter, path_cache)
                        if _status_is_active(st):
                            endpoints["GET " + p] = {
                                "path": p, "method": "GET", "status": st,
                                "source": "probe", "snippet": _snip(body),
                                "description": "single model ({})".format(mid)}
            except Exception:
                pass

    # backfill status for GET routes already probed elsewhere (free, no request)
    for e in endpoints.values():
        if e["method"] == "GET" and e["status"] is None:
            cached = path_cache.get(e["path"])
            if cached and _status_is_active(cached[0]):
                e["status"] = cached[0]

    return sorted(endpoints.values(),
                  key=lambda e: (e["method"] != "GET", e["path"]))


# ----------------------------- HTTP layer ---------------------------------
def _one_request(host, port, path, scheme, timeout, method, body, headers_extra):
    if scheme == "https":
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    headers = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    if headers_extra:
        headers.update(headers_extra)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(MAX_BODY)
        return resp.status, list(resp.getheaders()), raw.decode("utf-8", "replace")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def fetch(host, port, path, schemes, timeout, method="GET", body=None,
          headers_extra=None):
    """Try each scheme in order; return (scheme, status, headers, body) or None."""
    for scheme in schemes:
        try:
            status, headers, text = _one_request(
                host, port, path, scheme, timeout, method, body, headers_extra
            )
        except ssl.SSLError:
            continue
        except (http.client.BadStatusLine, http.client.RemoteDisconnected,
                ConnectionResetError, ConnectionRefusedError, BrokenPipeError):
            # plain HTTP against a TLS port (or vice-versa) -> try next scheme
            continue
        except (socket.timeout, TimeoutError):
            return None
        except Exception:
            continue

        # Server told us to use HTTPS
        if status in (400, 495, 496, 497) and "plain http" in text.lower():
            continue
        return scheme, status, headers, text
    return None


# ----------------------------- probing ------------------------------------
def match_all(conds, status, headers, body, jdata):
    for c in conds:
        t = c["type"]
        if t == "status":
            if status not in c["in"]:
                return False
        elif t == "contains":
            if c["value"] not in body:
                return False
        elif t == "not_contains":
            if c["value"] in body:
                return False
        elif t == "json_key":
            if jdata is None or json_get(jdata, c["value"]) is MISSING:
                return False
        elif t == "json_value":
            if jdata is None or json_get(jdata, c["value"]) != c["equals"]:
                return False
        elif t == "header":
            hv = get_header(headers, c["name"])
            if hv is None or c["contains"].lower() not in hv.lower():
                return False
        elif t == "json":
            if jdata is None:
                return False
    return True


def parse_json(body):
    try:
        return json.loads(body)
    except Exception:
        return None


def run_probe(host, port, schemes, timeout, limiter, probe):
    limiter.wait()
    method = probe.get("method", "GET")
    body = probe.get("body")
    headers = probe.get("headers")
    res = fetch(host, port, probe["path"], schemes, timeout, method, body, headers)
    if res is None:
        return None
    scheme, status, hdrs, text = res
    if method == "GET":
        _maybe_dump(host, port, probe["path"], status, text)
    return {"path": probe["path"], "scheme": scheme, "status": status,
            "headers": hdrs, "body": text}


def evidence_snippet(text, key):
    """Produce a short, safe evidence snippet."""
    try:
        data = json.loads(text)
    except Exception:
        return text[:120].replace("\n", " ").strip()
    if key:
        val = json_get(data, key)
        if val is not MISSING:
            s = json.dumps(val)
            return s[:160]
    return json.dumps(data)[:160]


def _snip(body, n=120):
    """One-line snippet of a response body, for inline display."""
    if not body:
        return ""
    return body.strip().replace("\n", " ").replace("\r", " ")[:n]


def probe_target(host, port, schemes, timeout, limiter, aggressive, verify=True):
    """Return a finding dict or None (port closed)."""
    # --- TCP reachability ---
    limiter.wait()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except Exception:
        return None

    finding = {
        "host": host, "port": port,
        "service": "unknown-HTTP", "vendor": "", "category": "unknown",
        "auth": "unknown", "confidence": "low", "severity": "info",
        "evidence": [], "commands": [], "endpoints": [], "notes": "",
    }

    candidates = [s for s in SIG.SIGNATURES if port in s["ports"]]
    if aggressive:
        # try every signature on this port
        candidates = list(SIG.SIGNATURES)

    best = None          # (score, sig, matched_probe, evidence, auth_seen, scheme)
    protected = None     # (sig, evidence, scheme) when a known service enforces auth
    auth_seen = False
    server_banner = None
    path_cache = {}      # path -> (status, body), cached to avoid duplicate GETs

    # canary: a catch-all server (SPA) answers 2xx for ANY path, which makes
    # status-only probe matches meaningless. When detected, only accept probe
    # matches that also check content (JSON / string / header).
    canary_st, _ = _probe_path(host, port, "/__agentscan_404_canary__", schemes,
                               timeout, limiter, path_cache)
    catch_all = canary_st is not None and 200 <= canary_st < 300

    for sig in candidates:
        local_strong = False
        local_unauth = False
        local_evidence = []
        matched_probe = None
        local_scheme = None
        local_auth_scheme = None
        for probe in sig["probes"]:
            resp = run_probe(host, port, schemes, timeout, limiter, probe)
            if resp is None:
                continue
            if server_banner is None:
                server_banner = get_header(resp["headers"], "server")
            st = resp["status"]
            path_cache[resp["path"]] = (st, resp["body"])
            if st in sig["auth_status"]:
                auth_seen = True
                if local_auth_scheme is None:
                    local_auth_scheme = resp["scheme"]
                local_evidence.append({
                    "path": resp["path"], "status": st,
                    "result": "auth-required",
                    "snippet": (get_header(resp["headers"], "www-authenticate") or "")[:120],
                })
                continue
            jdata = parse_json(resp["body"])
            if catch_all and not any(c["type"] != "status" for c in probe["match"]):
                continue  # status-only match is worthless on a catch-all server
            if match_all(probe["match"], st, resp["headers"], resp["body"], jdata):
                local_unauth = True
                if probe.get("strong"):
                    local_strong = True
                local_evidence.append({
                    "path": resp["path"], "status": st,
                    "result": "match",
                    "snippet": evidence_snippet(resp["body"], probe.get("snippet")),
                })
                if matched_probe is None:
                    matched_probe = probe
                    local_scheme = resp["scheme"]
        if local_unauth:
            score = 2 if local_strong else 1
            if best is None or score > best[0]:
                best = (score, sig, matched_probe, local_evidence, auth_seen,
                        local_scheme or "http")
            # keep scanning other candidate sigs only if low confidence
            if local_strong:
                break
        elif (protected is None
              and any(e["result"] == "auth-required" for e in local_evidence)):
            protected = (sig, local_evidence, local_auth_scheme or "http")

    if best is not None:
        score, sig, matched_probe, local_evidence, sig_auth_seen, answ_scheme = best
        finding["service"] = sig["service"]
        finding["vendor"] = sig.get("vendor", "")
        finding["category"] = sig.get("category", "unknown")
        finding["evidence"] = local_evidence
        finding["notes"] = sig.get("notes", "")
        finding["confidence"] = "high" if score == 2 else "medium"
        if sig_auth_seen and not any(e["result"] == "match" for e in local_evidence):
            finding["auth"] = "required"
            finding["severity"] = "info"
        else:
            finding["auth"] = "none"
            finding["severity"] = sig.get("severity_noauth", "high")
        base = "{}://{}:{}".format(answ_scheme, host, port)
        finding["commands"] = verify_commands(
            host, port, schemes, timeout, limiter, sig.get("commands", []),
            base, path_cache, verify)
        finding["endpoints"] = discover_endpoints(
            host, port, schemes, timeout, limiter, sig, path_cache, verify,
            evidence=local_evidence)
        return finding

    # --- no signature matched: fall back to generic OpenAI probe ---
    gp = SIG.GENERIC_PROBE
    probe = {"path": gp["path"], "match": gp["match"]}
    resp = run_probe(host, port, schemes, timeout, limiter, probe)
    if resp is not None:
        jdata = parse_json(resp["body"])
        if match_all(probe["match"], resp["status"], resp["headers"], resp["body"], jdata):
            base = "{}://{}:{}".format(resp["scheme"], host, port)
            return {
                "host": host, "port": port,
                "service": gp["service"], "vendor": "", "category": gp["category"],
                "auth": "none", "confidence": "high",
                "severity": gp["severity_noauth"],
                "evidence": [{"path": resp["path"], "status": resp["status"],
                              "result": "match",
                              "snippet": evidence_snippet(resp["body"], "data")}],
                "commands": verify_commands(host, port, schemes, timeout, limiter,
                                            gp["commands"], base, path_cache, verify),
                "endpoints": discover_endpoints(
                    host, port, schemes, timeout, limiter, gp, path_cache, verify,
                    evidence=[{"path": resp["path"], "status": resp["status"],
                               "result": "match"}]),
                "notes": gp["notes"],
            }
        # known service present but authentication is enforced
        if protected is not None:
            psig, pev, psch = protected
            return {
                "host": host, "port": port,
                "service": psig["service"], "vendor": psig.get("vendor", ""),
                "category": psig.get("category", "unknown"),
                "auth": "required", "confidence": "medium", "severity": "info",
                "evidence": pev,
                "commands": verify_commands(
                    host, port, schemes, timeout, limiter, psig.get("commands", []),
                    "{}://{}:{}".format(psch, host, port), path_cache, verify),
                "endpoints": discover_endpoints(
                    host, port, schemes, timeout, limiter, psig, path_cache, verify,
                    evidence=pev),
                "notes": (psig.get("notes", "") +
                          "  [service detected but authentication is enforced]").strip(),
            }
        # open port but unidentified
        return {
            "host": host, "port": port,
            "service": "open-port (unidentified)", "vendor": "", "category": "unknown",
            "auth": "unknown", "confidence": "low", "severity": "info",
            "evidence": [{"path": resp["path"], "status": resp["status"],
                          "result": "banner",
                          "snippet": (get_header(resp["headers"], "server") or "")[:120]}],
            "commands": [],
            "endpoints": discover_endpoints(host, port, schemes, timeout, limiter,
                                            None, path_cache, verify),
            "notes": "TCP open; no known AI/agent fingerprint matched.",
        }

    if protected is not None:
        psig, pev, psch = protected
        return {
            "host": host, "port": port,
            "service": psig["service"], "vendor": psig.get("vendor", ""),
            "category": psig.get("category", "unknown"),
            "auth": "required", "confidence": "medium", "severity": "info",
            "evidence": pev,
            "commands": verify_commands(
                host, port, schemes, timeout, limiter, psig.get("commands", []),
                "{}://{}:{}".format(psch, host, port), path_cache, verify),
            "endpoints": discover_endpoints(
                host, port, schemes, timeout, limiter, psig, path_cache, verify,
                evidence=pev),
            "notes": (psig.get("notes", "") +
                      "  [service detected but authentication is enforced]").strip(),
        }

    return finding  # TCP open but no HTTP response


# ----------------------------- targets ------------------------------------
def _ipv4_range_parts(raw):
    """Return (start_str, end_str) if `raw` looks like an IPv4 range, else None.

    Accepts both '10.0.0.1-10.0.0.50' (explicit end) and '10.0.0.1-50'
    (last-octet shorthand). Rejects anything containing letters so hostnames
    such as 'web-01.example.com' are not misread as ranges.
    """
    if "-" not in raw or any(ch.isalpha() for ch in raw):
        return None
    left, _, right = raw.partition("-")
    left, right = left.strip(), right.strip()
    if not left or not right:
        return None
    try:
        ipaddress.IPv4Address(left)
    except ValueError:
        return None
    return left, right


def parse_targets(items, max_hosts, force):
    hosts = []
    for raw in items:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False) if "/" in raw else None
        except ValueError:
            net = None
        range_parts = _ipv4_range_parts(raw)
        if net is not None:
            n = net.num_addresses
            if n > max_hosts and not force:
                sys.stderr.write(
                    "[!] Skipping {} ({} hosts > cap {}). Use --force to override.\n"
                    .format(raw, n, max_hosts))
                continue
            for ip in net.hosts() if n > 2 else [net.network_address]:
                hosts.append(str(ip))
        elif range_parts is not None:
            start_s, end_s = range_parts
            try:
                start = ipaddress.IPv4Address(start_s)
                if "." in end_s:
                    end = ipaddress.IPv4Address(end_s)
                else:
                    end = ipaddress.IPv4Address(
                        ".".join(start_s.split(".")[:3] + [end_s]))
                if int(end) < int(start):
                    raise ValueError("end < start")
                count = int(end) - int(start) + 1
                if count > max_hosts and not force:
                    sys.stderr.write(
                        "[!] Skipping range {} ({} hosts > cap {}). "
                        "Use --force to override.\n".format(raw, count, max_hosts))
                else:
                    for cur in range(int(start), int(end) + 1):
                        hosts.append(str(ipaddress.IPv4Address(cur)))
            except ValueError:
                sys.stderr.write("[!] Bad IP range: {}\n".format(raw))
        else:
            # hostname or single IP -> resolve
            try:
                infos = socket.getaddrinfo(raw, None)
                addrs = sorted({i[4][0] for i in infos})
                hosts.extend(addrs if addrs else [raw])
            except socket.gaierror:
                sys.stderr.write("[!] Could not resolve {}\n".format(raw))
    # de-dup, preserve order
    seen = set()
    out = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def load_targets(args):
    items = []
    if args.target:
        for t in args.target:
            items.extend(t.split(","))
    if args.targets:
        with open(args.targets) as fh:
            items.extend(fh.read().splitlines())
    return items


# ----------------------------- reporting ----------------------------------
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def render_console(findings, started, elapsed, ok_targets, list_endpoints=True,
                   only_2xx=False):
    C = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
         "low": "\033[36m", "info": "\033[90m", "reset": "\033[0m",
         "b": "\033[1m", "g": "\033[32m"}
    print("\n" + "=" * 78)
    print("{}EXPOSED AI/AGENT SERVICES{}".format(C["b"], C["reset"]))
    print("=" * 78)
    if not findings:
        print("No AI/agent services found. ({}/{} targets responded)".format(
            ok_targets, started))
        return
    findings_sorted = sorted(
        findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["host"], f["port"]))
    unauth = [f for f in findings_sorted if f["auth"] == "none"]
    print("Targets scanned : {}".format(started))
    print("Open/identified : {}".format(len(findings_sorted)))
    print("NO-AUTH exposed : {}  <-- action required".format(len(unauth)))
    print("-" * 78)
    for f in findings_sorted:
        col = C.get(f["severity"], "")
        tag = {"none": "NO-AUTH!", "required": "auth", "unknown": "?"}[f["auth"]]
        all_eps = f.get("endpoints") or []
        if only_2xx:
            n2 = len([e for e in all_eps
                      if e.get("status") and 200 <= e["status"] < 300])
            ep_lbl = "{}/{} endpoints (2xx)".format(n2, len(all_eps))
        else:
            ep_lbl = "{} endpoints".format(len(all_eps))
        print("{col}{tag:<8}{reset} {bold}{host}:{port}{reset}  "
              "{bold}{svc}{reset} [{sev}] {ep_lbl}".format(
                  col=col, tag=tag, reset=C["reset"], bold=C["b"],
                  host=f["host"], port=f["port"], svc=f["service"],
                  sev=f["severity"], ep_lbl=ep_lbl))
        for ev in f["evidence"][:3]:
            print("           {} {} -> {} {}".format(
                ev["path"], ev["status"], ev["result"],
                ("| " + ev["snippet"]) if ev.get("snippet") else ""))
        eps = f.get("endpoints") or []
        if only_2xx:
            eps = [e for e in eps
                   if e.get("status") and 200 <= e["status"] < 300]
        if list_endpoints and eps:
            cap = 60
            for e in eps[:cap]:
                line = "           {:<4} {:<38} {:<4}".format(
                    e["method"], e["path"], e.get("status") or "-")
                if e.get("snippet"):
                    line += " " + e["snippet"]
                print(line)
            if len(eps) > cap:
                print("           ... +{} more endpoint(s) — see --md / --json"
                      .format(len(eps) - cap))
    print("-" * 78)
    print("elapsed {:.1f}s".format(elapsed))


def render_markdown(findings, started, elapsed, ports, targets_count, args):
    L = []
    L.append("# AgentScan — Exposed AI / Agent Services Report\n")
    L.append("- **Date:** {}".format(datetime.now().isoformat(timespec="seconds")))
    L.append("- **Targets provided:** {} ({} resolved host(s))".format(
        targets_count, started))
    L.append("- **Ports:** {}".format(", ".join(str(p) for p in ports)))
    L.append("- **Elapsed:** {:.1f}s".format(elapsed))
    L.append("- **Scope authorization:** confirmed by operator (`--authorized`)\n")

    unauth = [f for f in findings if f["auth"] == "none"]
    L.append("## Summary\n")
    L.append("| Severity | Count |")
    L.append("|---|---|")
    for sev in ("critical", "high", "medium", "low", "info"):
        n = len([f for f in findings if f["severity"] == sev])
        if n:
            L.append("| {} | {} |".format(sev, n))
    L.append("| **unauthenticated (auth=none)** | **{}** |\n".format(len(unauth)))

    if not findings:
        L.append("No AI/agent services detected.\n")
        return "\n".join(L)

    L.append("## Findings\n")
    for f in sorted(findings, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                             x["host"], x["port"])):
        L.append("### {} — {}:{}".format(f["service"], f["host"], f["port"]))
        L.append("- **Severity:** {}".format(f["severity"]))
        L.append("- **Authentication:** {}".format(f["auth"]))
        L.append("- **Confidence:** {}".format(f["confidence"]))
        L.append("- **Category:** {}".format(f["category"]))
        if f.get("vendor"):
            L.append("- **Vendor:** {}".format(f["vendor"]))
        if f.get("notes"):
            L.append("- **Notes:** {}".format(f["notes"]))
        L.append("")
        if f["evidence"]:
            L.append("**Evidence**\n")
            L.append("| Path | Status | Result | Snippet |")
            L.append("|---|---|---|---|")
            for ev in f["evidence"]:
                snip = (ev.get("snippet") or "").replace("|", "\\|")[:160]
                L.append("| {} | {} | {} | `{}` |".format(
                    ev["path"], ev["status"], ev["result"], snip))
            L.append("")
        eps = f.get("endpoints") or []
        if getattr(args, "only_2xx", False):
            eps = [e for e in eps
                   if e.get("status") and 200 <= e["status"] < 300]
        if eps:
            L.append("**API endpoints exposed — {} ({} via OpenAPI{})**\n".format(
                len(eps),
                len([e for e in eps if e["source"] == "openapi"]),
                ", 2xx only" if getattr(args, "only_2xx", False) else ""))
            L.append("| Method | Path | HTTP | Source | Response snippet | Description |")
            L.append("|---|---|---|---|---|---|")
            for e in eps[:80]:
                snip = (e.get("snippet") or "").replace("|", "\\|")[:70]
                L.append("| {} | `{}` | {} | {} | `{}` | {} |".format(
                    e["method"], e["path"], e.get("status") or "-", e["source"],
                    snip, (e.get("description") or "").replace("|", "\\|")[:50]))
            L.append("")
        if f["commands"]:
            L.append("**Live API endpoints — read-only commands (verified on this target)**\n")
            L.append("```bash")
            for c in f["commands"]:
                st = c.get("status")
                label = ("{} (HTTP {})".format(c["description"], st)
                         if st else c["description"])
                L.append("# {}".format(label))
                L.append(c["command"])
            L.append("```\n")
    L.append("\n---\n_Generated by AgentScan. Read-only reconnaissance — "
             "no destructive or write actions were performed._\n")
    return "\n".join(L)


# --------------------- CyberStrike integration ----------------------------
CYBER_TAGS = {
    "llm-inference": ["active-recon", "technology", "api-security"],
    "agent-platform": ["active-recon", "technology", "authz-testing"],
    "web-ui": ["active-recon", "technology"],
    "automation": ["active-recon", "technology", "authz-testing"],
    "mcp": ["active-recon", "technology", "api-security"],
    "notebook": ["active-recon", "technology"],
    "unknown": ["active-recon"],
}
CYBER_TARGET_CLASS = {
    "llm-inference": "llm",
    "agent-platform": "authz",
    "automation": "authz",
    "mcp": "ssrf",
    "notebook": "file-attacks",
    "web-ui": "authz",
    "unknown": "",
}
IMPACT = {
    "llm-inference": "Unauthenticated access to the inference API lets an attacker consume GPU/compute budget, enumerate and extract served models, and — where provider keys are proxied (e.g. LiteLLM) — abuse upstream LLM credentials.",
    "agent-platform": "Agent platforms hold prompt/tool definitions and provider API keys; unauthenticated access can leak secrets and invoke tools, which commonly leads to server-side request forgery or code execution.",
    "web-ui": "Any network user can drive the AI web UI, consuming the operator's model budget and potentially exposing conversation history and connected credentials.",
    "automation": "Automation instances store workflow definitions and credential references; unauthenticated read exposes logic and ingested data, and unauthenticated write can trigger arbitrary workflows.",
    "mcp": "An unauthenticated MCP server discloses its full tool list and can be driven to perform those tools' actions (filesystem, HTTP, database) on the host.",
    "notebook": "A notebook server without a token grants interactive code execution as the notebook user — equivalent to remote code execution.",
    "unknown": "The service is reachable without authentication, exposing its full functionality to any network peer.",
}
RECO = {
    "llm-inference": "Require an API key (e.g. --api-key on vLLM/LiteLLM, or an authenticating reverse proxy) and bind the service to localhost/private interfaces only.",
    "agent-platform": "Enable the platform's built-in authentication (or front it with an auth proxy), set a strong admin credential, and restrict network exposure to trusted networks.",
    "web-ui": "Enable authentication on the UI (or place it behind an SSO/auth proxy) and do not expose it to the public internet.",
    "automation": "Enable user management and authentication, restrict the /rest/* API, and never expose the instance without auth.",
    "mcp": "Require an authentication token on the MCP transport and bind to localhost; do not expose MCP servers directly to untrusted networks.",
    "notebook": "Set a strong Jupyter token/password immediately and bind to localhost or an authenticated gateway; treat any exposure as an incident.",
    "unknown": "Identify the service and enforce authentication before exposing it to untrusted networks.",
}


def _poc_block(f):
    lines = []
    for c in f.get("commands", [])[:6]:
        lines.append("# {}".format(c["description"]))
        lines.append(c["command"])
    if not lines:
        ev = f["evidence"][0] if f["evidence"] else {"path": "/"}
        lines = ["curl -s http://{}:{}{}".format(f["host"], f["port"], ev["path"])]
    return "\n".join(lines)


def to_cyberstrike(findings, hosts_scanned, ports):
    """Build payloads matching the CyberStrike add_intel / report_vulnerability
    schemas so the orchestrator can ingest them directly."""
    intel, vulns = [], []
    for f in findings:
        ev_txt = "; ".join(
            "{} {} -> {} {}".format(e["path"], e["status"], e["result"],
                                    (e.get("snippet") or "")[:120])
            for e in f["evidence"][:4])
        ep_list = ", ".join("{} {}".format(e["method"], e["path"])
                            for e in (f.get("endpoints") or [])[:15])
        detail = ("{} on {}:{} | auth={} confidence={} | evidence: {}".format(
            f["service"], f["host"], f["port"], f["auth"], f["confidence"], ev_txt))
        if ep_list:
            detail += " | endpoints({}): {}".format(
                len(f.get("endpoints") or []), ep_list)
        intel.append({
            "type": "endpoint",
            "title": "{} on {}:{} ({})".format(
                f["service"], f["host"], f["port"],
                "NO AUTH" if f["auth"] == "none" else f["auth"]),
            "asset": "{}:{}".format(f["host"], f["port"]),
            "severity": f["severity"],
            "detail": detail,
            "confidence_level": ("confirmed"
                                 if (f["auth"] == "none" and f["confidence"] == "high")
                                 else "high"),
            "tags": CYBER_TAGS.get(f["category"], ["active-recon"]),
            "chain_potential": (
                "Unauthenticated {} reachable; if it holds LLM provider keys or tool "
                "credentials, pivot to key exfiltration / SSRF via agent tools.".format(
                    f["service"]) if f["auth"] == "none" else ""),
            "target_class": CYBER_TARGET_CLASS.get(f["category"], ""),
        })

        if f["auth"] != "none" or f["severity"] not in ("critical", "high", "medium"):
            continue

        first = f["evidence"][0] if f["evidence"] else {"path": "/", "status": 200,
                                                        "result": "match", "snippet": ""}
        scheme = "http"
        if f.get("commands") and "://" in f["commands"][0].get("url", ""):
            scheme = f["commands"][0]["url"].split("://", 1)[0]
        endpoint = "GET {}://{}:{}{}".format(scheme, f["host"], f["port"], first["path"])
        poc = _poc_block(f)
        exc = "{} {} -> {} | {}".format(
            first["path"], first["status"], first["result"],
            (first.get("snippet") or ""))
        vulns.append({
            "severity": f["severity"],
            "title": "Unauthenticated {} exposed on {}:{}".format(
                f["service"], f["host"], f["port"]),
            "description": (
                "The {} service on {}:{} answers requests without authentication. "
                "Probe(s) {} returned HTTP {} with valid data and no auth challenge. "
                "Exposed endpoints: {}. {}"
                .format(f["service"], f["host"], f["port"],
                        ", ".join(e["path"] for e in f["evidence"][:3]),
                        first["status"], ep_list or "n/a",
                        f.get("notes", ""))).strip(),
            "endpoint": endpoint,
            "attack_vector": "other",
            "poc": poc,
            "steps_to_reproduce": (
                "1. From an authorized host, run the command(s) below.\n"
                "2. Observe valid data returned with HTTP {} and no authentication.\n\n{}"
                .format(first["status"], poc)),
            "business_impact": IMPACT.get(f["category"], IMPACT["unknown"]),
            "recommendation": RECO.get(f["category"], RECO["unknown"]),
            "cwe_id": "CWE-306",
            "vrt_category": ("Remote Code Execution" if f["category"] == "notebook"
                             else "Authentication Bypass"),
            "execution_evidence": exc,
        })
    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "hosts_scanned": hosts_scanned,
        "ports": ports,
        "intel": intel,
        "findings": vulns,
    }


# ----------------------------- main ---------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Scan authorized assets for exposed AI/agent services (no auth).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "TARGET FORMATS ACCEPTED  (for -t/--target, and for lines in the --targets file)\n"
            "  10.0.0.5                 single IP address (IPv4 or IPv6)\n"
            "  box.lab.internal         hostname (resolved via DNS, A/AAAA records)\n"
            "  10.0.0.0/24              CIDR subnet (expanded; capped by --max-hosts)\n"
            "  10.0.0.1-10.0.0.50       IP range with explicit end address\n"
            "  10.0.0.1-50              IP range, last-octet shorthand\n"
            "  commas allowed           -t 10.0.0.5,10.0.0.9\n"
            "  -t may be repeated       -t host1 -t host2\n"
            "  '#' starts a comment     when reading a --targets file\n"
            "\n"
            "PORT FORMATS ACCEPTED  (--ports)\n"
            "  auto                     built-in AI/agent port list (28 ports)\n"
            "  11434,3000,8080          comma-separated list\n"
            "  8000-8100                inclusive range\n"
            "  11434,5000-5001,8080     any mix of list + range\n"
            "\n"
            "EXAMPLES\n"
            "  agentscan.py -t 10.0.0.0/24 --authorized\n"
            "  agentscan.py -t 10.0.0.5,10.0.0.9 --ports 11434,3000 --authorized\n"
            "  agentscan.py --targets hosts.txt --authorized --out-dir ./reports\n"
        ))
    ap.add_argument("--version", action="version",
                    version="AgentScan {}".format(VERSION))
    ap.add_argument("--no-banner", dest="banner", action="store_false",
                    help="do not print the startup banner")
    ap.add_argument("-t", "--target", action="append",
                    help="target host/IP/CIDR/range (repeatable, comma-separated)")
    ap.add_argument("--targets", help="file with one target per line")
    ap.add_argument("--ports", default="auto",
                    help="'auto' (AI/agent default ports), a list '11434,3000..', "
                         "or a range '1-10000'")
    ap.add_argument("--scheme", default="auto", choices=["auto", "http", "https", "both"],
                    help="transport scheme (default auto)")
    ap.add_argument("--workers", type=int, default=100, help="concurrent workers")
    ap.add_argument("--rate", type=float, default=50.0,
                    help="max requests/second globally (default 50)")
    ap.add_argument("--timeout", type=float, default=4.0, help="socket timeout seconds")
    ap.add_argument("--max-hosts", type=int, default=4096,
                    help="safety cap on expanded hosts; larger CIDRs are skipped "
                         "unless --force (default 4096)")
    ap.add_argument("--aggressive", action="store_true",
                    help="try ALL signatures on every open port (more requests)")
    ap.add_argument("--no-verify-commands", dest="verify_commands",
                    action="store_false",
                    help="do NOT probe command endpoints; list the full static "
                         "command set instead of only the live ones")
    ap.add_argument("--no-list-endpoints", dest="list_endpoints",
                    action="store_false",
                    help="do not print the enumerated endpoint list in the console "
                         "(they are still written to --md / --json)")
    ap.add_argument("--all-status", dest="all_status", action="store_true",
                    help="show ALL endpoint statuses (incl. 401/403/405). "
                         "Default: only 2xx endpoints are displayed")
    ap.add_argument("--sweep", default="aggressive",
                    choices=["off", "normal", "aggressive"],
                    help="brute-force common API sub-paths for detected services "
                         "that have no OpenAPI spec (default: aggressive)")
    ap.add_argument("--sweep-budget", dest="sweep_budget", type=int,
                    help="max sweep requests per service (default: 120 normal, "
                         "700 aggressive); raise for a deeper sweep")
    ap.add_argument("--json", dest="json_out", help="write findings JSON to PATH")
    ap.add_argument("--md", dest="md_out", help="write Markdown report to PATH")
    ap.add_argument("--cyberstrike", dest="cyber_out",
                    help="write CyberStrike payloads (intel[] + findings[]) to PATH")
    ap.add_argument("--out-dir", help="auto-name json/md/cyberstrike outputs in this directory")
    ap.add_argument("--dump-response", dest="dump_response", action="store_true",
                    help="save the body of every 2xx response (one file per endpoint) "
                         "to --dump-dir, to inspect what each service returns")
    ap.add_argument("--dump-dir", dest="dump_dir",
                    help="directory for --dump-response output "
                         "(default: OUT_DIR/dump, else ./agentscan-dump)")
    ap.add_argument("--force", action="store_true", help="ignore --max-hosts cap")
    ap.add_argument("--authorized", action="store_true",
                    help="REQUIRED: confirm you are authorized to test these assets")
    args = ap.parse_args()

    if args.banner:
        print(BANNER)

    if not args.authorized:
        sys.stderr.write(
            "\n[!] Refusing to run: you must pass --authorized to confirm you own "
            "or have written permission to test the supplied targets.\n")
        sys.exit(2)

    # default: display only 2xx endpoints; --all-status opts out
    args.only_2xx = not args.all_status

    items = load_targets(args)
    if not items:
        ap.error("no targets supplied (-t/--target or --targets)")
    targets_provided = [i for i in items if i.strip() and not i.strip().startswith("#")]

    # resolve targets
    hosts = parse_targets(items, args.max_hosts, args.force)
    if not hosts:
        sys.stderr.write("[!] No usable targets after parsing/resolution.\n")
        sys.exit(1)

    # ports
    if args.ports == "auto":
        ports = SIG.ALL_PORTS
    else:
        ports = []
        for part in args.ports.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            else:
                ports.append(int(part))
    ports = sorted(set(ports))

    schemes = {"auto": ["http", "https"], "both": ["http", "https"],
               "http": ["http"], "https": ["https"]}[args.scheme]

    print("[*] AgentScan starting")
    print("    hosts   : {} (from {} target spec(s))".format(len(hosts), len(targets_provided)))
    print("    ports   : {} ({})".format(len(ports), "auto" if args.ports == "auto" else args.ports))
    print("    rate    : {}/s   workers: {}   timeout: {}s".format(
        args.rate, args.workers, args.timeout))
    if args.aggressive:
        print("    mode    : AGGRESSIVE (all signatures on all ports)")
    print("    commands: {}".format(
        "verify endpoints, show only the live ones"
        if args.verify_commands else "static list (verification disabled)"))
    SWEEP["mode"] = args.sweep if args.verify_commands else "off"
    SWEEP["budget"] = args.sweep_budget
    if SWEEP["mode"] != "off":
        print("    sweep   : {} path sweep for services without OpenAPI{}".format(
            SWEEP["mode"],
            " (budget={})".format(args.sweep_budget) if args.sweep_budget else ""))
    print("    show    : {}".format(
        "ALL statuses" if args.all_status
        else "2xx endpoints only (use --all-status for 401/403/405)"))

    if args.dump_response:
        dump_dir = args.dump_dir or (
            os.path.join(args.out_dir, "dump") if args.out_dir else "agentscan-dump")
        DUMP["enabled"] = True
        DUMP["dir"] = dump_dir
        print("    dump    : 2xx response bodies -> {}".format(dump_dir))

    limiter = RateLimiter(args.rate)
    tasks = [(h, p) for h in hosts for p in ports]
    print("    probes  : {} (host,port) pairs".format(len(tasks)))
    if len(tasks) > 100000:
        sys.stderr.write(
            "[!] Large scan ({} probes). Narrow --ports/--targets to reduce "
            "time and load (Ctrl-C to abort).\n".format(len(tasks)))

    findings = []
    open_ports = 0
    began = time.monotonic()
    lock = threading.Lock()
    done = 0

    def work(hp):
        h, p = hp
        return probe_target(h, p, schemes, args.timeout, limiter, args.aggressive,
                            args.verify_commands)

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(work, t): t for t in tasks}
        for fut in cf.as_completed(futs):
            try:
                res = fut.result()
            except Exception:
                res = None
            with lock:
                done += 1
                if res:
                    open_ports += 1
                    findings.append(res)
            if done % 500 == 0:
                print("    ... {}/{} probed, {} identified".format(
                    done, len(tasks), open_ports))

    elapsed = time.monotonic() - began
    render_console(findings, len(hosts), elapsed, open_ports,
                   list_endpoints=args.list_endpoints, only_2xx=args.only_2xx)

    # outputs
    out_json = args.json_out
    out_md = args.md_out
    out_cyber = args.cyber_out
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_json = out_json or os.path.join(args.out_dir, "agentscan-{}.json".format(ts))
        out_md = out_md or os.path.join(args.out_dir, "agentscan-{}.md".format(ts))
        out_cyber = out_cyber or os.path.join(
            args.out_dir, "agentscan-{}.cyberstrike.json".format(ts))

    if out_json:
        with open(out_json, "w") as fh:
            json.dump({
                "generated": datetime.now().isoformat(timespec="seconds"),
                "hosts_scanned": len(hosts),
                "ports": ports,
                "findings": findings,
                "summary": {
                    "identified": len(findings),
                    "unauthenticated": len([f for f in findings if f["auth"] == "none"]),
                    "by_severity": {
                        s: len([f for f in findings if f["severity"] == s])
                        for s in ("critical", "high", "medium", "low", "info")
                    },
                },
            }, fh, indent=2)
        print("[+] JSON  -> {}".format(out_json))
    if out_md:
        with open(out_md, "w") as fh:
            fh.write(render_markdown(findings, len(hosts), elapsed, ports,
                                     len(targets_provided), args))
        print("[+] MD    -> {}".format(out_md))
    if out_cyber:
        payload = to_cyberstrike(findings, len(hosts), ports)
        with open(out_cyber, "w") as fh:
            json.dump(payload, fh, indent=2)
        print("[+] CYBER -> {} ({} intel, {} findings)".format(
            out_cyber, len(payload["intel"]), len(payload["findings"])))

    return 0
