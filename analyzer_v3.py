#!/usr/bin/env python3
"""
Huawei Firewall Log Analyzer  v3.0
────────────────────────────────────────────────────────────────────────────
This version fixes six data-correctness bugs found in v2 by cross-checking
the parser's assumptions against the real log files line-by-line.

  BUG-5  [CRITICAL] Denied / blocked events were counted TWICE.
         Every blocked connection produces BOTH a top-level POLICY/POLICYDENY
         line AND a SECLOG/PACKET_DENY (or SECLOG/SESSION_TEARDOWN with a
         BLOCK_ policy + tcp-rst) line for the SAME event. v2 incremented its
         deny counter on every line that matched "POLICYDENY|PACKET_DENY",
         so it counted most blocks ~2x (header "Denied" stat, per-app
         deny_count, per-PC blocked-attempt tags were all roughly double).
         FIX: only SECLOG lines are used for accounting. Top-level POLICY
         lines are no longer counted at all (they're only used for the new
         MAC-tracking feature, see below).

  BUG-6  [CRITICAL] DNS connection counts were inflated ~2x.
         v2's RULE_APP_MAP turned empty-app POLICYPERMIT lines with
         rule-name=policy_dns_filter into a synthetic zero-byte "DNS" permit
         event. Since the *real* DNS event (the SECLOG/SESSION_TEARDOWN line,
         which already carries ApplicationName=DNS and the real bytes) was
         also being counted, every DNS lookup was effectively logged twice.
         FIX: RULE_APP_MAP is gone entirely. DNS (and everything else) now
         comes only from the real SECLOG ApplicationName field.

  BUG-7  [CRITICAL] Session duration ignored the real connection lifetime.
         v2 used the SECLOG line's *report* timestamp (a single instant —
         when the teardown was logged) as both session start AND end, so a
         12-hour connection that produced one teardown line showed up as
         "0s duration." Conversely, several short, separate connections
         that happened to report within 10 minutes of each other got
         merged into one inflated session.
         FIX: every SECLOG line carries BeginTime=/EndTime= (real epoch UTC
         seconds marking the actual connection lifetime). v3 parses these
         directly and uses them as the authoritative basis for session
         reconstruction (gap-based merge using min(start)/max(end) to
         correctly handle overlapping connections).

  BUG-8  Blocked-connection bytes were polluting "Total Data" and the
         hourly traffic chart. A few packets are often sent before a
         block resets the connection (e.g. ~1.9 KB of TLS ClientHello on
         a DoH block before tcp-rst) — v2 counted those bytes in the PC's
         overall traffic totals even though the per-app rows correctly
         excluded them, making the PC header total not match the sum of
         its own app rows.
         FIX: bytes from denied/blocked events are excluded from
         bytes_in / bytes_out / hourly_bytes, and tracked separately as
         "bytes leaked before block" — itself a useful security metric.

  BUG-9  HTTPS-based DoH blocks were invisible. BLOCK_DOH_IPS blocks DoH by
         destination IP:port (8.8.8.8/8.8.4.4:443), so the firewall logs
         ApplicationName=HTTPS, not "dns_over_https" — these fell through
         categorize() into a generic grey OTHER row, even though they were
         genuinely blocked (confirmed: ~1.9 KB sent, ~52 B received,
         CloseReason=tcp-rst — the block IS working).
         FIX: rather than recoloring the whole HTTPS app row red (which
         would wrongly flag ordinary HTTPS browsing), every blocked
         attempt is now tracked by (PolicyName, app) so the per-PC
         "Blocked Attempts" box explicitly names which BLOCK_ rule fired
         and how many bytes leaked, regardless of the app row's color.

  BUG-10 BitTorrent traffic (ApplicationName=BT) wasn't in the RED_BLOCK
         category set (only "bittorrent"/"torrent" were), so confirmed
         P2P traffic (incl. classic port 6881/udp) displayed as grey OTHER.
         FIX: added "bt" as an exact-match keyword. Short (≤3 char)
         category keywords now require an exact match rather than a
         substring match, so 2-letter tokens like "bt" can't accidentally
         match inside unrelated app names.

NEW FEATURES:
  • Executive Summary panel — top blocked policies, bytes leaked before
    block, top bandwidth consumers, and a critical-PC count, all visible
    before scrolling into individual PC cards.
  • PC cards are now collapsible (native <details>/<summary>) — critical
    and top-bandwidth PCs auto-expand, everything else starts collapsed,
    so a 50-PC report doesn't dump 50 screens of detail at once.
  • MAC-binding anomaly detector — cheaply scans the (now otherwise-unused)
    top-level POLICY lines for source-mac=, and flags any internal IP seen
    with more than one distinct MAC address (possible spoofing / missing
    MAC binding).
  • Cross-midnight flag — sessions whose real BeginTime falls on a
    different calendar day than the report's nominal log date are marked,
    directly addressing "is the time period actually correct."
  • "Default deny (unclassified)" is now shown as its own label, distinct
    from named BLOCK_ rule hits, for PolicyName=default denies.

KEPT FROM v2:
  • UTC+5 timezone fix for SECLOG timestamps (BUG-1)
  • Pre-compiled regex patterns (BUG-3)
  • Expanded app category sets (BUG-4)
  • Windows-friendly progress bar / .bat launcher / auto-open report

Usage:
  python analyzer_v3.py  <logfile.txt>

  Or on Windows, simply drag the log file onto  run_analyzer.bat
"""

import re, os, sys, platform
from datetime import datetime, timedelta, date
from collections import defaultdict

# ─── Timezone ─────────────────────────────────────────────────────────────────
# Firewall is UTC+5. SECLOG lines (BeginTime/EndTime epoch, and the line's own
# report timestamp) are UTC → we add +5h. Top-level POLICY lines carry a
# local "time=" field already, but those lines are no longer used for
# accounting in v3 (only for MAC tracking), so this offset is all we need.
FW_UTC_OFFSET = timedelta(hours=5)
EPOCH = datetime(1970, 1, 1)

def epoch_to_local(epoch_seconds):
    return EPOCH + timedelta(seconds=epoch_seconds) + FW_UTC_OFFSET

# ─── Application Categories ───────────────────────────────────────────────────
SAFE_COMPANY = {
    # Microsoft / Office 365
    "microsoft", "microsoftteams", "ms_common", "microsoft_azure",
    "microsoft_office_365", "microsoft_powerapps", "skype", "skype_portals",
    "outlook", "onedrive", "sharepoint", "windowsupdate", "windows_update",
    "microsoft_dynamics_crm", "microsoft_store", "bing", "visualstudio",
    "office365_powerbi", "skydrive",
    # Google Workspace
    "google", "google_service", "google_api", "gmail",
    "google_docs", "google_drive", "google_play",
    # Corporate / internal tools
    "lark", "genesys", "genesys_v", "genesys_voice", "genesys_media",
    "genesys_call", "1c", "1crm",
    # Infrastructure / updates
    "ntp", "chrome_update", "akamai",
}

WORK_ALLOWED = {
    # Messaging
    "telegram", "telegram_messenger",
    "whatsapp", "whatsapp_web", "whatsapp_filetransfer",
    "wechatwork", "wechatwork_filetransfer",
    "weixin_im", "weixin_gongzhonghao",
    "tencent_common", "tencent_beacon",
    "tencentdocs", "webmail_tencent_enterprise",
    # Video conferencing
    "zoom", "webex",
    # Maps / navigation
    "yandex", "yandexmaps",
    # DNS (work-critical protocol)
    "dns",
}

RED_BLOCK = {
    # P2P / Torrents
    "bittorrent", "torrent", "bt",
    # VPN / Anonymizers
    "vpn", "openvpn", "wireguard", "nordvpn", "expressvpn",
    "hamachivpn", "protonvpn", "holaunlimitedfreevpn", "operavpn",
    "supervpn", "skyvpn", "tinyvpn", "touchvpn", "vpnlinkcontrol",
    "vpn_connect", "operamobile", "operamini",
    "tor", "proxy", "http_proxy", "socks", "dns_over_https",
    # Gaming
    "worldoftanks", "steam", "steam_game", "steam_streaming",
    "battle.net", "poki", "roblox",
    # Social media (personal / banned)
    "facebook", "instagram", "tiktok", "youtube", "youtube_kids",
    "youtube_music", "youtube_videoplay", "twitch", "rutube",
    "vk", "vkontakte", "ok.ru", "pinterest", "bilibili",
    "sina_weibo", "daum_web", "daumtvpot",
    # IPv6 tunnel (often used for circumvention)
    "teredo",
}

# ─── Pre-compiled Regex Patterns ──────────────────────────────────────────────
RE_SRC_IP    = re.compile(r'[Ss]ource[-_]?[Ii][Pp]=(\d{1,3}(?:\.\d{1,3}){3})')
RE_FW_UTC    = re.compile(r'<\d+>(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) Firewall_Huawei')
RE_APP       = re.compile(r'[Aa]pplication[-_]?[Nn]ame=([^,;.\n\r]+)')
RE_POLICY    = re.compile(r'PolicyName=([^,\s\n\r.]+)')
RE_SEND_B    = re.compile(r'SendBytes=(\d+)')
RE_RCV_B     = re.compile(r'RcvBytes=(\d+)')
RE_BEGIN     = re.compile(r'BeginTime=(\d+)')
RE_END       = re.compile(r'EndTime=(\d+)')
RE_MAC       = re.compile(r'source-mac=([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})')

TRIVIAL_MACS = {"00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF"}

SUBNET_PREFIX = "192.168.100."


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _kw_match(a, keyword_set):
    for kw in keyword_set:
        if len(kw) <= 3:
            if a == kw:
                return True
        elif kw in a:
            return True
    return False

def categorize(app):
    a = app.lower()
    if _kw_match(a, RED_BLOCK):    return ("BLOCKED", 4, "#f85149")
    if _kw_match(a, SAFE_COMPANY): return ("COMPANY", 0, "#3fb950")
    if _kw_match(a, WORK_ALLOWED): return ("WORK",    1, "#58a6ff")
    return ("OTHER", 2, "#8b949e")

def fmt_bytes(b):
    if b < 1024:          return f"{b} B"
    if b < 1_048_576:      return f"{b/1024:.1f} KB"
    if b < 1_073_741_824:  return f"{b/1_048_576:.1f} MB"
    return f"{b/1_073_741_824:.2f} GB"

def fmt_time(s):
    if s < 60:   return f"{s}s"
    if s < 3600: return f"{s//60}m {s%60:02d}s"
    return f"{s//3600}h {(s%3600)//60:02d}m"

def extract_log_date(logfile):
    """Pull a YYYY-MM-DD date out of the filename, e.g.
    '1781684141029_2026-06-15.txt' -> date(2026,6,15). Returns (label, date|None)."""
    base = os.path.splitext(os.path.basename(logfile))[0]
    m = re.search(r'(\d{4})-(\d{2})-(\d{2})', base)
    if m:
        try:
            return base, date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return base, None
    return base, None


# ─── Parser ───────────────────────────────────────────────────────────────────
def new_pc():
    return {
        "events": [],                                   # successful (non-deny) events only
        "bytes_in": 0, "bytes_out": 0,
        "hourly_bytes": defaultdict(int),
        "first": None, "last": None,
        "blocked": defaultdict(lambda: {"count": 0, "bytes": 0}),  # (policy_label, app) -> {}
        "deny_count_by_app": defaultdict(int),
        "deny_bytes_by_app": defaultdict(int),
        "blocked_bytes_total": 0,
        "total_event_count": 0,
        "macs": set(),
    }

def parse_log(filepath):
    pcs = defaultdict(new_pc)
    total_lines = 0
    seclog_lines = 0
    denied = 0
    file_size = os.path.getsize(filepath)
    bytes_read = 0
    last_dot = -1

    print(f"\n  File : {os.path.basename(filepath)}  ({fmt_bytes(file_size)})")
    print(f"  Parse: [", end="", flush=True)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            bytes_read += len(line)

            dot = bytes_read * 20 // file_size
            if dot != last_dot:
                last_dot = dot
                print("█", end="", flush=True)

            is_seclog = "SECLOG" in line

            if not is_seclog:
                # Top-level POLICY lines are no longer used for accounting
                # (BUG-5/BUG-6 fix) — only cheaply scanned for MAC info.
                if "source-mac=" in line:
                    src_m = RE_SRC_IP.search(line)
                    if src_m and src_m.group(1).startswith(SUBNET_PREFIX):
                        mac_m = RE_MAC.search(line)
                        if mac_m:
                            mac = mac_m.group(1).upper()
                            if mac not in TRIVIAL_MACS:
                                pcs[src_m.group(1)]["macs"].add(mac)
                continue

            # ── SECLOG line (SESSION_TEARDOWN or PACKET_DENY) ─────────────────
            src_m = RE_SRC_IP.search(line)
            if not src_m:
                continue
            ip = src_m.group(1)
            if not ip.startswith(SUBNET_PREFIX):
                continue
            seclog_lines += 1

            app_m = RE_APP.search(line)
            app = app_m.group(1).strip().rstrip(".,").strip() if app_m else ""
            if app in ("", "-", ".", " "):
                app = "Unknown"

            policy_m = RE_POLICY.search(line)
            policy_name = policy_m.group(1).rstrip(".,").strip() if policy_m else ""

            is_packet_deny = "PACKET_DENY" in line
            is_block_policy = policy_name.startswith("BLOCK_")
            is_deny = is_packet_deny or is_block_policy

            sb_m = RE_SEND_B.search(line)
            rb_m = RE_RCV_B.search(line)
            sb = int(sb_m.group(1)) if sb_m else 0
            rb = int(rb_m.group(1)) if rb_m else 0

            # ── Real connection lifetime (BUG-7 fix) ───────────────────────────
            begin_m = RE_BEGIN.search(line)
            end_m = RE_END.search(line)
            if begin_m and end_m:
                begin_dt = epoch_to_local(int(begin_m.group(1)))
                end_dt = epoch_to_local(int(end_m.group(1)))
                if end_dt < begin_dt:
                    end_dt = begin_dt
            else:
                fw_utc_m = RE_FW_UTC.search(line)
                if fw_utc_m:
                    try:
                        ts = datetime.strptime(fw_utc_m.group(1), "%Y-%m-%d %H:%M:%S") + FW_UTC_OFFSET
                        begin_dt = end_dt = ts
                    except Exception:
                        begin_dt = end_dt = None
                else:
                    begin_dt = end_dt = None

            pc = pcs[ip]
            pc["total_event_count"] += 1

            if begin_dt:
                if pc["first"] is None or begin_dt < pc["first"]:
                    pc["first"] = begin_dt
                if pc["last"] is None or end_dt > pc["last"]:
                    pc["last"] = end_dt

            if is_deny:
                denied += 1
                if not policy_name or policy_name.lower() == "default":
                    label = "Default deny (unclassified)"
                else:
                    label = policy_name
                entry = pc["blocked"][(label, app)]
                entry["count"] += 1
                entry["bytes"] += sb + rb
                pc["blocked_bytes_total"] += sb + rb
                pc["deny_count_by_app"][app] += 1
                pc["deny_bytes_by_app"][app] += sb + rb
            else:
                # BUG-8 fix: only successful traffic counts toward totals
                pc["bytes_in"] += rb
                pc["bytes_out"] += sb
                if begin_dt:
                    pc["hourly_bytes"][begin_dt.hour] += sb + rb
                    pc["events"].append({
                        "begin": begin_dt, "end": end_dt,
                        "app": app, "sb": sb, "rb": rb,
                    })

            mac_m = RE_MAC.search(line)
            if mac_m:
                mac = mac_m.group(1).upper()
                if mac not in TRIVIAL_MACS:
                    pc["macs"].add(mac)

    print(f"]  done.\n")
    return pcs, total_lines, seclog_lines, denied


# ─── Session reconstruction (BUG-7 fix) ────────────────────────────────────────
def merge_sessions(events):
    """events: list of {begin, end, sb, rb} using REAL connection lifetimes.
    Gap-based merge (<=600s between one connection's end and the next one's
    start) using max() for end so overlapping/nested connections are handled
    correctly."""
    events_sorted = sorted(events, key=lambda x: x["begin"])
    sessions = []
    cur = None
    for e in events_sorted:
        if cur is None:
            cur = {"start": e["begin"], "end": e["end"],
                   "sb": e["sb"], "rb": e["rb"], "cnt": 1}
        else:
            gap = (e["begin"] - cur["end"]).total_seconds()
            if gap <= 600:
                if e["end"] > cur["end"]:
                    cur["end"] = e["end"]
                cur["sb"] += e["sb"]
                cur["rb"] += e["rb"]
                cur["cnt"] += 1
            else:
                sessions.append(cur)
                cur = {"start": e["begin"], "end": e["end"],
                       "sb": e["sb"], "rb": e["rb"], "cnt": 1}
    if cur:
        sessions.append(cur)
    return sessions


def group_by_app(pc, log_date_obj):
    by_app = defaultdict(list)
    for e in pc["events"]:
        by_app[e["app"]].append(e)

    all_apps = set(by_app.keys()) | set(pc["deny_count_by_app"].keys())

    result = []
    for app in all_apps:
        cat, risk, color = categorize(app)
        sessions = merge_sessions(by_app.get(app, []))

        for s in sessions:
            s["cross_midnight"] = bool(log_date_obj and s["start"].date() != log_date_obj)

        deny_count = pc["deny_count_by_app"].get(app, 0)
        deny_bytes = pc["deny_bytes_by_app"].get(app, 0)
        total_sb = sum(s["sb"] for s in sessions)
        total_rb = sum(s["rb"] for s in sessions)

        if not sessions and deny_count == 0:
            continue

        result.append({
            "app": app, "cat": cat, "risk": risk, "color": color,
            "sessions": sessions, "deny_count": deny_count, "deny_bytes": deny_bytes,
            "total_sb": total_sb, "total_rb": total_rb,
            "total_cnt": sum(s["cnt"] for s in sessions) + deny_count,
        })

    return sorted(result, key=lambda x: x["risk"], reverse=True)


# ─── Build HTML Report ────────────────────────────────────────────────────────
def build_html(pcs, total_lines, seclog_lines, denied, log_date, log_date_obj):
    # Drop any IP that only ever showed up via a stray top-level MAC scan
    # with zero real SECLOG activity (defensive — shouldn't normally happen).
    active_pcs = {ip: v for ip, v in pcs.items() if v["total_event_count"] > 0}

    sorted_pcs = sorted(active_pcs.items(),
                        key=lambda x: x[1]["bytes_in"] + x[1]["bytes_out"],
                        reverse=True)

    total_pcs   = len(sorted_pcs)
    total_bytes = sum(v["bytes_in"] + v["bytes_out"] for _, v in sorted_pcs)
    total_blocked_bytes = sum(v["blocked_bytes_total"] for _, v in sorted_pcs)
    blocked_pcs = sum(1 for _, v in sorted_pcs if v["blocked"])

    # ── Pre-compute per-PC app groupings once (used for summary + cards) ──────
    pc_apps = {ip: group_by_app(v, log_date_obj) for ip, v in sorted_pcs}

    # ── MAC anomalies ──────────────────────────────────────────────────────
    mac_anomalies = [(ip, v["macs"]) for ip, v in sorted_pcs if len(v["macs"]) > 1]

    # ── Global hourly chart data ─────────────────────────────────────────────
    global_hourly = defaultdict(int)
    for _, v in sorted_pcs:
        for h, b in v["hourly_bytes"].items():
            global_hourly[h] += b
    max_hourly = max(global_hourly.values(), default=1)

    hourly_bars = ""
    for h in range(24):
        b = global_hourly.get(h, 0)
        pct = int(b * 100 / max_hourly) if max_hourly else 0
        hourly_bars += (
            f'<div class="hbar-col" title="{h:02d}:00 — {fmt_bytes(b)}">'
            f'<div class="hbar-fill" style="height:{pct}%"></div>'
            f'<div class="hbar-lbl">{h:02d}</div></div>'
        )

    # ── Executive summary aggregation ──────────────────────────────────────
    global_blocked = defaultdict(lambda: {"count": 0, "bytes": 0})
    for _, v in sorted_pcs:
        for (label, app), data in v["blocked"].items():
            g = global_blocked[(label, app)]
            g["count"] += data["count"]
            g["bytes"] += data["bytes"]
    top_blocked = sorted(global_blocked.items(), key=lambda x: x[1]["count"], reverse=True)[:8]

    critical_pcs = [(ip, max((a["risk"] for a in pc_apps[ip]), default=0)) for ip, _ in sorted_pcs]
    critical_count = sum(1 for _, r in critical_pcs if r == 4)
    top_bandwidth = sorted_pcs[:5]

    def _blocked_row(label, app, data):
        leaked_suffix = f' · {fmt_bytes(data["bytes"])} leaked' if data["bytes"] else ""
        return (f'<div class="exec-row"><span class="exec-name">{label} '
                f'<span class="exec-sub">→ {app}</span></span>'
                f'<span class="exec-val">{data["count"]:,} blocked{leaked_suffix}</span></div>')

    top_blocked_rows = "".join(
        _blocked_row(label, app, data) for (label, app), data in top_blocked
    ) or '<div class="exec-empty">No blocked attempts in this log.</div>'

    top_bw_rows = "".join(
        f'<div class="exec-row"><span class="exec-name">{ip}</span>'
        f'<span class="exec-val">{fmt_bytes(v["bytes_in"]+v["bytes_out"])}</span></div>'
        for ip, v in top_bandwidth
    ) or '<div class="exec-empty">No traffic recorded.</div>'

    mac_rows = "".join(
        f'<div class="exec-row"><span class="exec-name">{ip}</span>'
        f'<span class="exec-val" style="color:#f85149">{len(macs)} distinct MACs</span></div>'
        for ip, macs in mac_anomalies
    ) or '<div class="exec-empty">No multi-MAC anomalies detected.</div>'

    # ── Per-PC HTML ──────────────────────────────────────────────────────────
    # Auto-expand: critical-risk PCs and the top-3 bandwidth consumers.
    top3_ips = {ip for ip, _ in sorted_pcs[:3]}

    pc_html = ""
    for ip, v in sorted_pcs:
        apps = pc_apps[ip]
        risk_level = max((a["risk"] for a in apps), default=0)
        risk_color = {0: "#3fb950", 1: "#58a6ff",
                      2: "#8b949e", 4: "#f85149"}.get(risk_level, "#8b949e")
        risk_name  = {0: "SAFE", 1: "WORK",
                      2: "OTHER", 4: "CRITICAL"}.get(risk_level, "OTHER")

        total_b = v["bytes_in"] + v["bytes_out"]
        first   = v["first"].strftime("%H:%M:%S") if v["first"] else "—"
        last    = v["last"].strftime("%H:%M:%S")  if v["last"]  else "—"

        mac_badge = ""
        if len(v["macs"]) > 1:
            mac_badge = (f'<span class="badge" style="background:#f8514922;'
                         f'color:#f85149;border:1px solid #f8514955" '
                         f'title="{", ".join(sorted(v["macs"]))}">⚠ {len(v["macs"])} MACs</span>')

        # App activity rows
        app_html = ""
        for a in apps:
            sess_rows = ""
            for s in a["sessions"]:
                dur = int((s["end"] - s["start"]).total_seconds())
                midnight_flag = ' <span title="Started previous day" style="color:#d29922">⚠</span>' if s.get("cross_midnight") else ""
                sess_rows += (
                    f'<tr>'
                    f'<td>{s["start"].strftime("%H:%M")}{midnight_flag}</td>'
                    f'<td>{s["end"].strftime("%H:%M")}</td>'
                    f'<td>{fmt_time(dur)}</td>'
                    f'<td>↑{fmt_bytes(s["sb"])} ↓{fmt_bytes(s["rb"])}</td>'
                    f'<td>{s["cnt"]}</td>'
                    f'</tr>'
                )

            deny_note = ""
            if a["deny_count"] > 0:
                leaked = f' — {fmt_bytes(a["deny_bytes"])} sent before block' if a["deny_bytes"] else ""
                deny_note = (
                    f'<div class="deny-note">'
                    f'🚫 {a["deny_count"]} blocked attempt'
                    f'{"s" if a["deny_count"] != 1 else ""}{leaked}</div>'
                )

            body = ""
            if a["sessions"]:
                body = (
                    f'<table class="sess-tbl">'
                    f'<tr class="sess-hdr">'
                    f'<td>Start</td><td>End</td>'
                    f'<td>Duration</td><td>Data</td><td>Conn</td></tr>'
                    f'{sess_rows}</table>'
                )
            elif a["deny_count"] > 0:
                body = '<div class="no-sess">No successful sessions — all attempts blocked</div>'

            app_html += (
                f'<div class="app-row" style="border-left:3px solid {a["color"]};'
                f'background:{a["color"]}0d">'
                f'<div class="app-name" style="color:{a["color"]}">'
                f'{a["app"]} <span class="app-cat">({a["cat"]})</span></div>'
                f'<div class="app-stats">'
                f'{a["total_cnt"]} conn · ↑{fmt_bytes(a["total_sb"])} ↓{fmt_bytes(a["total_rb"])}'
                f'</div>'
                f'{deny_note}{body}'
                f'</div>'
            )

        # Blocked summary — now keyed by (policy, app)
        blocked_html = ""
        if v["blocked"]:
            def _block_tag(label, app, data):
                bytes_suffix = f' ({fmt_bytes(data["bytes"])})' if data["bytes"] else ""
                return f'<span class="block-tag">{label} → {app}: <b>{data["count"]}</b>{bytes_suffix}</span>'

            tags = "".join(
                _block_tag(label, app, data)
                for (label, app), data in sorted(v["blocked"].items(),
                                                  key=lambda x: x[1]["count"], reverse=True)
            )
            blocked_html = (
                f'<div class="block-box">'
                f'<div class="block-title">🚫 Blocked Attempts</div>'
                f'{tags}</div>'
            )

        open_attr = " open" if (risk_level == 4 or ip in top3_ips) else ""

        pc_html += (
            f'<details class="pc-card" data-ip="{ip}" data-risk="{risk_level}"{open_attr}>'
            f'<summary class="pc-head" style="border-left:4px solid {risk_color}">'
            f'<div class="pc-top">'
            f'<span class="pc-ip">{ip}</span>'
            f'<span class="badge" style="background:{risk_color}22;'
            f'color:{risk_color};border:1px solid {risk_color}55">{risk_name}</span>'
            f'{mac_badge}'
            f'</div>'
            f'<div class="pc-meta">'
            f'Active: <b>{first}</b> → <b>{last}</b>'
            f'&nbsp;·&nbsp;Data: <b>{fmt_bytes(total_b)}</b>'
            f' (↑{fmt_bytes(v["bytes_out"])} ↓{fmt_bytes(v["bytes_in"])})'
            f'&nbsp;·&nbsp;<b>{v["total_event_count"]:,}</b> events'
            + (f'&nbsp;·&nbsp;<span style="color:#f85149">'
               f'<b>{sum(d["count"] for d in v["blocked"].values())}</b> blocks</span>'
               if v["blocked"] else "")
            + f'</div></summary>'
            f'<div class="pc-body">'
            f'{blocked_html}'
            f'<div class="section-lbl">Application Activity</div>'
            f'{app_html}'
            f'</div></details>'
        )

    cross_midnight_note = ""
    if log_date_obj is None:
        cross_midnight_note = ("Couldn't parse a calendar date from the filename, so cross-midnight "
                                "session flags are disabled for this report. ")

    # ── Full HTML ────────────────────────────────────────────────────────────
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firewall Report — {log_date}</title>
<style>
/* Reset */
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Segoe UI",system-ui,sans-serif;background:#0d1117;
      color:#c9d1d9;font-size:13px;line-height:1.55}}

/* Header */
.hdr{{background:#161b22;padding:14px 24px;border-bottom:1px solid #30363d;
      position:sticky;top:0;z-index:100;display:flex;align-items:center;
      gap:16px;flex-wrap:wrap}}
.hdr h1{{font-size:14px;font-weight:700;color:#f0f6fc;white-space:nowrap}}
.hdr p{{font-size:11px;color:#8b949e;font-family:monospace}}

/* Summary stats */
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
        gap:8px;padding:12px 24px;background:#0d1117}}
.stat{{background:#161b22;border:1px solid #30363d;padding:10px 12px;border-radius:6px}}
.stat-l{{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.06em}}
.stat-v{{font-size:22px;font-weight:700;color:#f0f6fc;font-family:monospace;margin-top:2px}}

/* Executive summary */
.exec-wrap{{margin:0 24px 12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}}
.exec-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 14px}}
.exec-title{{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;font-weight:700}}
.exec-row{{display:flex;justify-content:space-between;align-items:baseline;gap:10px;
           padding:4px 0;border-top:1px solid #21262d;font-size:12px}}
.exec-row:first-of-type{{border-top:none}}
.exec-name{{color:#c9d1d9;font-family:monospace}}
.exec-sub{{color:#8b949e}}
.exec-val{{color:#f0f6fc;white-space:nowrap;font-family:monospace;font-size:11px}}
.exec-empty{{color:#484f58;font-size:11px;font-style:italic}}

/* Hourly chart */
.chart-box{{margin:0 24px 12px;background:#161b22;border:1px solid #30363d;
            border-radius:6px;padding:10px 14px}}
.chart-title{{font-size:10px;color:#8b949e;text-transform:uppercase;
              letter-spacing:.06em;margin-bottom:8px}}
.hbars{{display:flex;align-items:flex-end;height:52px;gap:2px}}
.hbar-col{{flex:1;display:flex;flex-direction:column;align-items:center;height:100%}}
.hbar-fill{{width:100%;background:#58a6ff55;border-radius:2px 2px 0 0;
            min-height:1px;transition:background .15s}}
.hbar-col:hover .hbar-fill{{background:#58a6ff}}
.hbar-lbl{{font-size:8px;color:#484f58;margin-top:2px;font-family:monospace}}

/* Info note */
.note{{background:#0d419d18;border-top:1px solid #0d419d55;
       border-bottom:1px solid #0d419d55;padding:8px 24px;
       font-size:11px;color:#79c0ff}}

/* Filter bar */
.ctrl{{padding:10px 24px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;
       background:#161b22;border-bottom:1px solid #30363d;position:sticky;
       top:43px;z-index:99}}
.ctrl input{{padding:5px 10px;background:#0d1117;border:1px solid #30363d;
             border-radius:4px;color:#c9d1d9;font-size:12px;
             min-width:160px;outline:none}}
.ctrl input:focus{{border-color:#58a6ff}}
.ctrl button{{padding:5px 12px;background:#21262d;border:1px solid #30363d;
              border-radius:4px;color:#8b949e;cursor:pointer;
              font-size:11px;transition:all .15s}}
.ctrl button:hover{{border-color:#8b949e;color:#c9d1d9}}
.ctrl button.act{{background:#161b22;color:#f0f6fc;border-color:#8b949e}}
.ctrl .sep{{color:#484f58;padding:0 4px}}
.ctrl .exp-btn{{margin-left:auto}}

/* PC cards */
.cards{{padding:12px 24px 32px}}
.pc-card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
          margin-bottom:8px;overflow:hidden}}
.pc-head{{padding:10px 14px;border-bottom:1px solid #21262d;cursor:pointer;
          list-style:none}}
.pc-head::-webkit-details-marker{{display:none}}
.pc-card:not([open]) .pc-head{{border-bottom:none}}
.pc-top{{display:flex;align-items:center;justify-content:space-between;
         margin-bottom:5px;flex-wrap:wrap;gap:6px}}
.pc-ip{{font-size:14px;font-weight:700;font-family:monospace;color:#f0f6fc}}
.badge{{padding:2px 10px;border-radius:20px;font-size:10px;font-weight:700}}
.pc-meta{{font-size:11px;color:#8b949e}}
.pc-body{{padding:10px 14px}}

/* App rows */
.section-lbl{{font-size:10px;color:#8b949e;text-transform:uppercase;
              letter-spacing:.08em;margin-bottom:8px}}
.app-row{{padding:9px 10px;margin-bottom:7px;border-radius:4px}}
.app-name{{font-weight:600;margin-bottom:3px}}
.app-cat{{font-size:10px;opacity:.65;font-weight:400}}
.app-stats{{font-size:11px;color:#8b949e}}
.deny-note{{color:#f85149;font-size:11px;margin-top:4px}}
.no-sess{{font-size:11px;color:#8b949e;font-style:italic;margin-top:4px}}

/* Session table */
.sess-tbl{{border-collapse:collapse;width:100%;margin-top:6px;font-family:monospace}}
.sess-tbl td{{padding:3px 5px;font-size:11px;border-top:1px solid #21262d}}
.sess-hdr td{{color:#484f58;font-family:"Segoe UI",sans-serif;
              font-size:10px;text-transform:uppercase;border-top:none}}
.sess-tbl tr:hover td{{background:#21262d55}}

/* Blocked box */
.block-box{{background:#f8514912;border-left:3px solid #f85149;padding:8px 10px;
            margin-bottom:10px;border-radius:4px}}
.block-title{{font-weight:600;color:#f85149;margin-bottom:5px;font-size:12px}}
.block-tag{{display:inline-block;margin:2px 3px;padding:2px 7px;
            background:#21262d;border-radius:3px;font-size:11px;color:#c9d1d9}}

/* No-match message */
#no-match{{display:none;text-align:center;padding:32px;color:#484f58;
           font-size:13px}}
</style>
</head>
<body>

<div class="hdr">
  <h1>🛡 Firewall Activity Report</h1>
  <p>{log_date} &nbsp;·&nbsp; {total_lines:,} log lines ({seclog_lines:,} connection events) &nbsp;·&nbsp;
     {denied:,} denied &nbsp;·&nbsp; {total_pcs} active PCs
     &nbsp;·&nbsp; Timestamps: UTC+5 (local)</p>
</div>

<div class="stats">
  <div class="stat"><div class="stat-l">Active PCs</div>
    <div class="stat-v">{total_pcs}</div></div>
  <div class="stat"><div class="stat-l">Total Data (successful)</div>
    <div class="stat-v">{fmt_bytes(total_bytes)}</div></div>
  <div class="stat"><div class="stat-l">Connection Events</div>
    <div class="stat-v">{seclog_lines:,}</div></div>
  <div class="stat"><div class="stat-l">Denied</div>
    <div class="stat-v" style="color:#f85149">{denied:,}</div></div>
  <div class="stat"><div class="stat-l">PCs w/ Blocks</div>
    <div class="stat-v" style="color:#f85149">{blocked_pcs}</div></div>
  <div class="stat"><div class="stat-l">Critical PCs</div>
    <div class="stat-v" style="color:#f85149">{critical_count}</div></div>
</div>

<div class="exec-wrap">
  <div class="exec-box">
    <div class="exec-title">Top Blocked Policies</div>
    {top_blocked_rows}
  </div>
  <div class="exec-box">
    <div class="exec-title">Top Bandwidth Consumers</div>
    {top_bw_rows}
  </div>
  <div class="exec-box">
    <div class="exec-title">MAC-Binding Anomalies</div>
    {mac_rows}
  </div>
</div>

<div class="chart-box">
  <div class="chart-title">Hourly Traffic (all PCs combined, successful connections only — hover for bytes)</div>
  <div class="hbars">{hourly_bars}</div>
</div>

<div class="note">
  ℹ️ Counted strictly from <b>SECLOG</b> connection-tracking events (SESSION_TEARDOWN / PACKET_DENY) —
  the redundant top-level POLICY lines are excluded from all counts to avoid double-counting.
  Session start/end use each connection's real <b>BeginTime/EndTime</b>, not just the moment it was logged.
  Blocked-attempt bytes are excluded from traffic totals and shown separately. {cross_midnight_note}
  Timestamps converted to <b>local time (UTC+5)</b>.
</div>

<div class="ctrl">
  <input type="text" id="iip"  placeholder="🔍 Filter IP…"  oninput="applyFilters()">
  <input type="text" id="iapp" placeholder="🔍 Filter app…" oninput="applyFilters()">
  <span class="sep">|</span>
  <button class="act" onclick="setRisk('a',this)">All</button>
  <button onclick="setRisk('0',this)" style="color:#3fb950">✔ Safe</button>
  <button onclick="setRisk('1',this)" style="color:#58a6ff">💼 Work</button>
  <button onclick="setRisk('2',this)" style="color:#8b949e">⬜ Other</button>
  <button onclick="setRisk('4',this)" style="color:#f85149">🚫 Critical</button>
  <span class="sep">|</span>
  <button onclick="window.print()" title="Print or Save as PDF">🖨 Print / PDF</button>
  <button class="exp-btn" onclick="toggleAll()">⇕ Expand/Collapse All</button>
</div>

<div class="cards" id="cards">{pc_html}</div>
<div id="no-match">No PCs match the current filter.</div>

<script>
let riskFilter = 'a';
let allOpen = false;

function setRisk(x, btn) {{
  riskFilter = x;
  document.querySelectorAll('.ctrl button.act').forEach(b => b.classList.remove('act'));
  btn.classList.add('act');
  applyFilters();
}}

function toggleAll() {{
  allOpen = !allOpen;
  document.querySelectorAll('.pc-card').forEach(card => {{ card.open = allOpen; }});
}}

function applyFilters() {{
  const ip  = document.getElementById('iip').value.toLowerCase();
  const app = document.getElementById('iapp').value.toLowerCase();
  let visible = 0;
  document.querySelectorAll('.pc-card').forEach(card => {{
    const show =
      card.dataset.ip.includes(ip) &&
      (app === '' || card.innerText.toLowerCase().includes(app)) &&
      (riskFilter === 'a' || card.dataset.risk === riskFilter);
    card.style.display = show ? '' : 'none';
    if (show) visible++;
  }});
  document.getElementById('no-match').style.display = visible ? 'none' : 'block';
}}
</script>
</body>
</html>'''


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  Huawei Firewall Log Analyzer  v3.0")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\n  Usage:  python analyzer_v3.py  <logfile.txt>\n")
        if platform.system() == "Windows":
            input("  Press Enter to exit…")
        sys.exit(1)

    logfile = sys.argv[1]
    if not os.path.isfile(logfile):
        print(f"\n  ERROR: File not found: {logfile}\n")
        if platform.system() == "Windows":
            input("  Press Enter to exit…")
        sys.exit(1)

    log_date, log_date_obj = extract_log_date(logfile)

    pcs, total_lines, seclog_lines, denied = parse_log(logfile)
    print(f"  Found {len(pcs)} active PCs | {total_lines:,} lines "
          f"({seclog_lines:,} connection events) | {denied:,} denied events")
    print(f"  Building report…")

    html = build_html(pcs, total_lines, seclog_lines, denied, log_date, log_date_obj)

    log_dir = os.path.dirname(os.path.abspath(logfile))
    outfile = os.path.join(log_dir, f"{log_date}_report.html")
    with open(outfile, "w", encoding="utf-8") as fh:
        fh.write(html)

    size_kb = os.path.getsize(outfile) / 1024
    print(f"\n  ✅  Report saved:  {outfile}")
    print(f"      Size: {size_kb:.0f} KB\n")

    if platform.system() == "Windows":
        try:
            os.startfile(outfile)
            print("  Opened in your default browser.")
        except Exception:
            pass
        input("\n  Press Enter to close…")
