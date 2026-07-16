#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Preformatted, HRFlowable
)

# ----------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------

DEFAULT_TIMEOUT = 90        # seconds, per external tool call
INSTALL_TIMEOUT = 240        # seconds, per install attempt (downloads take longer)
AMASS_TIMEOUT = 150          # seconds, amass passive enum can be slow (unused now, kept for reference)

# Every command actually run gets logged here as a dict:
# {"phase": ..., "tool": ..., "command": ..., "success": bool}
COMMANDS_LOG = []

# Candidate install commands per tool, tried in order until one works.
# apt is tried first (fastest / most reliable on Kali), go install as fallback
# for the projectdiscovery / tomnomnom tools that ship as Go binaries.
INSTALL_COMMANDS = {
    "subfinder":    ["sudo apt-get install -y subfinder",
                      "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    "amass":        ["sudo apt-get install -y amass"],
    "assetfinder":  ["go install -v github.com/tomnomnom/assetfinder@latest"],
    "sublist3r":    ["sudo apt-get install -y sublist3r",
                      "pip3 install sublist3r --break-system-packages"],
    "httpx-toolkit": ["sudo apt-get install -y httpx-toolkit",
                       "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    "cdncheck":     ["go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"],
    "lbd":          ["sudo apt-get install -y lbd"],
    "whatweb":      ["sudo apt-get install -y whatweb"],
    "nmap":         ["sudo apt-get install -y nmap"],
    "dig":          ["sudo apt-get install -y dnsutils"],
    "curl":         ["sudo apt-get install -y curl"],
    "go":           ["sudo apt-get install -y golang-go"],
}

GO_BIN_PATH = os.path.expanduser("~/go/bin")


# ----------------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------------

def log(msg):
    """Simple timestamped console logger so you can see progress live."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def strip_ansi(text):
    """
    Remove ANSI color/escape codes from tool output.
    Several tools (whatweb, httpx-toolkit) print color codes meant for a
    terminal. Left in place, they show up as garbage like "[1m[34m" inside
    the PDF, so every piece of raw tool output is passed through this
    before it is stored or displayed.
    """
    if not text:
        return ""
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)


def tool_exists(tool_name):
    """Check if a command-line tool is installed and on PATH (incl. ~/go/bin)."""
    if shutil.which(tool_name):
        return True
    # Go installs binaries to ~/go/bin, which may not be in PATH yet
    candidate = os.path.join(GO_BIN_PATH, tool_name)
    return os.path.isfile(candidate) and os.access(candidate, os.X_OK)


def run_cmd(cmd, timeout=DEFAULT_TIMEOUT, phase="", tool=""):
    """
    Run a shell command safely and log it to COMMANDS_LOG.

    Returns (success: bool, stdout: str, stderr: str)
    Output is ANSI-stripped before being returned, so every caller
    automatically gets clean text.
    Never raises - always returns something so the calling phase
    can decide what to do (skip, log, continue).
    """
    # Make sure ~/go/bin is on PATH for this call, in case tools were
    # just go-installed in this same run
    env = os.environ.copy()
    env["PATH"] = f"{GO_BIN_PATH}:{env.get('PATH', '')}"

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, env=env
        )
        stdout = strip_ansi(result.stdout)
        stderr = strip_ansi(result.stderr)
        success = result.returncode == 0 or bool(stdout.strip())
        COMMANDS_LOG.append({"phase": phase, "tool": tool, "command": cmd, "success": success})
        if not success:
            return False, stdout, stderr
        return True, stdout, stderr
    except subprocess.TimeoutExpired:
        COMMANDS_LOG.append({"phase": phase, "tool": tool, "command": cmd, "success": False})
        return False, "", f"Command timed out after {timeout}s: {cmd}"
    except Exception as e:
        COMMANDS_LOG.append({"phase": phase, "tool": tool, "command": cmd, "success": False})
        return False, "", f"Unexpected error running command: {e}"


def clean_lines(text):
    """Split tool output into a clean, de-duplicated, sorted list of lines."""
    lines = {line.strip() for line in text.splitlines() if line.strip()}
    return sorted(lines)


def truncate(text, limit=3000):
    """Cap long tool output so the PDF doesn't balloon in size."""
    text = text or "(no output)"
    if len(text) > limit:
        return text[:limit] + f"\n... [truncated, {len(text) - limit} more characters]"
    return text


# ----------------------------------------------------------------------
# PHASE 0: DEPENDENCY CHECK & AUTO-INSTALL
# ----------------------------------------------------------------------

def auto_install(tool_name, allow_install=True):
    """
    Try to install a missing tool automatically.
    Returns a dict describing the outcome for the report.
    """
    if tool_exists(tool_name):
        return {"tool": tool_name, "status": "already installed", "command": "-"}

    if not allow_install:
        return {"tool": tool_name, "status": "missing (auto-install disabled)", "command": "-"}

    # golang is a prerequisite for some tools - install it first if needed
    if tool_name in ("assetfinder", "subfinder", "httpx-toolkit", "cdncheck") and not tool_exists("go"):
        log("  [setup] golang not found, installing it first (needed to build Go-based tools)...")
        ok, out, err = run_cmd(INSTALL_COMMANDS["go"][0], timeout=INSTALL_TIMEOUT, phase="Phase 0", tool="go")
        if not ok:
            log(f"  [setup] failed to install golang: {err.strip()[:150]}")

    candidates = INSTALL_COMMANDS.get(tool_name, [])
    for cmd in candidates:
        log(f"  [auto-install] {tool_name}: trying `{cmd}` ...")
        ok, out, err = run_cmd(cmd, timeout=INSTALL_TIMEOUT, phase="Phase 0", tool=tool_name)
        if tool_exists(tool_name):
            log(f"  [auto-install] {tool_name}: SUCCESS via `{cmd}`")
            return {"tool": tool_name, "status": "installed", "command": cmd}
        else:
            log(f"  [auto-install] {tool_name}: that attempt did not succeed, trying next option if any")

    return {
        "tool": tool_name,
        "status": "install failed - please install manually",
        "command": " | ".join(candidates) if candidates else "no known install command"
    }


def phase_dependency_check(allow_install=True):
    log("PHASE 0: Dependency Check & Auto-Install")
    required_tools = [
        "subfinder", "amass", "assetfinder", "sublist3r", "curl",
        "httpx-toolkit", "cdncheck", "lbd", "dig", "whatweb", "nmap"
    ]
    report = []
    for t in required_tools:
        result = auto_install(t, allow_install=allow_install)
        log(f"  [{t}] -> {result['status']}")
        report.append(result)
    return report


# ----------------------------------------------------------------------
# PHASE 1: SUBDOMAIN DISCOVERY
# ----------------------------------------------------------------------

def run_subfinder(domain, timeout):
    if not tool_exists("subfinder"):
        return []
    log("  [subfinder] running...")
    cmd = f"subfinder -d {domain} -silent"
    ok, out, err = run_cmd(cmd, timeout, phase="Phase 1", tool="subfinder")
    if not ok:
        log(f"  [subfinder] failed: {err.strip()[:200]}")
        return []
    return clean_lines(out)


def run_amass(domain, timeout):
    """
    Uses `amass subs -names` only (reads amass's existing local asset
    database). The slower `amass enum -passive` pass is intentionally
    NOT run here - on this machine the local database is already
    populated from earlier scans, and enum was unreliable/slow, so we
    just read back whatever amass already knows.
    """
    if not tool_exists("amass"):
        return []
    log("  [amass] running (subs -names, using local database)...")

    subs_cmd = f"amass subs -names -d {domain}"
    ok, out, err = run_cmd(subs_cmd, timeout=60, phase="Phase 1", tool="amass")

    if not ok or not out.strip():
        log("  [amass] no subdomains found in local database")
        return []
    return clean_lines(out)


def run_assetfinder(domain, timeout):
    if not tool_exists("assetfinder"):
        return []
    log("  [assetfinder] running...")
    cmd = f"assetfinder --subs-only {domain}"
    ok, out, err = run_cmd(cmd, timeout, phase="Phase 1", tool="assetfinder")
    if not ok:
        log(f"  [assetfinder] failed: {err.strip()[:200]}")
        return []
    return clean_lines(out)


def run_sublist3r(domain, timeout):
    if not tool_exists("sublist3r"):
        return []
    log("  [sublist3r] running...")
    tmp_file = f"/tmp/sublist3r_{domain}.txt"
    cmd = f"sublist3r -d {domain} -o {tmp_file}"
    ok, out, err = run_cmd(cmd, timeout, phase="Phase 1", tool="sublist3r")
    if not ok:
        log(f"  [sublist3r] failed: {err.strip()[:200]}")
        return []
    if os.path.exists(tmp_file):
        with open(tmp_file, "r") as f:
            results = clean_lines(f.read())
        os.remove(tmp_file)
        return results
    return []


def run_crtsh(domain, timeout):
    """crt.sh is queried over HTTPS with curl and parsed as JSON (not a CLI tool)."""
    if not tool_exists("curl"):
        return []
    log("  [crt.sh] querying certificate transparency logs...")
    cmd = f'curl -s "https://crt.sh/?q=%25.{domain}&output=json"'
    ok, out, err = run_cmd(cmd, timeout, phase="Phase 1", tool="crt.sh")
    if not ok or not out.strip():
        log(f"  [crt.sh] failed or empty response: {err.strip()[:200]}")
        return []
    try:
        data = json.loads(out)
        names = set()
        for entry in data:
            for line in entry.get("name_value", "").split("\n"):
                line = line.strip().lstrip("*.")
                if line:
                    names.add(line)
        return sorted(names)
    except Exception as e:
        log(f"  [crt.sh] failed to parse JSON: {e}")
        return []


def phase_subdomain_discovery(domain, timeout):
    log("PHASE 1: Subdomain Discovery")
    all_subs = set()
    sources = {
        "subfinder": run_subfinder(domain, timeout),
        "amass": run_amass(domain, timeout),
        "assetfinder": run_assetfinder(domain, timeout),
        "sublist3r": run_sublist3r(domain, timeout),
        "crt.sh": run_crtsh(domain, timeout),
    }
    for tool, subs in sources.items():
        log(f"  [{tool}] found {len(subs)} entries")
        all_subs.update(subs)

    valid_subs = sorted(
        s for s in all_subs
        if s.endswith(domain) and re.match(r"^[a-zA-Z0-9_.\-]+$", s)
    )
    log(f"  TOTAL unique candidate subdomains: {len(valid_subs)}")
    return {"by_source": sources, "candidate_subdomains": valid_subs}


# ----------------------------------------------------------------------
# PHASE 2: LIVE HOST VALIDATION
# ----------------------------------------------------------------------

def parse_live_hosts(raw_lines):
    """
    Turn raw `httpx-toolkit -silent -status-code -title -tech-detect -no-color`
    lines into structured records: {host, url, status, title, tech}.
    Example input line:
        https://sub.example.com [200] [Example Title] [nginx,PHP]
    """
    parsed = []
    for line in raw_lines:
        line = strip_ansi(line)
        m = re.match(r"^(https?://\S+)\s*(.*)$", line.strip())
        if not m:
            continue
        url = m.group(1)
        rest = m.group(2).strip()
        host = re.sub(r"^https?://", "", url).split("/")[0]

        status = ""
        sm = re.search(r"\[(\d{3})\]", rest)
        if sm:
            status = sm.group(1)

        brackets = re.findall(r"\[([^\]]*)\]", rest)
        # First bracket is usually the status code; treat the rest as
        # title/tech info in whatever order httpx-toolkit printed them.
        extras = [b for b in brackets if b != status]
        title = extras[0] if len(extras) > 0 else ""
        tech = extras[1] if len(extras) > 1 else ""

        parsed.append({
            "host": host, "url": url, "status": status,
            "title": title, "tech": tech
        })
    return parsed


def phase_live_host_validation(subdomains, timeout):
    log("PHASE 2: Live Host Validation")
    if not subdomains or not tool_exists("httpx-toolkit"):
        log("  Skipping (no subdomains or the live-probe tool is not installed)")
        return []

    # -no-color: httpx-toolkit colors its output for terminals by default,
    # which pollutes the PDF with raw escape codes. Ask it for plain text.
    cmd = "httpx-toolkit -silent -status-code -title -tech-detect -no-color"
    log(f"  [live probe] checking {len(subdomains)} hosts...")
    env = os.environ.copy()
    env["PATH"] = f"{GO_BIN_PATH}:{env.get('PATH', '')}"
    try:
        result = subprocess.run(
            cmd, shell=True, input="\n".join(subdomains), capture_output=True,
            text=True, timeout=max(timeout, 30 + len(subdomains) * 2), env=env
        )
        COMMANDS_LOG.append({"phase": "Phase 2", "tool": "httpx-toolkit", "command": cmd, "success": True})
        out = strip_ansi(result.stdout)
    except Exception as e:
        COMMANDS_LOG.append({"phase": "Phase 2", "tool": "httpx-toolkit", "command": cmd, "success": False})
        log(f"  [live probe] error: {e}")
        return []

    live_hosts = parse_live_hosts(clean_lines(out))
    log(f"  TOTAL live hosts: {len(live_hosts)}")
    return live_hosts


# ----------------------------------------------------------------------
# PHASE 3: CDN DETECTION
# ----------------------------------------------------------------------

def phase_cdn_detection(live_hosts, timeout):
    log("PHASE 3: CDN Detection")
    if not live_hosts or not tool_exists("cdncheck"):
        log("  Skipping (no live hosts or the CDN-check tool is not installed)")
        return []

    hosts = [h["host"] for h in live_hosts]
    # -resp prints the actual provider name (e.g. "cloudflare") alongside
    # the host, instead of just echoing back the host with no context.
    cmd = "cdncheck -silent -resp"
    log(f"  [CDN check] checking {len(hosts)} hosts...")
    env = os.environ.copy()
    env["PATH"] = f"{GO_BIN_PATH}:{env.get('PATH', '')}"
    try:
        result = subprocess.run(
            cmd, shell=True, input="\n".join(hosts), capture_output=True,
            text=True, timeout=timeout, env=env
        )
        COMMANDS_LOG.append({"phase": "Phase 3", "tool": "cdncheck", "command": cmd, "success": True})
        out = strip_ansi(result.stdout)
    except Exception as e:
        COMMANDS_LOG.append({"phase": "Phase 3", "tool": "cdncheck", "command": cmd, "success": False})
        log(f"  [CDN check] error: {e}")
        return []

    cdn_results = clean_lines(out)
    log(f"  TOTAL CDN matches: {len(cdn_results)}")
    return cdn_results


# ----------------------------------------------------------------------
# PHASE 4: LOAD BALANCER DISCOVERY
# ----------------------------------------------------------------------

def phase_load_balancer_discovery(domain, timeout):
    log("PHASE 4: Load Balancer Discovery")
    results = {}

    if tool_exists("lbd"):
        log(f"  [load balancer check] checking {domain}...")
        cmd = f"lbd {domain}"
        ok, out, err = run_cmd(cmd, timeout, phase="Phase 4", tool="lbd")
        results["indicators"] = out.strip() if ok else ""
    else:
        results["indicators"] = ""

    log("  [DNS check] resolving DNS for multiple A records...")
    custom_findings = []
    if tool_exists("dig"):
        cmd = f"dig +short {domain} A"
        ok, out, err = run_cmd(cmd, timeout=20, phase="Phase 4", tool="dig")
        if ok:
            ips = clean_lines(out)
            if len(ips) > 1:
                custom_findings.append(
                    f"{domain} resolves to {len(ips)} IPs (possible load balancing): {', '.join(ips)}"
                )
            elif ips:
                custom_findings.append(f"{domain} resolves to a single IP: {ips[0]}")
            else:
                custom_findings.append(f"{domain} did not resolve to any A records")

    results["dns_check"] = custom_findings
    return results


# ----------------------------------------------------------------------
# PHASE 5: TECHNOLOGY FINGERPRINTING
# ----------------------------------------------------------------------

def phase_tech_fingerprinting(domain, live_hosts, timeout):
    log("PHASE 5: Technology Fingerprinting")
    results = {"web_tech": [], "port_scan": "", "open_ports_summary": []}

    if tool_exists("whatweb"):
        hosts = [h["host"] for h in live_hosts][:20] or [domain]
        for host in hosts:
            log(f"  [web tech scan] fingerprinting {host}...")
            # --color=never: whatweb colors its output for terminals by
            # default, which pollutes the PDF with raw escape codes.
            cmd = f"whatweb -a 3 --color=never {host}"
            ok, out, err = run_cmd(cmd, timeout, phase="Phase 5", tool="whatweb")
            if ok and out.strip():
                results["web_tech"].append((host, out.strip()))

    if tool_exists("nmap"):
        log(f"  [port scan] scanning top ports on {domain}...")
        cmd = f"nmap -sV --top-ports 20 -T4 {domain}"
        ok, out, err = run_cmd(cmd, timeout=max(timeout, 120), phase="Phase 5", tool="nmap")
        if ok and out.strip():
            results["port_scan"] = out.strip()
            # Pull out just the "open" lines for a quick-glance summary
            # table at the top of the Open Ports section in the PDF.
            # Typical nmap line: "80/tcp open  http    Cloudflare http proxy"
            results["open_ports_summary"] = re.findall(
                r"^(\d+/tcp)\s+open\s+(\S+)\s*(.*)$", out, re.MULTILINE
            )

    return results


# ----------------------------------------------------------------------
# PHASE 6: PDF REPORT GENERATION
# ----------------------------------------------------------------------

PAGE_W, PAGE_H = letter
NAVY = colors.HexColor("#1F3864")
RED = colors.HexColor("#C00000")
GREEN = colors.HexColor("#2E7D32")
LIGHT_GREY = colors.HexColor("#F2F2F2")


def build_table(data_rows, col_widths=None, header=True):
    """Helper to build a consistently-styled ReportLab table with zebra rows."""
    t = Table(data_rows, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ]
        # zebra-striped body rows for readability on wide tables
        for row_idx in range(1, len(data_rows)):
            if row_idx % 2 == 0:
                style.append(("BACKGROUND", (0, row_idx), (-1, row_idx), LIGHT_GREY))
    t.setStyle(TableStyle(style))
    return t


def section_header(title, styles, story):
    """Adds a heading followed by a full-width rule, used to open every section."""
    story.append(Paragraph(title, styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1.2, color=NAVY, spaceBefore=0, spaceAfter=12))


def add_header_footer(canvas_obj, doc, domain):
    """
    Draws a running header (report title) and footer (domain + page number)
    on every page except the cover page. Registered as onLaterPages.
    """
    canvas_obj.saveState()
    # Header
    canvas_obj.setStrokeColor(NAVY)
    canvas_obj.setLineWidth(0.75)
    canvas_obj.line(0.5 * inch, PAGE_H - 0.55 * inch, PAGE_W - 0.5 * inch, PAGE_H - 0.55 * inch)
    canvas_obj.setFont("Helvetica-Bold", 8.5)
    canvas_obj.setFillColor(NAVY)
    canvas_obj.drawString(0.5 * inch, PAGE_H - 0.45 * inch, "OSINT Reconnaissance Report")
    canvas_obj.setFont("Helvetica", 8.5)
    canvas_obj.drawRightString(PAGE_W - 0.5 * inch, PAGE_H - 0.45 * inch, domain)

    # Footer
    canvas_obj.setLineWidth(0.5)
    canvas_obj.setStrokeColor(colors.HexColor("#AAAAAA"))
    canvas_obj.line(0.5 * inch, 0.5 * inch, PAGE_W - 0.5 * inch, 0.5 * inch)
    canvas_obj.setFont("Helvetica", 7.5)
    canvas_obj.setFillColor(colors.HexColor("#666666"))
    canvas_obj.drawString(0.5 * inch, 0.35 * inch,
                           f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    canvas_obj.drawRightString(PAGE_W - 0.5 * inch, 0.35 * inch, f"Page {doc.page}")
    canvas_obj.restoreState()


def generate_pdf_report(domain, output_path, data, start_time):
    """
    Builds the PDF. Deliberately contains only facts about the target
    (live subdomains, CDN, load-balancing, tech, open ports) - no tool
    names, install status, or commands used.

    Layout: a dedicated cover page, then an executive summary, then one
    clearly-divided section per finding category, all with a consistent
    running header/footer and page numbers so it reads like a proper
    report rather than a raw dump of tool output.

    Key facts (status codes, CDN/provider names, open ports, service
    names, detected technologies) are bolded and colored so they stand
    out at a glance instead of being buried in dense paragraphs.
    """
    log("PHASE 6: PDF Report Generation")

    live_hosts = data["live_hosts"]
    cdn_findings = data["cdn"]
    lb = data["load_balancer"]
    tech = data["tech"]
    open_ports = tech.get("open_ports_summary") or []
    scan_seconds = (datetime.now() - start_time).total_seconds()

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"],
                               fontSize=26, textColor=NAVY, spaceAfter=6, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="CoverSub", parent=styles["Normal"],
                               fontSize=13, textColor=colors.HexColor("#444444"),
                               alignment=TA_CENTER, spaceAfter=4))
    styles.add(ParagraphStyle(name="CoverDomain", parent=styles["Normal"],
                               fontSize=20, textColor=NAVY, fontName="Helvetica-Bold",
                               alignment=TA_CENTER, spaceBefore=14, spaceAfter=14))
    styles.add(ParagraphStyle(name="H1", parent=styles["Heading1"],
                               textColor=NAVY, fontSize=15, spaceBefore=4, spaceAfter=2))
    styles.add(ParagraphStyle(name="Mono", parent=styles["Code"], fontSize=7, leading=9.5))
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8, leading=11))
    styles.add(ParagraphStyle(name="Body", parent=styles["Normal"], fontSize=9.5, leading=14))
    # Red bold - used for anything security-relevant that should jump out:
    # error/forbidden statuses, CDN/WAF names, open ports.
    styles.add(ParagraphStyle(name="Highlight", parent=styles["Normal"],
                               textColor=RED, fontName="Helvetica-Bold", fontSize=8, leading=11))
    # Dark blue bold - used for neutral-but-important facts: IPs, detected
    # technologies, service names.
    styles.add(ParagraphStyle(name="KeyInfo", parent=styles["Normal"],
                               textColor=NAVY, fontName="Helvetica-Bold", fontSize=8, leading=11))
    # Green bold - used for healthy/OK statuses (2xx, 3xx).
    styles.add(ParagraphStyle(name="StatusOk", parent=styles["Normal"],
                               textColor=GREEN, fontName="Helvetica-Bold", fontSize=8, leading=11))

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.9 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        title=f"OSINT Report - {domain}"
    )
    story = []

    # ============================================================
    # COVER PAGE
    # ============================================================
    story.append(Spacer(1, 1.6 * inch))
    story.append(Paragraph("OSINT RECONNAISSANCE REPORT", styles["CoverTitle"]))
    story.append(Paragraph("Open-Source Intelligence &amp; Attack Surface Summary", styles["CoverSub"]))
    story.append(Paragraph(escape(domain), styles["CoverDomain"]))
    story.append(Spacer(1, 0.4 * inch))

    cover_meta = build_table([
        ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Scan Duration", f"{scan_seconds:.1f} seconds"],
        ["Live Subdomains Found", str(len(live_hosts))],
        ["Open Ports Identified", str(len(open_ports))],
    ], col_widths=[2.3 * inch, 3 * inch], header=False)
    cover_meta.hAlign = "CENTER"
    story.append(cover_meta)
    story.append(Spacer(1, 1.5 * inch))
    story.append(HRFlowable(width="60%", thickness=1, color=colors.HexColor("#AAAAAA"), hAlign="CENTER"))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report summarizes publicly-observable information about the target domain "
        "only. It reflects a point-in-time scan and does not constitute a full security "
        "assessment.", styles["Small"]
    ))
    story.append(PageBreak())

    # ============================================================
    # EXECUTIVE SUMMARY
    # ============================================================
    section_header("Executive Summary", styles, story)

    error_count = sum(1 for h in live_hosts if h["status"] and h["status"][0] in ("4", "5"))
    cdn_name = ", ".join(sorted({
        re.sub(r"^.*\[(.*)\]\s*$", r"\1", f) for f in cdn_findings if "[" in f
    })) if cdn_findings else "None detected"
    lb_detected = "Yes" if "does load-balancing" in lb.get("indicators", "").lower() else \
                  ("Possible" if lb.get("dns_check") and "resolves to" in " ".join(lb["dns_check"]) and
                   "single IP" not in " ".join(lb["dns_check"]) else "No")

    summary_rows = [
        ["Metric", "Result"],
        ["Live subdomains discovered", str(len(live_hosts))],
        ["Subdomains returning errors (4xx/5xx)", str(error_count)],
        ["CDN / WAF provider", cdn_name],
        ["Load balancing detected", lb_detected],
        ["Open ports identified", str(len(open_ports)) if open_ports else "0"],
    ]
    story.append(build_table(summary_rows, col_widths=[3.2 * inch, 3.1 * inch]))
    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "The sections below detail every live subdomain, the CDN/WAF and load-balancing "
        "infrastructure in front of the target, the technologies detected on each host, "
        "and any open network ports. Values in <font color='#C00000'><b>red</b></font> "
        "flag findings worth a closer look (errors, CDN/WAF names, open ports); values in "
        "<font color='#1F3864'><b>navy</b></font> highlight key identifying facts such as "
        "IP addresses and detected technologies.", styles["Body"]
    ))
    story.append(PageBreak())

    # ============================================================
    # LIVE SUBDOMAINS
    # ============================================================
    section_header("1. Live Subdomains", styles, story)
    story.append(Paragraph(f"<b>{len(live_hosts)}</b> live subdomain(s) found.", styles["Body"]))
    story.append(Spacer(1, 8))
    if live_hosts:
        host_rows = [["#", "Subdomain", "Status", "Title", "Technologies"]]
        for i, h in enumerate(live_hosts):
            status = h["status"] or "-"
            if status and status[0] in ("4", "5"):
                status_style = "Highlight"
            elif status and status[0] in ("2", "3"):
                status_style = "StatusOk"
            else:
                status_style = "Small"
            host_rows.append([
                str(i + 1),
                Paragraph(escape(h["host"]), styles["Small"]),
                Paragraph(escape(status), styles[status_style]),
                Paragraph(escape(h["title"] or "-"), styles["Small"]),
                Paragraph(escape(h["tech"] or "-"), styles["KeyInfo"]),
            ])
        story.append(build_table(
            host_rows,
            col_widths=[0.3 * inch, 1.7 * inch, 0.55 * inch, 2 * inch, 1.55 * inch]
        ))
    else:
        story.append(Paragraph("No live subdomains were found.", styles["Body"]))
    story.append(PageBreak())

    # ============================================================
    # CDN DETECTION
    # ============================================================
    section_header("2. CDN &amp; WAF Detection", styles, story)
    if cdn_findings:
        cdn_rows = [["#", "Finding"]] + [
            [str(i + 1), Paragraph(escape(c), styles["Highlight"])]
            for i, c in enumerate(cdn_findings)
        ]
        story.append(build_table(cdn_rows, col_widths=[0.5 * inch, 5.8 * inch]))
    else:
        story.append(Paragraph("No CDN usage detected.", styles["Body"]))
    story.append(Spacer(1, 18))

    # ============================================================
    # LOAD BALANCER
    # ============================================================
    section_header("3. Load Balancer Indicators", styles, story)
    if lb.get("indicators"):
        story.append(Preformatted(truncate(lb["indicators"], 1500), styles["Mono"]))
        story.append(Spacer(1, 8))
    for f in lb.get("dns_check", []):
        story.append(Paragraph(f"&bull; {escape(f)}", styles["Body"]))
    if not lb.get("indicators") and not lb.get("dns_check"):
        story.append(Paragraph("No load-balancing indicators found.", styles["Body"]))
    story.append(PageBreak())

    # ============================================================
    # TECH FINGERPRINTING
    # ============================================================
    section_header("4. Web Technologies Detected", styles, story)
    if tech["web_tech"]:
        ww_rows = [["Host", "Detected"]]
        for host, result in tech["web_tech"]:
            ww_rows.append([
                Paragraph(escape(host), styles["KeyInfo"]),
                Paragraph(escape(truncate(result, 500)), styles["Small"]),
            ])
        story.append(build_table(ww_rows, col_widths=[1.6 * inch, 4.7 * inch]))
    else:
        story.append(Paragraph("No web technology data available.", styles["Body"]))
    story.append(Spacer(1, 20))

    # ============================================================
    # OPEN PORTS (quick-glance summary table, then raw nmap output)
    # ============================================================
    section_header("5. Open Ports &amp; Services", styles, story)

    if open_ports:
        op_rows = [["Port", "Service", "Version / Details"]]
        for port, service, version in open_ports:
            op_rows.append([
                Paragraph(f"<b>{escape(port)}</b>", styles["Highlight"]),
                Paragraph(f"<b>{escape(service)}</b>", styles["KeyInfo"]),
                Paragraph(escape(version or "-"), styles["Small"]),
            ])
        story.append(build_table(op_rows, col_widths=[1 * inch, 1.6 * inch, 3.7 * inch]))
        story.append(Spacer(1, 14))

    if tech["port_scan"]:
        story.append(Paragraph("Full scan output:", styles["Body"]))
        story.append(Spacer(1, 4))
        story.append(Preformatted(truncate(tech["port_scan"], 2500), styles["Mono"]))
    elif not open_ports:
        story.append(Paragraph("No open-port data available.", styles["Body"]))

    doc.build(
        story,
        onFirstPage=lambda c, d: None,
        onLaterPages=lambda c, d: add_header_footer(c, d, domain),
    )
    log(f"  PDF report written to: {output_path}")


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Automated OSINT Reconnaissance Script (PDF Edition)")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default=".", help="Output directory for the report")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-tool timeout in seconds")
    parser.add_argument("--no-install", action="store_true", help="Do not auto-install missing tools, just skip them")
    args = parser.parse_args()

    domain = re.sub(r"^https?://", "", args.domain.strip().lower()).strip("/")
    os.makedirs(args.output, exist_ok=True)
    report_path = os.path.join(
        args.output, f"osint_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    start_time = datetime.now()
    log(f"Starting OSINT reconnaissance on: {domain}")
    log(f"Report will be saved to: {report_path}")
    log("-" * 60)

    results = {}
    phase_dependency_check(allow_install=not args.no_install)
    results["subdomains"] = phase_subdomain_discovery(domain, args.timeout)
    results["live_hosts"] = phase_live_host_validation(
        results["subdomains"]["candidate_subdomains"] or [domain], args.timeout
    )
    results["cdn"] = phase_cdn_detection(results["live_hosts"], args.timeout)
    results["load_balancer"] = phase_load_balancer_discovery(domain, args.timeout)
    results["tech"] = phase_tech_fingerprinting(domain, results["live_hosts"], args.timeout)

    generate_pdf_report(domain, report_path, results, start_time)

    log("-" * 60)
    log("Reconnaissance complete.")
    print(f"\nFull PDF report saved at: {report_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(1)
