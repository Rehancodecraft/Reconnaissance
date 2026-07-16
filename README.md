# OSINT Recon

Automated OSINT reconnaissance script for a target domain. Chains together
several well-known open-source tools, merges their results, and produces a
single polished PDF report.

> ⚠️ **Legal notice:** Only run this against domains you own or have
> explicit written authorization to test. Unauthorized scanning may be
> illegal in your jurisdiction.

## What it does

| Phase | Tools used | Output |
|---|---|---|
| 0. Dependency check | — | Auto-installs any missing tool (`apt` / `go install`) |
| 1. Subdomain discovery | `subfinder`, `amass`, `assetfinder`, `sublist3r`, `crt.sh` | Deduplicated subdomain list |
| 2. Live host validation | `httpx-toolkit` | Status code, title, tech per host |
| 3. CDN / WAF detection | `cdncheck` | Provider name (e.g. Cloudflare) |
| 4. Load balancer discovery | `lbd` + DNS A-record check | Load-balancing indicators |
| 5. Technology fingerprinting | `whatweb`, `nmap` | Detected tech stack + open ports |
| 6. Report generation | `reportlab` | Single formatted PDF report |

The PDF includes a cover page, an executive summary, and one clearly
divided section per phase, with key findings (errors, CDN name, open
ports) highlighted in color.

## Requirements

- Kali Linux (or any Linux distro with the tools below on `PATH`)
- Python 3.8+
- `pip install reportlab --break-system-packages`

Missing recon tools (`subfinder`, `amass`, `assetfinder`, `sublist3r`,
`httpx-toolkit`, `cdncheck`, `lbd`, `whatweb`, `nmap`, `dig`, `curl`, `go`)
are auto-installed on first run unless `--no-install` is passed.

## Installation

```bash
git clone https://github.com/<your-username>/osint-recon.git
cd osint-recon
pip install reportlab --break-system-packages
```

## Usage

```bash
python3 recon.py -d example.com
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-d`, `--domain` | Target domain (required) | — |
| `-o`, `--output` | Output directory for the PDF | `.` |
| `--timeout` | Per-tool timeout in seconds | `90` |
| `--no-install` | Skip auto-install; skip any missing tool instead | off |

### Examples

```bash
# Basic scan
python3 recon.py -d example.com

# Save report to a specific folder
python3 recon.py -d example.com -o ./reports

# Increase timeout for slower networks
python3 recon.py -d example.com --timeout 180

# Don't auto-install missing tools
python3 recon.py -d example.com --no-install
```

The report is saved as `osint_report_<domain>_<timestamp>.pdf` in the
output directory.

## Notes

- `amass` uses its local asset database (`amass subs -names`) rather than
  running a fresh passive enumeration, since `amass enum` can be slow and
  its results are read back afterward anyway. Run `amass enum -passive -d
  <domain>` separately beforehand if you want a fresh database.
- Every external tool call is logged internally for troubleshooting but
  intentionally left out of the PDF, which only reports facts about the
  target.
- If a tool is missing and fails to auto-install, that phase is skipped
  gracefully rather than crashing the whole scan.

## License

MIT
