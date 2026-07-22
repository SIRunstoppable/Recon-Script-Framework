# Recon Framework — AI-Assisted Attack Surface Mapper

Automated recon pipeline for **authorized** bug bounty / pentest engagements.
Chains subdomain discovery through vulnerability scanning, then uses Gemini to
turn the raw output into a readable attack-surface report.

⚠️ **Only run this against domains you are authorized to test.** Several steps
(sensitive file probing, CORS header injection, XSS scanning, WordPress
user enumeration) send active requests to the target. Confirm the domain is in
scope before running.

---

## 1. Setup

### 1.1 Python dependencies
```bash
pip install -r requirements.txt --break-system-packages
```

### 1.2 External tools
Most steps depend on an external CLI tool and **skip themselves gracefully**
if that tool isn't installed — nothing crashes, you just get less coverage.
Check what you have installed:

```bash
chmod +x recon-framework.sh
./recon-framework.sh --check-deps
```

This prints a ✓/⚠/✗ table for every tool and Python package, plus whether
`GEMINI_API_KEY` is configured, along with install commands for anything
missing.

| Tool | Used by | Install |
|---|---|---|
| `subfinder` | Subdomain Enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `amass` | Subdomain Enumeration | see github.com/owasp-amass/amass |
| `sublist3r` | Subdomain Enumeration | `pip install sublist3r` |
| `gobuster` | Subdomain Enumeration | `go install github.com/OJ/gobuster/v3@latest` |
| `alterx` | Subdomain Permutation | `go install github.com/projectdiscovery/alterx/cmd/alterx@latest` |
| `dnsx` | DNS Resolution, Permutation | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `httpx` | Probe Alive Hosts | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `waybackurls` | URL Collection | `go install github.com/tomnomnom/waybackurls@latest` |
| `gau` | URL Collection | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `arjun` | Parameter Discovery | `pip install arjun` |
| `paramspider` | Parameter Discovery | see github.com/devanshbatham/ParamSpider |
| `nuclei` | Vuln Scanning (3 modes) + WordPress | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `subjack` | Subdomain Takeover | `go install github.com/haccer/subjack@latest` |
| `dalfox` | XSS Scan | `go install github.com/hahwul/dalfox/v2@latest` |

### 1.3 Scope — `scope.txt`
```bash
cp scope.txt.example scope.txt
nano scope.txt   # list domains you're authorized to test
```
Before touching anything, the script checks the domain you enter against
`scope.txt` and **refuses to run if it's not covered**. Format:
```
*.example.com              # matches example.com and every subdomain
example.com                # matches only that exact host
!internal.example.com      # explicit exclusion, wins over any match above
```
If `scope.txt` doesn't exist yet, the script offers to create one
pre-filled with the domain you type in — but for a real engagement, build
`scope.txt` from the program's official scope definition rather than
relying on that shortcut, since it just trusts whatever you typed.
`scope.txt` is git-ignored (it may reflect a private program's scope).

### 1.4 Secrets — `.env`
```bash
cp .env.example .env
nano .env   # set GEMINI_API_KEY=AIza...
```
`.env` is auto-loaded on every run and is git-ignored — never commit it.
Get a key at https://aistudio.google.com/apikey. The model used is set via
`GEMINI_MODEL` in `.env` (defaults to `gemini-2.0-flash` — check
https://ai.google.dev/gemini-api/docs/models for current names).

### 1.5 Files that must sit next to `recon-framework.sh`
The shell script copies these into each run's output folder automatically —
just keep them all in the same directory:
```
recon-framework.sh
scan_js_secrets.py
check_sensitive_files.py
wordpress_scan.py
extract_api_endpoints.py
check_cors_headers.py
flag_interesting_params.py
extract_source_maps.py
generate_ai_report.py
requirements.txt
.env.example
scope.txt.example
.gitignore
```

---

## 2. Running it

```bash
./recon-framework.sh
```
You'll be prompted for a target domain. If a previous run for that domain
exists, you'll be offered to **resume** it (skipping already-completed
steps) or start fresh. Progress for each step shows a live spinner with
elapsed time and a running count of results found so far.

Output goes to `recon-<domain>-<timestamp>/`, organized into one subfolder
per step (`subdomains/`, `live/`, `nuclei/`, `report/`, ...).

### Resuming
Just run the script again with the same domain — it detects the prior run
folder and skips any step already marked complete in `.checkpoint`. A step
only gets checkpointed on success, so anything that failed (e.g. the AI
report because `GEMINI_API_KEY` wasn't set yet) will simply retry next time.

---

## 3. Pipeline steps (in order)

| # | Step | What it does | Depends on |
|---|---|---|---|
| 1 | **Subdomain Enumeration** | Runs subfinder/amass/sublist3r/gobuster, merges + dedupes into `all_subdomains.txt` | target domain |
| 2 | **Subdomain Permutation** | `alterx` generates candidate variations (`dev-api.`, `staging.`...) from step 1's results; `dnsx` keeps only ones that actually resolve; merges back into `all_subdomains.txt` | step 1 |
| 3 | **DNS Resolution Check** | `dnsx` filters the full subdomain list down to `resolved_subdomains.txt` so later steps don't waste time probing dead hosts. (Deliberately **not** used for the takeover check — dangling/non-resolving CNAMEs are exactly what that step looks for.) | steps 1–2 |
| 4 | **Probe Alive Hosts** | `httpx` checks which resolved hosts are actually serving HTTP(S), grabs title/tech/status/IP | step 3 |
| 5 | **Sensitive File Exposure Check** | Probes ~40 paths per live host (`.git/HEAD`, `.env`, backups, cloud creds, swagger, actuator...). Uses a random-path **baseline request** first so custom "soft-404" pages don't produce false positives. | step 4 |
| 6 | **WordPress Detection + Vuln Scan** | Confirms WordPress via tech-detect + active checks (`wp-login.php`, `wp-json`), reads version from `readme.html`, enumerates usernames via the public `/wp-json/wp/v2/users` endpoint, checks `xmlrpc.php` reachability, then runs nuclei's WordPress core/plugin/theme CVE templates against confirmed hosts only | step 4 |
| 7 | **API Endpoint Extraction** | Probes for exposed OpenAPI/Swagger specs (parses `paths` to list every documented endpoint+method) and GraphQL introspection (lists every query/mutation if introspection is enabled) | step 4 |
| 8 | **CORS + Security Headers Check** | Sends requests with crafted `Origin` headers (arbitrary origin, `null`, prefix/suffix substring tricks) to catch reflected-origin and other CORS misconfigs; also flags missing CSP/X-Frame-Options/HSTS/X-Content-Type-Options | step 4 |
| 9 | **Collect URLs** | `waybackurls` + `gau` pull historical URLs for every live host | step 4 |
| 10 | **Parameter Discovery** | Splits URLs into with/without query params; runs `arjun` (hidden param brute-force) and `paramspider` | step 9 |
| 11 | **Open Redirect / SSRF / IDOR Flagging** | **Passive** — no requests sent. Classifies query parameter names+values against known-risky patterns (`redirect=`, `url=`, numeric `id=`...) with a strong/weak confidence signal | step 10 |
| 12 | **XSS Scan (dalfox)** | Runs `dalfox` against every collected parameterized URL | step 10 |
| 13 | **Nuclei Vulnerability Scan** | Three passes: all severities, high/critical only, and a broader `-tags exposure,misconfig,default-login,...` pass to catch "easy win" bugs nuclei itself rates as low/info severity | step 4 |
| 14 | **Subdomain Takeover Check** | `subjack` against the **full unfiltered** subdomain list | step 1 |
| 15 | **Sensitive Keyword Grep** | Greps collected URLs for `admin`, `debug`, `token`, `internal`, etc. | step 9 |
| 16 | **JavaScript File Harvest** | Downloads every `.js` file referenced in collected URLs, then scans them for secrets (AWS/Google/Slack/Stripe/GitHub keys, JWTs, private keys...) and hidden endpoints. Each secret gets a `confidence: high/low` score from Shannon entropy + a placeholder-word denylist, to cut false positives | step 9 |
| 17 | **Exposed Source Map Recovery** | Looks for `.js.map` files (via the `sourceMappingURL` comment or the `<file>.map` convention). If found, reconstructs the **original unminified source code** from `sourcesContent` and runs the same secret/endpoint scanner from step 16 against it — unminified code is far more readable and often reveals more | step 16 |
| 18 | **AI Attack Surface Report** | Sends a condensed summary of every step's findings to Gemini, gets back a structured risk assessment, writes `report/attack_surface_report.html` (dashboard) + `.json` | all steps |

---

## 4. Output structure

```
recon-<domain>-<timestamp>/
├── .checkpoint                    # completed step keys, one per line
├── all_subdomains.txt             # every subdomain found (unfiltered)
├── resolved_subdomains.txt        # only the ones that resolve
├── subdomains/                    # raw output per tool
├── permutation/                   # alterx candidates + resolved results
├── resolve/
├── live/httpx_live.txt            # live hosts with title/tech/status/IP
├── wordpress/                     # wp_hosts.txt, nuclei_wordpress.txt
├── urls/all_urls.txt              # every historical URL found
├── params/                        # urls_with_params.txt, arjun/paramspider output
├── nuclei/                        # nuclei_result.txt, _critical.txt, _exposures.txt, dalfox_xss.txt
├── takeover/takeover-results.txt
├── js/                            # downloaded .js files + recovered_sources/ from source maps
├── logs/                          # per-tool raw logs (for debugging failures)
└── report/
    ├── flagged.txt                # sensitive-keyword URL matches
    ├── sensitive_files.json/.txt
    ├── api_endpoints.json/.txt
    ├── cors_headers.json/.txt
    ├── interesting_params.json/.txt
    ├── js_findings.json/.txt
    ├── source_maps.json/.txt
    ├── wordpress.json/.txt
    └── attack_surface_report.html # <- start here
```

---

## 5. Safety notes

- This tool sends **active requests** to the target in several steps
  (sensitive file probing, CORS header injection, dalfox XSS, WordPress
  user enumeration, source map fetching). Make sure active testing is
  permitted by the program's scope/rules before running.
- The Open Redirect / SSRF / IDOR flagging step is passive (pattern
  matching only) — but everything downstream of live-host probing is not.
- AI-generated findings in the final report are **leads, not confirmed
  vulnerabilities** — always manually verify before reporting to a program.