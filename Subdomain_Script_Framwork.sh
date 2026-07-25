#!/bin/bash
###############################################################################
#  R E C O N   F R A M E W O R K   -   AI-Assisted Attack Surface Mapper
#  For authorized bug bounty / pentest use only.
###############################################################################

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- Load secrets from .env (never hardcode keys / never commit .env) ----------
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/.env"
  set +a
fi

# ---------- Colors ----------
red="\e[91m"; green="\e[92m"; blue="\e[94m"; yellow="\e[93m"
cyan="\e[96m"; bold="\e[1m"; dim="\e[2m"; reset="\e[0m"

# ---------- Dependency check ----------
# name:required?  (required=yes means the script can barely function without it;
# required=no means that step is skipped gracefully if missing)
EXTERNAL_TOOLS=(
  "python3:yes"      "curl:yes"          "subfinder:no"      "amass:no"
  "sublist3r:no"      "gobuster:no"      "dnsx:no"           "alterx:no"
  "httpx:no"          "waybackurls:no"   "gau:no"            "arjun:no"
  "paramspider:no"    "nuclei:no"        "subjack:no"        "dalfox:no"
  "ffuf:no"           "subenum:no"       "assetfinder:no"    "dirsearch:no"
)
PYTHON_PACKAGES=("requests")

check_dependencies() {
  echo -e "${cyan}${bold}Dependency check${reset}"
  echo -e "${dim}────────────────────────────────────────────────────────────${reset}"
  local missing_required=0
  local missing_optional=0

  for entry in "${EXTERNAL_TOOLS[@]}"; do
    local name="${entry%%:*}" required="${entry##*:}"
    if command -v "$name" &> /dev/null; then
      printf "  ${green}✓${reset} %-14s installed\n" "$name"
    else
      if [[ "$required" == "yes" ]]; then
        printf "  ${red}✗${reset} %-14s MISSING (required — core steps will fail)\n" "$name"
        missing_required=$((missing_required + 1))
      else
        printf "  ${yellow}⚠${reset} %-14s missing (optional — that step will be skipped)\n" "$name"
        missing_optional=$((missing_optional + 1))
      fi
    fi
  done

  echo ""
  echo -e "${cyan}Python packages${reset}"
  for pkg in "${PYTHON_PACKAGES[@]}"; do
    if python3 -c "import $pkg" &> /dev/null; then
      printf "  ${green}✓${reset} %-14s installed\n" "$pkg"
    else
      printf "  ${red}✗${reset} %-14s MISSING — run: pip install %s --break-system-packages\n" "$pkg" "$pkg"
      missing_required=$((missing_required + 1))
    fi
  done

  echo ""
  if [[ -f "$SCRIPT_DIR/scope.txt" ]]; then
    echo -e "  ${green}✓${reset} scope.txt found"
  else
    echo -e "  ${yellow}⚠${reset} scope.txt not found — you'll be prompted to create one on first run"
  fi

  echo ""
  if [[ -n "$GEMINI_API_KEY" ]]; then
    echo -e "  ${green}✓${reset} GEMINI_API_KEY is set"
  else
    echo -e "  ${yellow}⚠${reset} GEMINI_API_KEY not set (.env missing or empty) — the AI report step will be skipped"
  fi

  echo ""
  echo -e "${dim}────────────────────────────────────────────────────────────${reset}"
  if [[ $missing_required -gt 0 ]]; then
    echo -e "${red}$missing_required required item(s) missing.${reset} Install them before running."
  else
    echo -e "${green}All required items present.${reset} $missing_optional optional tool(s) missing — those steps will auto-skip."
  fi

  echo ""
  echo -e "${dim}Install hints (ProjectDiscovery tools via go install, e.g.):${reset}"
  echo -e "${dim}  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${reset}"
  echo -e "${dim}  go install github.com/projectdiscovery/httpx/cmd/httpx@latest${reset}"
  echo -e "${dim}  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest${reset}"
  echo -e "${dim}  go install github.com/projectdiscovery/alterx/cmd/alterx@latest${reset}"
  echo -e "${dim}  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${reset}"
  echo -e "${dim}  go install github.com/hahwul/dalfox/v2@latest${reset}"
  echo -e "${dim}  go install github.com/ffuf/ffuf/v2@latest${reset}"
  echo -e "${dim}  # ffuf needs a wordlist too: sudo apt install seclists  (or clone github.com/danielmiessler/SecLists)${reset}"
  echo -e "${dim}  git clone https://github.com/bing0o/SubEnum.git && cd SubEnum && ./setup.sh${reset}"
  echo -e "${dim}  go install github.com/tomnomnom/assetfinder@latest${reset}"
  echo -e "${dim}  pip install dirsearch  (or git clone github.com/maurosoria/dirsearch)${reset}"
  echo -e "${dim}  go install github.com/tomnomnom/waybackurls@latest${reset}"
  echo -e "${dim}  go install github.com/lc/gau/v2/cmd/gau@latest${reset}"
  echo -e "${dim}  pip install requests --break-system-packages${reset}"
}

if [[ "$1" == "--check-deps" || "$1" == "-check-deps" ]]; then
  check_dependencies
  exit 0
fi

# ---------- Config ----------
# GEMINI_API_KEY comes from .env (see .env.example)
GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.0-flash}"   # check https://ai.google.dev/gemini-api/docs/models for current names

# Centralized rate-limit / concurrency knobs — override in .env if needed.
# These apply to every active-scanning step, external tool AND Python helper
# script alike, so raising concurrency in one place doesn't leave other
# steps still hammering the target at a different, uncoordinated rate.
RATE_LIMIT="${RECON_RATE_LIMIT:-10}"     # requests/sec cap (shared, not per-thread) for the Python scanners
THREADS="${RECON_MAX_WORKERS:-15}"       # worker/thread count for both external tools and Python scanners
export RECON_RATE_LIMIT="$RATE_LIMIT"
export RECON_MAX_WORKERS="$THREADS"

# ---------- Step tracking ----------
# key = stable ID stored in the checkpoint file. label = what's shown to the user.
STEP_KEYS=(subdomains permutation resolve probe content_discovery sensitive_files wordpress api_extraction cors_headers misconfig urls params param_flagging xss nuclei takeover keywords js cloud_exposure source_maps ai_report)
STEP_LABELS=(
  "Subdomain Enumeration"
  "Subdomain Permutation (alterx)"
  "DNS Resolution Check"
  "Probe Alive Hosts"
  "Content Discovery (ffuf)"
  "Sensitive File Exposure Check"
  "WordPress Detection + Vuln Scan"
  "API Endpoint Extraction (Swagger/GraphQL)"
  "CORS + Security Headers Check"
  "Security Misconfiguration Check"
  "Collect URLs (Wayback/GAU)"
  "Parameter Discovery"
  "Open Redirect / SSRF / IDOR Flagging"
  "XSS Scan (dalfox)"
  "Nuclei Vulnerability Scan"
  "Subdomain Takeover Check"
  "Sensitive Keyword Grep"
  "JavaScript File Harvest"
  "Cloud Exposure (S3/Azure/GitHub/CI-CD)"
  "Exposed Source Map Recovery"
  "AI Attack Surface Report"
)
TOTAL_STEPS=${#STEP_KEYS[@]}
CURRENT_STEP=0
CHECKPOINT_FILE=".checkpoint"

# ---------- UI helpers ----------

banner() {
clear
echo -e "${cyan}${bold}"
cat << "EOF"
  ____  _____ ____ ___  _   _   _____ ____      _    __  __ _______        _____  ____  _  __
 |  _ \| ____/ ___/ _ \| \ | | |  ___|  _ \    / \  |  \/  | ____\ \      / / _ \|  _ \| |/ /
 | |_) |  _|| |  | | | |  \| | | |_  | |_) |  / _ \ | |\/| |  _|  \ \ /\ / / | | | |_) | ' /
 |  _ <| |__| |__| |_| | |\  | |  _| |  _ <  / ___ \| |  | | |___  \ V  V /| |_| |  _ <| . \
 |_| \_\_____\____\___/|_| \_| |_|   |_| \_\/_/   \_\_|  |_|_____|  \_/\_/  \___/|_| \_\_|\_\

EOF
echo -e "${reset}${yellow}   Automated Recon + AI Attack-Surface Reporting${reset}\n"
}

# prints "[3/9] Nuclei Vulnerability Scan" header
step_header() {
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo -e "${blue}${bold}[${CURRENT_STEP}/${TOTAL_STEPS}] ${STEP_LABELS[$((CURRENT_STEP-1))]}${reset}"
  echo -e "${dim}────────────────────────────────────────────────────────────${reset}"
}

is_step_done() {
  [[ -f "$CHECKPOINT_FILE" ]] && grep -qx "$1" "$CHECKPOINT_FILE"
}

mark_step_done() {
  echo "$1" >> "$CHECKPOINT_FILE"
}

# Wraps a step: prints header, skips if already checkpointed, marks done on success.
# Usage: run_step <step_key> <function_name>
run_step() {
  local key="$1" func="$2"
  step_header
  if is_step_done "$key"; then
    echo -e "${green}✓ already completed earlier — skipping (checkpoint: $key)${reset}"
    return 0
  fi
  "$func"
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    mark_step_done "$key"
  else
    echo -e "${red}  ⚠ step '$key' exited with an error — not marked complete, will retry next run${reset}"
  fi
  return $rc
}

# Runs a command in the background and shows a live spinner + elapsed timer + line count of an output file
# Usage: run_with_progress "<log label>" "<output file to tail-count>" -- command args...
run_with_progress() {
  local label="$1"; shift
  local watch_file="$1"; shift
  if [[ "$1" == "--" ]]; then shift; fi

  local start_ts=$(date +%s)
  local logfile="logs/${label// /_}.log"
  mkdir -p logs

  ( "$@" ) > "$logfile" 2>&1 &
  local pid=$!

  local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    local now=$(date +%s)
    local elapsed=$(( now - start_ts ))
    local count="?"
    if [[ -n "$watch_file" && -f "$watch_file" ]]; then
      count=$(wc -l < "$watch_file" 2>/dev/null | tr -d ' ')
    fi
    i=$(( (i+1) % ${#spin} ))
    printf "\r${cyan}%s${reset} %-28s ${dim}%02d:%02d elapsed${reset}  ${green}found: %s${reset}   " \
      "${spin:$i:1}" "$label" $((elapsed/60)) $((elapsed%60)) "$count"
    sleep 0.3
  done
  wait "$pid"
  local rc=$?
  local now=$(date +%s)
  local elapsed=$(( now - start_ts ))
  if [[ $rc -eq 0 ]]; then
    printf "\r${green}✓${reset} %-28s ${dim}%02d:%02d elapsed${reset}  %-30s\n" \
      "$label" $((elapsed/60)) $((elapsed%60)) "done"
  else
    printf "\r${red}✗${reset} %-28s ${dim}%02d:%02d elapsed${reset}  %-30s\n" \
      "$label" $((elapsed/60)) $((elapsed%60)) "FAILED (see $logfile)"
  fi
  return $rc
}

check_tool() {
  if ! command -v "$1" &> /dev/null; then
    echo -e "${red}  ⚠ $1 not installed - skipping this sub-step${reset}"
    return 1
  fi
  return 0
}

###############################################################################
# STEP FUNCTIONS
# Each one assumes CWD = WORKDIR and returns non-zero only on a hard failure.
###############################################################################

step_subdomains() {
  mkdir -p subdomains && cd subdomains || return 1
  check_tool subfinder && run_with_progress "subfinder" "subfinder.txt" -- subfinder -d "$domain" -o subfinder.txt
  check_tool amass     && run_with_progress "amass"     "amass.txt"     -- amass enum -d "$domain" -o amass.txt
  check_tool sublist3r && run_with_progress "sublist3r" "sublist3r.txt" -- sublist3r -d "$domain" -o sublist3r.txt
  check_tool gobuster  && run_with_progress "gobuster"  "gobuster.txt"  -- \
    gobuster dns -d "$domain" -r /etc/resolv.conf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --wildcard -q -t "$THREADS" -o gobuster.txt
  # SubEnum wraps Findomain+SubFinder+Amass+AssetFinder+crt.sh+wayback — some overlap
  # with the tools above is expected and harmless (everything gets deduped below).
  check_tool subenum     && run_with_progress "subenum"     "subenum.txt"     -- \
    bash -c "subenum -d '$domain' -s > subenum.txt"
  check_tool assetfinder && run_with_progress "assetfinder" "assetfinder.txt" -- \
    bash -c "assetfinder --subs-only '$domain' > assetfinder.txt"

  cat ./*.txt 2>/dev/null | cut -d ' ' -f1 | sed '/^$/d' | sort -u > ../all_subdomains.txt
  cd ..
  echo -e "${green}[+] Total unique subdomains: $(wc -l < all_subdomains.txt)${reset}"
}

step_permutation() {
  mkdir -p permutation && cd permutation || return 1

  if check_tool alterx && check_tool dnsx; then
    run_with_progress "alterx" "candidates.txt" -- alterx -l ../all_subdomains.txt -o candidates.txt
    if [[ -s candidates.txt ]]; then
      run_with_progress "dnsx-permutation" "permuted_resolved.txt" -- \
        dnsx -l candidates.txt -silent -rate-limit "$RATE_LIMIT" -t "$THREADS" -o permuted_resolved.txt
    else
      touch permuted_resolved.txt
    fi
  else
    echo -e "${yellow}  alterx and/or dnsx not found — skipping permutation (install: go install github.com/projectdiscovery/alterx/cmd/alterx@latest)${reset}"
    touch permuted_resolved.txt
  fi

  local before after new_count
  before=$(cat ../all_subdomains.txt 2>/dev/null | wc -l | tr -d ' ')
  cat ../all_subdomains.txt permuted_resolved.txt 2>/dev/null | sed '/^$/d' | sort -u > ../all_subdomains.txt.tmp
  mv ../all_subdomains.txt.tmp ../all_subdomains.txt
  after=$(cat ../all_subdomains.txt 2>/dev/null | wc -l | tr -d ' ')
  new_count=$((after - before))
  cd ..
  echo -e "${green}[+] Permutation discovered $new_count new resolvable subdomain(s) (total now: $after)${reset}"
}

step_resolve() {
  mkdir -p resolve && cd resolve || return 1
  if check_tool dnsx; then
    run_with_progress "dnsx" "resolved_subdomains.txt" -- \
      dnsx -l ../all_subdomains.txt -silent -rate-limit "$RATE_LIMIT" -t "$THREADS" -o resolved_subdomains.txt
  else
    echo -e "${yellow}  dnsx not found — skipping resolution filter, all subdomains will be probed as-is${reset}"
    cp ../all_subdomains.txt resolved_subdomains.txt
  fi
  cp resolved_subdomains.txt ../resolved_subdomains.txt
  cd ..
  local total resolved
  total=$(cat all_subdomains.txt 2>/dev/null | wc -l | tr -d ' ')
  resolved=$(cat resolved_subdomains.txt 2>/dev/null | wc -l | tr -d ' ')
  echo -e "${green}[+] Resolvable subdomains: $resolved / $total${reset}"
}

step_probe() {
  mkdir -p live && cd live || return 1
  local target_list="../resolved_subdomains.txt"
  [[ -f "$target_list" ]] || target_list="../all_subdomains.txt"  # fallback for old runs without a resolve step
  if check_tool httpx; then
    run_with_progress "httpx" "httpx_live.txt" -- \
      httpx -l "$target_list" -title -tech-detect -status-code -ip -rate-limit "$RATE_LIMIT" -threads "$THREADS" -o httpx_live.txt
  fi
  cd ..
  echo -e "${green}[+] Live hosts: $(cat live/httpx_live.txt 2>/dev/null | wc -l | tr -d ' ')${reset}"
}

step_content_discovery() {
  mkdir -p content_discovery && cd content_discovery || return 1

  if [[ ! -s ../live/httpx_live.txt ]]; then
    echo -e "${yellow}  no live hosts to fuzz — skipping${reset}"
    cd ..
    return 0
  fi

  local have_ffuf=0 have_dirsearch=0
  check_tool ffuf && have_ffuf=1
  check_tool dirsearch && have_dirsearch=1

  if [[ $have_ffuf -eq 0 && $have_dirsearch -eq 0 ]]; then
    cd ..
    return 0
  fi

  local wordlist=""
  for candidate in \
    /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
    /usr/share/seclists/Discovery/Web-Content/common.txt \
    /usr/share/wordlists/dirb/common.txt
  do
    if [[ -f "$candidate" ]]; then wordlist="$candidate"; break; fi
  done
  if [[ $have_ffuf -eq 1 && -z "$wordlist" ]]; then
    echo -e "${yellow}  no content-discovery wordlist found for ffuf (checked SecLists/dirb paths) — ffuf pass will be skipped${reset}"
    have_ffuf=0
  fi

  local hosts_total hosts_done=0
  hosts_total=$(wc -l < ../live/httpx_live.txt)
  while read -r line; do
    [[ -z "$line" ]] && continue
    local host safe_name
    host=$(echo "$line" | awk '{print $1}')
    safe_name=$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g')
    hosts_done=$((hosts_done+1))
    printf "\r${cyan}⠋${reset} Content discovery  ${green}%d/%d hosts${reset}   " "$hosts_done" "$hosts_total"

    if [[ $have_ffuf -eq 1 ]]; then
      ffuf -u "${host}/FUZZ" -w "$wordlist" -mc 200,201,204,301,302,307,401,403 \
           -ac -t "$THREADS" -rate "$RATE_LIMIT" -of json -o "ffuf_${safe_name}.json" -s 2>/dev/null
    fi
    if [[ $have_dirsearch -eq 1 ]]; then
      # --format=plain is stable across dirsearch versions/forks, unlike its JSON schema.
      dirsearch -u "$host" -o "dirsearch_${safe_name}.txt" --format=plain -q --random-agent 2>/dev/null
    fi
  done < ../live/httpx_live.txt
  echo ""

  python3 ../merge_ffuf_results.py
  cd ..
}

step_sensitive_files() {
  mkdir -p report
  if ! command -v python3 &> /dev/null; then
    echo -e "${red}  ⚠ python3 not found — skipping sensitive file check${reset}"
    return 0
  fi
  python3 check_sensitive_files.py
}

step_wordpress() {
  mkdir -p wordpress report
  if ! command -v python3 &> /dev/null; then
    echo -e "${red}  ⚠ python3 not found — skipping WordPress scan${reset}"
    return 0
  fi
  python3 wordpress_scan.py

  if [[ -s wordpress/wp_hosts.txt ]] && check_tool nuclei; then
    run_with_progress "nuclei-wordpress" "wordpress/nuclei_wordpress.txt" -- \
      nuclei -l wordpress/wp_hosts.txt -tags wordpress,wp-plugin,wp-theme,cve -rate-limit "$RATE_LIMIT" -c "$THREADS" -o wordpress/nuclei_wordpress.txt
  fi
}

step_api_extraction() {
  mkdir -p report
  if ! command -v python3 &> /dev/null; then
    echo -e "${red}  ⚠ python3 not found — skipping API extraction${reset}"
    return 0
  fi
  python3 extract_api_endpoints.py
}

step_cors_headers() {
  mkdir -p report
  if ! command -v python3 &> /dev/null; then
    echo -e "${red}  ⚠ python3 not found — skipping CORS/header check${reset}"
    return 0
  fi
  python3 check_cors_headers.py
}

step_misconfig() {
  mkdir -p report
  if ! command -v python3 &> /dev/null; then
    echo -e "${red}  ⚠ python3 not found — skipping misconfig check${reset}"
    return 0
  fi
  python3 check_misconfig.py
}

step_urls() {
  mkdir -p urls && cd urls || return 1
  > raw_urls.txt
  if [[ -s ../live/httpx_live.txt ]]; then
    while read -r sub; do
      host=$(echo "$sub" | awk '{print $1}')
      check_tool waybackurls && echo "$host" | waybackurls >> raw_urls.txt 2>/dev/null
      check_tool gau         && echo "$host" | gau         >> raw_urls.txt 2>/dev/null
    done < ../live/httpx_live.txt
  fi
  sort -u raw_urls.txt > all_urls.txt
  echo -e "${green}[+] URLs collected: $(wc -l < all_urls.txt)${reset}"
  cd ..
}

step_params() {
  mkdir -p params && cd params || return 1
  grep -E "\?" ../urls/all_urls.txt 2>/dev/null | sort -u > urls_with_params.txt
  grep -v -E "\?" ../urls/all_urls.txt 2>/dev/null | sort -u > urls_no_params.txt
  check_tool arjun && run_with_progress "arjun" "arjun_out.txt" -- \
    arjun -i urls_no_params.txt -t "$THREADS" -o arjun_out.txt

  cat ../urls/all_urls.txt 2>/dev/null | awk -F/ '{print $3}' | grep -E "(\.|^)${domain}$" | sort -u > for_paramspider.txt
  check_tool paramspider && run_with_progress "paramspider" "" -- paramspider -l for_paramspider.txt
  cd ..
}

step_param_flagging() {
  mkdir -p report
  if ! command -v python3 &> /dev/null; then
    echo -e "${red}  ⚠ python3 not found — skipping param flagging${reset}"
    return 0
  fi
  python3 flag_interesting_params.py
}

step_xss() {
  mkdir -p nuclei  # reuse the nuclei/ folder for all "active vuln scan" output
  if ! check_tool dalfox; then
    return 0
  fi
  if [[ ! -s params/urls_with_params.txt ]]; then
    echo -e "${yellow}  no parameterized URLs to test — skipping${reset}"
    return 0
  fi
  cd nuclei || return 1
  run_with_progress "dalfox" "dalfox_xss.txt" -- \
    dalfox file ../params/urls_with_params.txt --silence --no-color -w "$THREADS" -o dalfox_xss.txt
  cd ..
}

step_nuclei() {
  mkdir -p nuclei && cd nuclei || return 1
  if check_tool nuclei && [[ -s ../live/httpx_live.txt ]]; then
    run_with_progress "nuclei-all"      "nuclei_result.txt"   -- nuclei -l ../live/httpx_live.txt -rate-limit "$RATE_LIMIT" -c "$THREADS" -o nuclei_result.txt
    run_with_progress "nuclei-critical" "nuclei_critical.txt" -- nuclei -l ../live/httpx_live.txt -severity high,critical -rate-limit "$RATE_LIMIT" -c "$THREADS" -o nuclei_critical.txt
    # Severity alone misses a lot of "easy win" bugs that nuclei tags as info/low/medium
    # (exposed panels, default creds, leaked .git/backup files, debug endpoints, tokens...).
    # These are usually trivial to exploit even though their CVSS-style severity is low.
    run_with_progress "nuclei-exposures" "nuclei_exposures.txt" -- \
      nuclei -l ../live/httpx_live.txt \
        -tags exposure,misconfig,default-login,token,git,backup,exposed-panel,config,listing \
        -rate-limit "$RATE_LIMIT" -c "$THREADS" \
        -o nuclei_exposures.txt
  fi
  cd ..
}

step_takeover() {
  mkdir -p takeover && cd takeover || return 1
  if check_tool subjack; then
    wget -q https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O fingerprints.json
    run_with_progress "subjack" "takeover-results.txt" -- \
      subjack -w ../all_subdomains.txt -t "$THREADS" -timeout 30 -ssl -c fingerprints.json -v -o takeover-results.txt
  fi
  cd ..
}

step_keywords() {
  mkdir -p report
  grep -Ei "admin|login|debug|test|staging|internal|secret|api[_-]?key|token|auth" urls/all_urls.txt 2>/dev/null > report/flagged.txt
  local flagged_count
  flagged_count=$(wc -l < report/flagged.txt 2>/dev/null || echo 0)
  if [[ "$flagged_count" -gt 0 ]]; then
    echo -e "${yellow}[!] $flagged_count suspicious URLs flagged -> report/flagged.txt${reset}"
  else
    echo -e "${green}[✓] No suspicious URLs found.${reset}"
  fi
}

step_js() {
  mkdir -p js && cd js || return 1
  grep -E '\.js(\?|$)' ../urls/all_urls.txt 2>/dev/null | sort -u > js_urls.txt
  local js_total js_done=0
  js_total=$(wc -l < js_urls.txt)
  while read -r jsurl; do
    [[ -z "$jsurl" ]] && continue
    local fname
    fname=$(echo "$jsurl" | sed 's/[^a-zA-Z0-9]/_/g').js
    curl -sS --max-time 10 -L "$jsurl" -o "$fname" 2>/dev/null && js_done=$((js_done+1))
    printf "\r${cyan}⠋${reset} Downloading JS files  ${green}%d/%d${reset}   " "$js_done" "$js_total"
  done < js_urls.txt
  echo ""

  if [[ "$js_done" -gt 0 ]]; then
    echo -e "${cyan}  Scanning JS files for hidden endpoints & secrets...${reset}"
    python3 ../scan_js_secrets.py
  fi
  cd ..
}

step_cloud_exposure() {
  mkdir -p report
  if ! command -v python3 &> /dev/null; then
    echo -e "${red}  ⚠ python3 not found — skipping cloud exposure check${reset}"
    return 0
  fi
  python3 check_cloud_exposure.py "$domain"
}

step_source_maps() {
  mkdir -p report
  if ! command -v python3 &> /dev/null; then
    echo -e "${red}  ⚠ python3 not found — skipping source map check${reset}"
    return 0
  fi
  if [[ ! -s js/js_urls.txt ]]; then
    echo -e "${yellow}  no JS urls collected — skipping source map check${reset}"
    return 0
  fi
  python3 extract_source_maps.py
}

step_ai_report() {
  if [[ -z "$GEMINI_API_KEY" ]]; then
    echo -e "${red}  ⚠ GEMINI_API_KEY not set - skipping AI report.${reset}"
    echo -e "  ${dim}Put GEMINI_API_KEY=AIza... in $SCRIPT_DIR/.env then re-run this step.${reset}"
    return 1
  fi
  python3 generate_ai_report.py "$domain" "$GEMINI_MODEL"
}

# ---------- Scope validation ----------
# scope.txt lives next to this script (not inside a run folder) so it
# persists across runs/domains. One pattern per line:
#   *.example.com   -> matches example.com and any subdomain
#   example.com     -> matches only that exact host
#   !internal.example.com -> explicit exclusion, wins over any include match
scope_pattern_matches() {
  local domain="$1" pattern="$2"
  if [[ "$pattern" == \*.* ]]; then
    local base="${pattern#\*.}"
    [[ "$domain" == "$base" || "$domain" == *".$base" ]]
  else
    [[ "$domain" == "$pattern" ]]
  fi
}

check_scope() {
  local domain="$1"
  local scope_file="$SCRIPT_DIR/scope.txt"

  if [[ ! -f "$scope_file" ]]; then
    echo -e "${yellow}${bold}No scope.txt found next to this script.${reset}"
    echo -e "${dim}scope.txt records which domains you're authorized to test, and gets checked automatically on every future run.${reset}"
    read -p "Do you have written authorization to test '$domain'? Confirm to create scope.txt [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
      echo -e "${red}Aborting — no scope file and authorization not confirmed.${reset}"
      exit 1
    fi
    {
      echo "# Scope file for recon-framework.sh — one pattern per line."
      echo "# '*.domain.com' matches domain.com and every subdomain."
      echo "# 'domain.com' matches only that exact host."
      echo "# Prefix a line with '!' to explicitly exclude something (wins over any match above it)."
      echo "*.${domain}"
      echo "${domain}"
    } > "$scope_file"
    echo -e "${green}Created $scope_file with *.${domain} and ${domain}${reset}"
    return 0
  fi

  local includes=() excludes=()
  while IFS= read -r line; do
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ "$line" == !* ]]; then
      excludes+=("${line#!}")
    else
      includes+=("$line")
    fi
  done < "$scope_file"

  local in_scope=0
  for pattern in "${includes[@]}"; do
    if scope_pattern_matches "$domain" "$pattern"; then
      in_scope=1
      break
    fi
  done
  if [[ $in_scope -eq 1 ]]; then
    for pattern in "${excludes[@]}"; do
      if scope_pattern_matches "$domain" "$pattern"; then
        in_scope=0
        break
      fi
    done
  fi

  if [[ $in_scope -eq 0 ]]; then
    echo -e "${red}${bold}✗ '$domain' is NOT covered by $scope_file — refusing to scan.${reset}"
    echo -e "${dim}Add a matching line (e.g. *.${domain}) to $scope_file if you're authorized, then re-run.${reset}"
    exit 1
  fi

  echo -e "${green}✓ '$domain' is in scope ($scope_file validated)${reset}"
}

###############################################################################
# START
###############################################################################
banner

read -p "🔎 Enter target domain (must be in your bug bounty scope): " domain
if [[ -z "$domain" ]]; then
  echo -e "${red}No domain given, exiting.${reset}"; exit 1
fi

check_scope "$domain"

# ---------- Resume detection ----------
mapfile -t existing_dirs < <(ls -d recon-"${domain}"-* 2>/dev/null | sort -r)

WORKDIR=""
if [[ ${#existing_dirs[@]} -gt 0 ]]; then
  latest="${existing_dirs[0]}"
  echo -e "${yellow}Found a previous run for this domain: ${bold}${latest}${reset}"
  read -p "Resume it? [Y/n] " resume_choice
  resume_choice="${resume_choice:-Y}"
  if [[ "$resume_choice" =~ ^[Yy]$ ]]; then
    WORKDIR="$latest"
    echo -e "${green}Resuming: $WORKDIR${reset}"
  fi
fi

if [[ -z "$WORKDIR" ]]; then
  WORKDIR="recon-${domain}-$(date +%Y%m%d-%H%M)"
  echo -e "${green}Starting fresh run: $WORKDIR${reset}"
fi

mkdir -p "$WORKDIR"/{subdomains,permutation,resolve,live,content_discovery,urls,params,nuclei,takeover,js,wordpress,report,logs}
cp "$SCRIPT_DIR/scan_js_secrets.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/rate_limiter.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/merge_ffuf_results.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/check_sensitive_files.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/wordpress_scan.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/flag_interesting_params.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/extract_api_endpoints.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/check_cors_headers.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/check_misconfig.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/check_cloud_exposure.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/extract_source_maps.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/generate_ai_report.py" "$WORKDIR/" 2>/dev/null
cd "$WORKDIR" || exit 1
touch "$CHECKPOINT_FILE"

echo -e "${green}Output directory: ${bold}$(pwd)${reset}"
if [[ -s "$CHECKPOINT_FILE" ]]; then
  echo -e "${dim}Checkpoints already completed: $(paste -sd, "$CHECKPOINT_FILE")${reset}"
fi

###############################################################################
# RUN ALL STEPS (each one auto-skips if already checkpointed)
###############################################################################
run_step subdomains      step_subdomains
run_step permutation     step_permutation
run_step resolve         step_resolve
run_step probe            step_probe
run_step content_discovery step_content_discovery
run_step sensitive_files step_sensitive_files
run_step wordpress       step_wordpress
run_step api_extraction  step_api_extraction
run_step cors_headers    step_cors_headers
run_step misconfig       step_misconfig
run_step urls            step_urls
run_step params          step_params
run_step param_flagging  step_param_flagging
run_step xss             step_xss
run_step nuclei          step_nuclei
run_step takeover        step_takeover
run_step keywords        step_keywords
run_step js              step_js
run_step cloud_exposure  step_cloud_exposure
run_step source_maps     step_source_maps
run_step ai_report       step_ai_report

echo ""
echo -e "${green}${bold}✔ Recon complete.${reset} Results in: $(pwd)"
[[ -f report/attack_surface_report.html ]] && echo -e "${green}  Open report/attack_surface_report.html for the AI summary.${reset}"