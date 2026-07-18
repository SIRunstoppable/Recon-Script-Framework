#!/bin/bash
###############################################################################
#  R E C O N   F R A M E W O R K   -   AI-Assisted Attack Surface Mapper
#  For authorized bug bounty / pentest use only.
###############################################################################

set -o pipefail

# ---------- Colors ----------
red="\e[91m"; green="\e[92m"; blue="\e[94m"; yellow="\e[93m"
cyan="\e[96m"; bold="\e[1m"; dim="\e[2m"; reset="\e[0m"

# ---------- Config ----------
# Set this env var before running: export GEMINI_API_KEY="AIza..."
GEMINI_MODEL="gemini-2.0-flash"          # check https://ai.google.dev/gemini-api/docs/models for current names
THREADS=100

# ---------- Step tracking ----------
STEPS=(
  "Subdomain Enumeration"
  "Probe Alive Hosts"
  "Collect URLs (Wayback/GAU)"
  "Parameter Discovery"
  "Nuclei Vulnerability Scan"
  "Subdomain Takeover Check"
  "Sensitive Keyword Grep"
  "JavaScript File Harvest"
  "AI Attack Surface Report"
)
TOTAL_STEPS=${#STEPS[@]}
CURRENT_STEP=0

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
  echo -e "${blue}${bold}[${CURRENT_STEP}/${TOTAL_STEPS}] ${STEPS[$((CURRENT_STEP-1))]}${reset}"
  echo -e "${dim}────────────────────────────────────────────────────────────${reset}"
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

  # run the real command in background, log everything
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
# START
###############################################################################
banner

read -p "🔎 Enter target domain (must be in your bug bounty scope): " domain
if [[ -z "$domain" ]]; then
  echo -e "${red}No domain given, exiting.${reset}"; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="recon-${domain}-$(date +%Y%m%d-%H%M)"
mkdir -p "$WORKDIR"/{subdomains,live,urls,params,nuclei,takeover,js,report,logs}
cp "$SCRIPT_DIR/scan_js_secrets.py" "$WORKDIR/" 2>/dev/null
cp "$SCRIPT_DIR/generate_ai_report.py" "$WORKDIR/" 2>/dev/null
cd "$WORKDIR" || exit 1

echo -e "${green}Output directory: ${bold}$(pwd)${reset}"

###############################################################################
# STEP 1: Subdomain enumeration
###############################################################################
step_header
cd subdomains || exit 1

check_tool subfinder && run_with_progress "subfinder" "subfinder.txt" -- subfinder -d "$domain" -o subfinder.txt
check_tool amass     && run_with_progress "amass"     "amass.txt"     -- amass enum -d "$domain" -o amass.txt
check_tool sublist3r && run_with_progress "sublist3r" "sublist3r.txt" -- sublist3r -d "$domain" -o sublist3r.txt
check_tool gobuster  && run_with_progress "gobuster"  "gobuster.txt"  -- \
  gobuster dns -d "$domain" -r /etc/resolv.conf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --wildcard -q -o gobuster.txt

cat ./*.txt 2>/dev/null | cut -d ' ' -f1 | sed '/^$/d' | sort -u > ../all_subdomains.txt
cd ..
echo -e "${green}[+] Total unique subdomains: $(wc -l < all_subdomains.txt)${reset}"

###############################################################################
# STEP 2: Probe alive hosts
###############################################################################
step_header
cd live || exit 1
if check_tool httpx; then
  run_with_progress "httpx" "httpx_live.txt" -- \
    httpx -l ../all_subdomains.txt -title -tech-detect -status-code -ip -o httpx_live.txt
fi
cd ..
echo -e "${green}[+] Live hosts: $(wc -l < live/httpx_live.txt 2>/dev/null || echo 0)${reset}"

###############################################################################
# STEP 3: URL collection
###############################################################################
step_header
cd urls || exit 1
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

###############################################################################
# STEP 4: Parameter discovery
###############################################################################
step_header
cd params || exit 1
grep -E "\?" ../urls/all_urls.txt 2>/dev/null | sort -u > urls_with_params.txt
grep -v -E "\?" ../urls/all_urls.txt 2>/dev/null | sort -u > urls_no_params.txt
check_tool arjun && run_with_progress "arjun" "arjun_out.txt" -- \
  arjun -i urls_no_params.txt -o arjun_out.txt

cat ../urls/all_urls.txt 2>/dev/null | awk -F/ '{print $3}' | grep -E "(\.|^)${domain}$" | sort -u > for_paramspider.txt
check_tool paramspider && run_with_progress "paramspider" "" -- paramspider -l for_paramspider.txt
cd ..

###############################################################################
# STEP 5: Nuclei scan
###############################################################################
step_header
cd nuclei || exit 1
if check_tool nuclei && [[ -s ../live/httpx_live.txt ]]; then
  run_with_progress "nuclei-all"      "nuclei_result.txt"   -- nuclei -l ../live/httpx_live.txt -o nuclei_result.txt
  run_with_progress "nuclei-critical" "nuclei_critical.txt" -- nuclei -l ../live/httpx_live.txt -severity high,critical -o nuclei_critical.txt
fi
cd ..

###############################################################################
# STEP 6: Subdomain takeover
###############################################################################
step_header
cd takeover || exit 1
if check_tool subjack; then
  wget -q https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O fingerprints.json
  run_with_progress "subjack" "takeover-results.txt" -- \
    subjack -w ../all_subdomains.txt -t "$THREADS" -timeout 30 -ssl -c fingerprints.json -v -o takeover-results.txt
fi
cd ..

###############################################################################
# STEP 7: Sensitive keyword grep
###############################################################################
step_header
grep -Ei "admin|login|debug|test|staging|internal|secret|api[_-]?key|token|auth" urls/all_urls.txt 2>/dev/null > report/flagged.txt
FLAGGED_COUNT=$(wc -l < report/flagged.txt 2>/dev/null || echo 0)
if [[ "$FLAGGED_COUNT" -gt 0 ]]; then
  echo -e "${yellow}[!] $FLAGGED_COUNT suspicious URLs flagged -> report/flagged.txt${reset}"
else
  echo -e "${green}[✓] No suspicious URLs found.${reset}"
fi

###############################################################################
# STEP 8: JS harvesting
###############################################################################
step_header
cd js || exit 1
grep -E '\.js(\?|$)' ../urls/all_urls.txt 2>/dev/null | sort -u > js_urls.txt
JS_TOTAL=$(wc -l < js_urls.txt)
JS_DONE=0
while read -r jsurl; do
  [[ -z "$jsurl" ]] && continue
  fname=$(echo "$jsurl" | sed 's/[^a-zA-Z0-9]/_/g').js
  curl -sS --max-time 10 -L "$jsurl" -o "$fname" 2>/dev/null && JS_DONE=$((JS_DONE+1))
  printf "\r${cyan}⠋${reset} Downloading JS files  ${green}%d/%d${reset}   " "$JS_DONE" "$JS_TOTAL"
done < js_urls.txt
echo ""

if [[ "$JS_DONE" -gt 0 ]]; then
  echo -e "${cyan}  Scanning JS files for hidden endpoints & secrets...${reset}"
  python3 ../scan_js_secrets.py
fi
cd ..

###############################################################################
# STEP 9: AI Attack Surface Report
###############################################################################
step_header

if [[ -z "$GEMINI_API_KEY" ]]; then
  echo -e "${red}  ⚠ GEMINI_API_KEY not set - skipping AI report.${reset}"
  echo -e "  ${dim}export GEMINI_API_KEY=\"AIza...\" then re-run this step.${reset}"
else
  python3 generate_ai_report.py "$domain" "$GEMINI_MODEL"
fi

echo ""
echo -e "${green}${bold}✔ Recon complete.${reset} Results in: $(pwd)"
[[ -f report/attack_surface_report.html ]] && echo -e "${green}  Open report/attack_surface_report.html for the AI summary.${reset}"