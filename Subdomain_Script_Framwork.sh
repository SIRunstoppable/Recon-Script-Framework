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

# ---------- Config ----------
# GEMINI_API_KEY comes from .env (see .env.example)
GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.0-flash}"   # check https://ai.google.dev/gemini-api/docs/models for current names
THREADS=100

# ---------- Step tracking ----------
# key = stable ID stored in the checkpoint file. label = what's shown to the user.
STEP_KEYS=(subdomains resolve probe urls params nuclei takeover keywords js ai_report)
STEP_LABELS=(
  "Subdomain Enumeration"
  "DNS Resolution Check"
  "Probe Alive Hosts"
  "Collect URLs (Wayback/GAU)"
  "Parameter Discovery"
  "Nuclei Vulnerability Scan"
  "Subdomain Takeover Check"
  "Sensitive Keyword Grep"
  "JavaScript File Harvest"
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
    gobuster dns -d "$domain" -r /etc/resolv.conf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --wildcard -q -o gobuster.txt

  cat ./*.txt 2>/dev/null | cut -d ' ' -f1 | sed '/^$/d' | sort -u > ../all_subdomains.txt
  cd ..
  echo -e "${green}[+] Total unique subdomains: $(wc -l < all_subdomains.txt)${reset}"
}

step_resolve() {
  mkdir -p resolve && cd resolve || return 1
  if check_tool dnsx; then
    run_with_progress "dnsx" "resolved_subdomains.txt" -- \
      dnsx -l ../all_subdomains.txt -silent -o resolved_subdomains.txt
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
      httpx -l "$target_list" -title -tech-detect -status-code -ip -o httpx_live.txt
  fi
  cd ..
  echo -e "${green}[+] Live hosts: $(cat live/httpx_live.txt 2>/dev/null | wc -l | tr -d ' ')${reset}"
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
    arjun -i urls_no_params.txt -o arjun_out.txt

  cat ../urls/all_urls.txt 2>/dev/null | awk -F/ '{print $3}' | grep -E "(\.|^)${domain}$" | sort -u > for_paramspider.txt
  check_tool paramspider && run_with_progress "paramspider" "" -- paramspider -l for_paramspider.txt
  cd ..
}

step_nuclei() {
  mkdir -p nuclei && cd nuclei || return 1
  if check_tool nuclei && [[ -s ../live/httpx_live.txt ]]; then
    run_with_progress "nuclei-all"      "nuclei_result.txt"   -- nuclei -l ../live/httpx_live.txt -o nuclei_result.txt
    run_with_progress "nuclei-critical" "nuclei_critical.txt" -- nuclei -l ../live/httpx_live.txt -severity high,critical -o nuclei_critical.txt
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

step_ai_report() {
  if [[ -z "$GEMINI_API_KEY" ]]; then
    echo -e "${red}  ⚠ GEMINI_API_KEY not set - skipping AI report.${reset}"
    echo -e "  ${dim}Put GEMINI_API_KEY=AIza... in $SCRIPT_DIR/.env then re-run this step.${reset}"
    return 1
  fi
  python3 generate_ai_report.py "$domain" "$GEMINI_MODEL"
}

###############################################################################
# START
###############################################################################
banner

read -p "🔎 Enter target domain (must be in your bug bounty scope): " domain
if [[ -z "$domain" ]]; then
  echo -e "${red}No domain given, exiting.${reset}"; exit 1
fi

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

mkdir -p "$WORKDIR"/{subdomains,resolve,live,urls,params,nuclei,takeover,js,report,logs}
cp "$SCRIPT_DIR/scan_js_secrets.py" "$WORKDIR/" 2>/dev/null
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
run_step subdomains step_subdomains
run_step resolve    step_resolve
run_step probe      step_probe
run_step urls       step_urls
run_step params     step_params
run_step nuclei     step_nuclei
run_step takeover   step_takeover
run_step keywords   step_keywords
run_step js         step_js
run_step ai_report  step_ai_report

echo ""
echo -e "${green}${bold}✔ Recon complete.${reset} Results in: $(pwd)"
[[ -f report/attack_surface_report.html ]] && echo -e "${green}  Open report/attack_surface_report.html for the AI summary.${reset}"