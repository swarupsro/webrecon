#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# Generic Safe Web Recon + Vulnerability Pipeline
# Notes:
# - Low rate, non-intrusive, discovery-first approach
# - Suitable for production environments with authorization
# ------------------------------------------------------------

# ================= Configuration ============================
PROJECT_DIR="${PROJECT_DIR:-$HOME/assessments/web-scan}"
INPUT_DIR="$PROJECT_DIR/input"
OUTPUT_DIR="$PROJECT_DIR/output"
LOG_DIR="$PROJECT_DIR/logs"

RATE_LIMIT="${RATE_LIMIT:-10}"   # Recommended: 5-10
KATANA_CONCURRENCY="${KATANA_CONCURRENCY:-5}"
KATANA_PARALLELISM="${KATANA_PARALLELISM:-5}"
DALFOX_WORKERS="${DALFOX_WORKERS:-5}"

# Optional proxy (e.g. Burp)
# export PROXY="http://127.0.0.1:8080"
PROXY="${PROXY:-}"

TARGETS_FILE="${TARGETS_FILE:-$INPUT_DIR/targets.txt}"
HEADERS_FILE="${HEADERS_FILE:-$INPUT_DIR/headers.txt}"

DOMAIN="${DOMAIN:-}"
SUBDOMAIN_MODE="${SUBDOMAIN_MODE:-0}"
# ============================================================

usage() {
  cat <<EOF
Usage:
  $(basename "$0") --single
  $(basename "$0") --subdomains example.com

Optional:
  --rate N
  --proxy http://127.0.0.1:8080
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Missing dependency: $1"
    exit 1
  }
}

log() { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --single)
        SUBDOMAIN_MODE=0
        shift
        ;;
      --subdomains)
        SUBDOMAIN_MODE=1
        DOMAIN="${2:-}"
        shift 2
        ;;
      --rate)
        RATE_LIMIT="${2:-}"
        shift 2
        ;;
      --proxy)
        PROXY="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        warn "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

init_dirs() {
  mkdir -p "$INPUT_DIR" "$OUTPUT_DIR" "$LOG_DIR"

  [[ -f "$HEADERS_FILE" ]] || cat > "$HEADERS_FILE" <<'EOF'
User-Agent: Authorized-Security-Assessment/1.0
Accept: */*
Connection: close
EOF

  [[ -f "$TARGETS_FILE" ]] || cat > "$TARGETS_FILE" <<'EOF'
https://example.com
EOF
}

build_flags() {
  HEADER_FLAGS=($(awk 'NF{print "-H"; print $0}' "$HEADERS_FILE"))

  HTTPX_FLAGS=(-silent -follow-redirects -rate-limit "$RATE_LIMIT" "${HEADER_FLAGS[@]}")
  NUCLEI_FLAGS=(-silent -rate-limit "$RATE_LIMIT" -retries 1 -timeout 8 "${HEADER_FLAGS[@]}")
  KATANA_FLAGS=(-silent -jc -kf -c "$KATANA_CONCURRENCY" -p "$KATANA_PARALLELISM" -rate-limit "$RATE_LIMIT" "${HEADER_FLAGS[@]}")

  [[ -n "$PROXY" ]] && {
    HTTPX_FLAGS+=(-proxy "$PROXY")
    NUCLEI_FLAGS+=(-proxy "$PROXY")
    KATANA_FLAGS+=(-proxy "$PROXY")
  }
}

prepare_targets() {
  if [[ "$SUBDOMAIN_MODE" -eq 1 ]]; then
    need_cmd subfinder
    subfinder -silent -all -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains.txt"

    cat "$OUTPUT_DIR/subdomains.txt" | httpx "${HTTPX_FLAGS[@]}" -o "$OUTPUT_DIR/live.txt"
  else
    cat "$TARGETS_FILE" | httpx "${HTTPX_FLAGS[@]}" -status-code -title -tech-detect -o "$OUTPUT_DIR/live.txt"
  fi
}

run_katana() {
  cat "$OUTPUT_DIR/live.txt" | katana "${KATANA_FLAGS[@]}" -o "$OUTPUT_DIR/katana_urls.txt"
}

run_history() {
  need_cmd gau
  need_cmd waybackurls

  awk '{print $1}' "$OUTPUT_DIR/live.txt" | sed 's#https\?://##' | cut -d/ -f1 | sort -u > "$OUTPUT_DIR/hosts.txt"

  cat "$OUTPUT_DIR/hosts.txt" | gau --subs --threads 5 > "$OUTPUT_DIR/gau_urls.txt" || true
  cat "$OUTPUT_DIR/hosts.txt" | waybackurls > "$OUTPUT_DIR/wayback_urls.txt" || true

  cat "$OUTPUT_DIR/katana_urls.txt" "$OUTPUT_DIR/gau_urls.txt" "$OUTPUT_DIR/wayback_urls.txt" \
    | grep -E '^https?://' | sort -u > "$OUTPUT_DIR/all_urls.txt"

  grep -E '\?.+=' "$OUTPUT_DIR/all_urls.txt" | sort -u > "$OUTPUT_DIR/param_urls.txt" || true
}

run_nuclei() {
  need_cmd nuclei
  cat "$OUTPUT_DIR/live.txt" | nuclei "${NUCLEI_FLAGS[@]}" \
    -severity low,medium,high,critical \
    -tags misconfig,exposure,tech,headers,cve \
    -o "$OUTPUT_DIR/nuclei_findings.txt"
}

run_dalfox() {
  need_cmd dalfox
  [[ -s "$OUTPUT_DIR/param_urls.txt" ]] || return 0

  dalfox file "$OUTPUT_DIR/param_urls.txt" \
    --silence \
    --worker "$DALFOX_WORKERS" \
    --timeout 8 \
    --header "User-Agent: Authorized-Security-Assessment/1.0" \
    --only-discovery \
    --output "$OUTPUT_DIR/dalfox_xss.txt"
}

summary() {
  echo
  log "Scan Summary"
  echo "Live targets     : $(wc -l < "$OUTPUT_DIR/live.txt")"
  echo "Total URLs       : $(wc -l < "$OUTPUT_DIR/all_urls.txt")"
  echo "Parameterized    : $(wc -l < "$OUTPUT_DIR/param_urls.txt" 2>/dev/null || echo 0)"
  echo "Nuclei findings  : $(wc -l < "$OUTPUT_DIR/nuclei_findings.txt" 2>/dev/null || echo 0)"
  echo "Dalfox results   : $(wc -l < "$OUTPUT_DIR/dalfox_xss.txt" 2>/dev/null || echo 0)"
}

main() {
  parse_args "$@"
  need_cmd httpx
  need_cmd katana

  init_dirs
  build_flags
  prepare_targets
  run_katana
  run_history
  run_nuclei
  run_dalfox
  summary
}

main "$@"
