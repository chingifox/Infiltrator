#!/bin/bash
set -euo pipefail

# dirs.sh
# - Try gobuster (directory-small). If site blocks fuzzing, inform user and skip gobuster.
# - ALWAYS extract .js URLs for each host (root HTML, robots.txt, sitemap.xml).
# - Save per-host list: js/<host>/js_files_with_names.txt   (format: <url> <filename>)
# - Save global deduped list: js/all_js_files.txt
#
# Usage: ./dirs.sh <domain> <outdir>
# Requires: gobuster, curl, sha256sum, grep, sed, awk, sort, xargs, basename

if [ $# -lt 2 ]; then
  echo "Usage: $0 <domain> <outdir>"
  exit 1
fi

domain="$1"
outdir="$2"
subdir="$outdir/subdomains"
live="$subdir/status/200_live.txt"
gobfile="$subdir/gobuster_dns.txt"
wordlist="${HOME:-~}/wordlists/directory-small.txt"
gobuster_opts="-q -t 30 -x js,php,html,txt,json,asp,aspx -b 301,302,307,308"

jsdir="$outdir/js"
mkdir -p "$jsdir"

# determine targets (prefer live 200 list)
targets="$outdir/targets_for_dirs.txt"
: > "$targets"
if [ -s "$live" ]; then
  awk '{print $1}' "$live" | sed -E 's|https?://||; s|/$||' > "$targets"
else
  awk '{print}' "$gobfile" | sed -E 's|https?://||; s|/$||' > "$targets"
fi

if ! [ -s "$targets" ]; then
  echo "[-] No targets (no live 200s and no gobuster subdomains). Exiting."
  exit 0
fi

# ---- helpers ----
fetch_body() {
  url="$1"; out="$2"
  curl -s -L --max-time 8 -w '%{http_code}' -o "$out" "$url" 2>/dev/null || printf "000"
}

detect_blocking() {
  host="$1"
  a=$(mktemp); b=$(mktemp); c=$(mktemp)
  rand(){ head -c12 /dev/urandom | tr -dc 'a-z0-9' | cut -c1-12; }
  p1="/$(rand)"; p2="/$(rand)"; p3="/$(rand)"

  code1=$(fetch_body "https://$host$p1" "$a"); [ "$code1" = "000" ] && code1=$(fetch_body "http://$host$p1" "$a")
  code2=$(fetch_body "https://$host$p2" "$b"); [ "$code2" = "000" ] && code2=$(fetch_body "http://$host$p2" "$b")
  code3=$(fetch_body "https://$host$p3" "$c"); [ "$code3" = "000" ] && code3=$(fetch_body "http://$host$p3" "$c")

  h1=$(sha256sum "$a" 2>/dev/null | awk '{print $1}' || echo "")
  h2=$(sha256sum "$b" 2>/dev/null | awk '{print $1}' || echo "")
  h3=$(sha256sum "$c" 2>/dev/null | awk '{print $1}' || echo "")

  rm -f "$a" "$b" "$c"

  # quick decision: if ALL 3 responses are 200 -> treat as blocked (uniform 200-on-miss)
  if [ "$code1" = "200" ] && [ "$code2" = "200" ] && [ "$code3" = "200" ]; then
    echo "    [!] Host $host returns 200 for random missing paths — treating as blocking (skip gobuster)."
    return 0
  fi

  codes_same=0
  [ "$code1" = "$code2" ] && codes_same=$((codes_same+1))
  [ "$code1" = "$code3" ] && codes_same=$((codes_same+1))
  [ "$code2" = "$code3" ] && codes_same=$((codes_same+1))

  hashes_same=0
  [ -n "$h1" ] && [ "$h1" = "$h2" ] && hashes_same=$((hashes_same+1))
  [ -n "$h1" ] && [ "$h1" = "$h3" ] && hashes_same=$((hashes_same+1))
  [ -n "$h2" ] && [ "$h2" = "$h3" ] && hashes_same=$((hashes_same+1))

  # majority non-200 (e.g., repeated 429/403) -> block
  non200=0
  [ "$code1" != "200" ] && non200=$((non200+1))
  [ "$code2" != "200" ] && non200=$((non200+1))
  [ "$code3" != "200" ] && non200=$((non200+1))

  # heuristics: consistent status+body OR majority non-200 => treat as blocking
  if [ "$codes_same" -ge 1 ] && [ "$hashes_same" -ge 1 ]; then
    return 0
  fi
  if [ "$non200" -ge 2 ]; then
    return 0
  fi

  return 1
}


# extract .js URLs from host root, robots, sitemap (light, no recursive crawling)
extract_js_from_host() {
  host="$1"
  out="$2"   # file to append urls to
  tmp=$(mktemp)

  # root HTML
  code=$(fetch_body "https://$host/" "$tmp"); [ "$code" = "000" ] && code=$(fetch_body "http://$host/" "$tmp")

  # script src extraction
  grep -oiE '<script[^>]+src=["'"'"'][^"'"'"' ]+\.js[^"'"'"' ]*' "$tmp" 2>/dev/null \
    | sed -E 's/.*src=["'"'"']?([^"'"'"' >]+).*/\1/' \
    | while IFS= read -r src; do
        [ -z "$src" ] && continue
        case "$src" in
          //*) echo "https:${src}" ;;
          http*) echo "$src" ;;
          /*) echo "https://$host${src}" ;;
          *) echo "https://$host/${src#./}" ;;
        esac
      done >> "$out" 2>/dev/null || true

  rm -f "$tmp"

  # robots -> capture sitemap URLs (do not fetch all sitemap entries)
  tmp2=$(mktemp)
  rc=$(fetch_body "https://$host/robots.txt" "$tmp2"); [ "$rc" = "000" ] && rc=$(fetch_body "http://$host/robots.txt" "$tmp2")
  if [ -s "$tmp2" ]; then
    grep -i '^sitemap:' "$tmp2" | awk '{print $2}' >> "$out" 2>/dev/null || true
  fi
  rm -f "$tmp2"

  # sitemap.xml -> pull first N locs (light) and extract script srcs from those pages (range-limited)
  tmp3=$(mktemp)
  scode=$(fetch_body "https://$host/sitemap.xml" "$tmp3"); [ "$scode" = "000" ] && scode=$(fetch_body "http://$host/sitemap.xml" "$tmp3")
  if [ -s "$tmp3" ]; then
    grep -Eo '<loc>[^<]+' "$tmp3" 2>/dev/null \
      | sed 's/<loc>//' \
      | head -n 50 \
      | while IFS= read -r loc; do

          # DO NOT save the sitemap URL
          # ONLY extract JS from linked pages

          # if loc ends with .js, extract only that file — but do NOT save the sitemap
          if echo "$loc" | grep -qE '\.js($|\?)'; then
            echo "$loc" >> "$out"
            continue
          fi

          # otherwise fetch the *page content* partially and extract JS
          tmp4=$(mktemp)
          curl -sS --compressed --range 0-32768 -m 8 "$loc" -o "$tmp4" 2>/dev/null || true

          grep -oiE '<script[^>]+src=["'"'"'][^"'"'"' ]+\.js[^"'"'"' ]*' "$tmp4" 2>/dev/null \
            | sed -E 's/.*src=["'"'"']?([^"'"'"' >]+).*/\1/' \
            | while IFS= read -r src; do
                case "$src" in
                  //*) echo "https:${src}" ;;
                  http*) echo "$src" ;;
                  /*) base=$(echo "$loc" | sed -E 's|(https?://[^/]+).*|\1|'); echo "${base}${src}" ;;
                  *) base=$(echo "$loc" | sed -E 's|(https?://.*/).*|\1|'); echo "${base}${src#./}" ;;
                esac
              done >> "$out"

          rm -f "$tmp4"
        done
  fi
  rm -f "$tmp3"
}

# --- robust helper wrappers (ensure non-zero exits in pipelines don't kill script) ---

# safe_fetch_body (optional) - identical behavior to fetch_body but explicit name
safe_fetch_body() {
  url="$1"; out="$2"
  code=$(curl -s -L --max-time 8 -w '%{http_code}' -o "$out" "$url" 2>/dev/null || printf "000")
  printf "%s" "$code"
}

# safe_grepextract: run a grep pipeline but never fail the script
safe_grepextract() {
  pattern="$1"; infile="$2"
  grep -Eo "$pattern" "$infile" 2>/dev/null || true
}
: > "$jsdir/all_js_files.txt"

while IFS= read -r host || [ -n "$host" ]; do
  [ -z "$host" ] && continue
  echo "[-] Processing host: $host"

  blocked=1
  # wrap detect in a subshell that won't abort on unexpected failures
  if ( detect_blocking "$host" ) 2>/dev/null; then
    echo "    [!] Detected rate-limiting / fake-200s or consistent non-existent behaviour on $host."
    echo "    [!] Skipping aggressive directory fuzzing for this host and switching to JS extraction only."
    blocked=0
  fi

  # prepare per-host dirs
  mkdir -p "$jsdir/$host"
  host_out="$jsdir/$host/js_files_raw.txt"
  : > "$host_out"

  # Run gobuster only if not blocked
  if [ "$blocked" -eq 1 ]; then
    echo "    [*] Running gobuster on $host (wordlists/directory-small.txt)"
    tmpgob=$(mktemp)

    # run gobuster but do not let its exit code kill the script
    if gobuster dir -u "https://$host" -w "$wordlist" $gobuster_opts 2>&1 | tee "$tmpgob"; then
      :
    else
      # try http; ignore failures
      gobuster dir -u "http://$host" -w "$wordlist" $gobuster_opts 2>&1 | tee -a "$tmpgob" || true
    fi

    # extract any .js mentions from gobuster output (safe)
    safe_grepextract '(/[A-Za-z0-9/_\.-]+\.js)' "$tmpgob" | sed "s|^|https://$host|" >> "$host_out" || true
    rm -f "$tmpgob"
  else
    echo "    [*] Gobuster skipped for $host."
  fi

  # ALWAYS run light JS extraction (root, robots, sitemap) and append to host_out
  # run in a subshell so any internal failures are contained
  (
    extract_js_from_host "$host" "$host_out"
  ) || true

  # normalize, remove duplicates (guard against sort failure)
  if [ -s "$host_out" ]; then
    sort -u "$host_out" 2>/dev/null | sed -E 's/[[:space:]]+$//' > "$jsdir/$host/js_files_unique.txt" || {
      # fallback: copy raw if sort failed
      cp -f "$host_out" "$jsdir/$host/js_files_unique.txt"
    }
  else
    : > "$jsdir/$host/js_files_unique.txt"
  fi

  # remove raw file
  rm -f "$host_out"

  # append per-host unique JS URLs to global list (append safely)
  if [ -s "$jsdir/$host/js_files_unique.txt" ]; then
    cat "$jsdir/$host/js_files_unique.txt" >> "$jsdir/all_js_files.txt"
    echo "    [+] Found $(wc -l < "$jsdir/$host/js_files_unique.txt") JS URLs for $host"
  else
    echo "    [!] No JS found for $host"
  fi

  # short delay to be nice to remote servers (optional, comment out if you prefer)
  sleep 0.2

done < "$targets"

# global dedupe (after loop) - tolerant to failures
if [ -s "$jsdir/all_js_files.txt" ]; then
  sort -u "$jsdir/all_js_files.txt" -o "$jsdir/all_js_files.txt" 2>/dev/null || true
  echo
  echo "[+] Collected JS files: $jsdir/all_js_files.txt ($(wc -l < "$jsdir/all_js_files.txt" 2>/dev/null || echo 0))"
else
  echo
  echo "[+] No JS files collected."
fi

echo
echo "[+] Done. Ready to feed all_js_files.txt into n8n for AI triage."
