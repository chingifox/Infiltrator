#!/bin/bash
set -euo pipefail

domain="$1"
outdir="$2"
sddir="$outdir/subdomains"
gout="$sddir/gobuster_dns.txt"
httpx_out="$sddir/httpx_sc.txt"
status_dir="$sddir/status"

mkdir -p "$sddir"
: > "$gout"

echo "[-] Running subdomain enumeration for $domain"

stdbuf -oL gobuster dns -zq -d "$domain" -w ~/wordlists/subdomains_tiny.txt 2>&1 \
  | tee >(sed -n 's/.*Found: \([A-Za-z0-9._-]\+\).*/\1/p' >> "$gout") \
  | awk '
    function strip_ansi(s) { gsub(/\033\[[0-9;]*[mK]/, "", s); return s }
    {
      line = strip_ansi($0)
      if (match(line, /Found:[[:space:]]*([A-Za-z0-9._-]+)/, m)) {
        printf("\r\033[KFound subdomain: %s", m[1])
        fflush()
      }
    }
    END { print "" }
  '

echo
echo "[+] $(wc -l < "$gout") Subdomains stored in $gout"
echo

# ---- httpx probing and categorization ----
echo "[-] Probing hosts with httpx"

# line-buffer stdout & stderr for httpx so live display updates
stdbuf -oL -eL httpx -silent -sc -nc -fr -l "$gout" \
  | tee "$httpx_out" \
  | awk '
      {
        url=$1
        match($0, /\[([0-9,]+)\]/, m)
        code=m[1]
        split(code, arr, ",")
        status=arr[length(arr)]
        if (status == "") status="?"
        printf("\r\033[KProbing: %-60s -> %s", url, status)
        fflush()
      }
    END { print "\n" }'

mkdir -p "$status_dir"
: > "$status_dir/200_live.txt"
: > "$status_dir/403_subdomains.txt"
: > "$status_dir/404_subdomains.txt"
: > "$status_dir/others.txt"
: > "$status_dir/3xx_discovered.txt"

# Parse saved httpx output and categorize (and capture redirect-discovered hosts)
while IFS= read -r line || [ -n "$line" ]; do
    url=$(echo "$line" | awk '{print $1}')
    code=$(echo "$line" | grep -o "\[[0-9,]\+\]" | tr -d '[]' | awk -F',' '{print $NF}')
    code=${code:-"?"}

    case "$code" in
        200)
            echo "$url" >> "$status_dir/200_live.txt"
            ;;
        403)
            echo "$url" >> "$status_dir/403_subdomains.txt"
            ;;
        404)
            echo "$url" >> "$status_dir/404_subdomains.txt"
            ;;
        3[0-9][0-9])
            echo "$url [$code]" >> "$status_dir/others.txt"
            # look for a redirect target like "-> https://host/path"
            redirects=$(echo "$line" | sed -n 's/.*->[[:space:]]*\(https\?:\/\/[^ ]*\).*/\1/p' || true)
            if [ -n "$redirects" ]; then
                host=$(echo "$redirects" | awk -F/ '{print $3}' | sed 's/:.*//')
                if [ -n "$host" ]; then
                    if ! grep -Fxq "$host" "$gout"; then
                        echo "$host" >> "$gout"
                        echo "$host" >> "$status_dir/3xx_discovered.txt"
                        # print a clean discovery line (does not disturb the probing line)
                        printf "\r\033[KNew subdomain discovered via redirect: %s\n" "$host"
                    fi
                fi
            fi
            ;;
        *)
            echo "$url [$code]" >> "$status_dir/others.txt"
            ;;
    esac
done < "$httpx_out"

# Final clean output / summary
printf "%s\n" "----------------------------------------"
printf "%s\n" "[+] Categorized HTTP responses:"
printf "    %-6s %s\n" "200:"   "$(wc -l < "$status_dir/200_live.txt")"
printf "    %-6s %s\n" "403:"   "$(wc -l < "$status_dir/403_subdomains.txt")"
printf "    %-6s %s\n" "404:"   "$(wc -l < "$status_dir/404_subdomains.txt")"
printf "    %-6s %s\n" "other:" "$(wc -l < "$status_dir/others.txt")"
printf "%s\n" "[+] Output stored in:"
printf "    %s\n" "$status_dir"
echo
