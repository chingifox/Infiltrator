#!/bin/bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
    read -r -p "Enter target domain: " target
else
    target="$1"
fi

echo "[+] Target: $target"

project_dir="/home/vandan/recon/$target"
mkdir -p "$project_dir"

# ./subdomains.sh "$target" "$project_dir"

# ./dirs.sh "$target" "$project_dir"

echo
read -r -p "[+] Press ENTER to send JS list to n8n..." _

curl -X POST "http://0.0.0.0:5678/webhook-test/js-list" \
     --data-binary @"$project_dir/js/all_js_files.txt"
echo "Sent successfully! Look for output in n8n_output/sensitive_urls.json"


if [ -s "$project_dir/subdomains/status/403_subdomains.txt" ]; then
    echo "[-] Running 403 bypass module (python requests)"

    script="$(dirname "$0")/403_bypass.py"

    if [ -f "$script" ]; then   
        chmod +x "$script" || true
        python3 "$script" "$project_dir"
        echo "[+] 403 bypass results saved → $project_dir/bypass_403/"
    else
        echo "[!] 403_bypass.py missing — skipping."
    fi
else
    echo "[-] No 403 hosts — skip 403 bypass."
fi


script="/home/vandan/recon/path_traversal.py"
if [ -f "$script" ]; then

  python3 "$script" "$project_dir" 
fi

./visualize.sh "$target" "$project_dir"
