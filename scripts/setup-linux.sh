#!/usr/bin/env bash
# Linux bootstrap. Optional scanners are detected, never installed from remote scripts.
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo 'Linux is required.' >&2; exit 2; }
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
case ${1:-} in
  --check)
    if [[ ! -x "$project_dir/.venv/bin/python" ]]; then
      echo 'Run bash scripts/setup-linux.sh first to create the virtual environment.' >&2
      exit 2
    fi
    exec "$project_dir/.venv/bin/python" "$project_dir/twiy.py" --check
    ;;
  '') ;;
  *) echo 'Usage: bash scripts/setup-linux.sh [--check]' >&2; exit 2 ;;
esac
command -v python3 >/dev/null || { echo 'Install python3 and python3-venv.' >&2; exit 2; }
python3 -m venv "$project_dir/.venv"
"$project_dir/.venv/bin/python" -m pip install -r "$project_dir/requirements.txt"
missing=()
for scanner in nmap whatweb; do
  command -v "$scanner" >/dev/null || missing+=("$scanner")
done
if ((${#missing[@]})); then
  echo "Missing required Linux scanners: ${missing[*]}"
  echo "On Kali/Ubuntu: sudo apt install python3-venv ${missing[*]}"
fi
"$project_dir/.venv/bin/python" "$project_dir/twiy.py" --check
echo "Start: $project_dir/.venv/bin/python $project_dir/twiy.py"
