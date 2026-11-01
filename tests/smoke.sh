#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m py_compile gnp_node.py gnp_mtls.py gnp_hc_job.py
python3 gnp_mtls.py --help >/dev/null
python3 -c "import gnp_hc_job"
python3 gnp_node.py --help >/dev/null 2>&1 || true
echo SMOKE_OK
