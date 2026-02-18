#!/usr/bin/env bash
set -euo pipefail

# ---- Config (anpassen) ----
BASE_URL="${BASE_URL:-http://localhost:3000}"
PROJECT_ID="${PROJECT_ID:-4}"
REPORT_ROOT="${REPORT_ROOT:-/var/snap/semaphore/common/reports}"

# Credentials (am besten als Semaphore Environment Variables setzen)
SEMA_USER="${SEMA_USER:-testadmin}"
SEMA_PASS="${SEMA_PASS:-}"

# Task ID muss kommen (Argument 1 oder ENV TASK_ID)
TASK_ID="${1:-${TASK_ID:-}}"

if [[ -z "${TASK_ID}" ]]; then
  echo "ERROR: TASK_ID fehlt. Übergib sie als Argument oder ENV TASK_ID." >&2
  exit 2
fi

if [[ -z "${SEMA_PASS}" ]]; then
  echo "ERROR: SEMA_PASS fehlt. Setze es als Environment Variable im Semaphore Task." >&2
  exit 2
fi

command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found"; exit 127; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 127; }

TS="$(date +%Y%m%d_%H%M%S)"
mkdir -p "${REPORT_ROOT}"
OUTDIR="${REPORT_ROOT}/${TS}_task${TASK_ID}"
mkdir -p "${OUTDIR}"

COOKIE_FILE="${OUTDIR}/cookies.txt"
META_JSON="${OUTDIR}/task_${TASK_ID}.json"
OUTPUT_TXT="${OUTDIR}/output.txt"
UI_TXT="${OUTDIR}/${TS}_task${TASK_ID}_semaphore_ui.txt"

# 1) Login -> cookies.txt
curl -s -c "${COOKIE_FILE}" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"auth\":\"${SEMA_USER}\",\"password\":\"${SEMA_PASS}\"}" \
  "${BASE_URL}/api/auth/login" > /dev/null

# 2) Task Meta holen (JSON)
curl -s -b "${COOKIE_FILE}" \
  "${BASE_URL}/api/project/${PROJECT_ID}/tasks/${TASK_ID}" > "${META_JSON}"

# 3) Task Output holen (wie händisch > output.txt)
curl -s -b "${COOKIE_FILE}" \
  "${BASE_URL}/api/project/${PROJECT_ID}/tasks/${TASK_ID}/output" > "${OUTPUT_TXT}"

# 4) Header aus JSON extrahieren (Status/Created/Start/Ende)
STATUS="$(python3 -c 'import json; d=json.load(open("'"${META_JSON}"'")); print(d.get("status",""))')"
CREATED="$(python3 -c 'import json; d=json.load(open("'"${META_JSON}"'")); print(d.get("created",""))')"
STARTED="$(python3 -c 'import json; d=json.load(open("'"${META_JSON}"'")); print(d.get("start",""))')"
ENDED="$(python3 -c 'import json; d=json.load(open("'"${META_JSON}"'")); print(d.get("end",""))')"

# 5) UI-like TXT bauen (Header + Output 1:1)
{
  echo "Task #${TASK_ID}"
  echo "Status: ${STATUS}"
  echo "Author: ${SEMA_USER}"
  echo "Created: ${CREATED}"
  echo "Started: ${STARTED}"
  echo "Ended: ${ENDED}"
  echo ""
  cat "${OUTPUT_TXT}"
  echo ""
} > "${UI_TXT}"

echo "DONE"
echo "Report folder: ${OUTDIR}"
echo "UI TXT: ${UI_TXT}"
