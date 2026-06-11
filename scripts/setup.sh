#!/usr/bin/env bash
set -euo pipefail

# Bootstrap local Python environment and dependencies.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[setup] Using project root: ${ROOT_DIR}"
echo "[setup] Using Python executable: ${PYTHON_BIN}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "[setup] Error: '${PYTHON_BIN}' not found." >&2
  exit 1
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  echo "[setup] Creating virtual environment at ${VENV_DIR}"
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
else
  echo "[setup] Reusing existing virtual environment at ${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

echo "[setup] Upgrading pip"
python -m pip install --upgrade pip

echo "[setup] Installing project dependencies"
python -m pip install -r "${ROOT_DIR}/requirements.txt"

echo "[setup] Done. Activate with: source .venv/bin/activate"
