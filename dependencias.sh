#!/usr/bin/env bash
# dependencias.sh — Instalador de dependencias de CipherPass Pro
# Debe ejecutarse DENTRO de un entorno virtual activo.
set -euo pipefail

# ── Guardia: verificar que hay un entorno virtual activo ──────────────────────
if [ -z "${VIRTUAL_ENV:-}" ]; then
    echo "[ERROR] No hay un entorno virtual activo." >&2
    echo "        Actívalo primero con: source .venv/bin/activate" >&2
    exit 1
fi

echo "[INFO] Instalando dependencias en: ${VIRTUAL_ENV}"

# --require-virtualenv evita instalar accidentalmente en el pip del sistema
pip install --require-virtualenv \
    PySide6 \
    zxcvbn \
    cryptography \
    platformdirs \
    requests \
    argon2-cffi \
    "qrcode[pil]"

echo "[OK] Dependencias instaladas correctamente."