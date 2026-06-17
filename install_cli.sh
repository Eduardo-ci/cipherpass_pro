#!/usr/bin/env bash
set -euo pipefail

# Colores para la salida
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Validar permisos de administrador
if [ "$EUID" -ne 0 ]; then
  echo_warn "Este script requiere permisos de administrador para crear el comando en /usr/local/bin."
  echo_warn "Por favor, ejecútalo usando: sudo ./install_cli.sh"
  exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_SCRIPT="$PROJECT_DIR/cipherpass_cli.py"
BIN_LINK="/usr/local/bin/cipherpass-cli"
VENV_DIR="$PROJECT_DIR/.venv"

# Validar que existe el script
if [ ! -f "$CLI_SCRIPT" ]; then
    echo_err "No se encuentra el script principal: $CLI_SCRIPT"
fi

echo_info "Preparando CipherPass CLI..."
chmod +x "$CLI_SCRIPT"

# Detectar y preparar entorno virtual
if [ ! -d "$VENV_DIR" ]; then
    echo_info "No se encontró el entorno virtual. Creando uno para aislar dependencias..."
    # Crear venv con el usuario original para evitar problemas de permisos
    if [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" python3 -m venv "$VENV_DIR"
        PIP_CMD="sudo -u $SUDO_USER $VENV_DIR/bin/pip"
    else
        python3 -m venv "$VENV_DIR"
        PIP_CMD="$VENV_DIR/bin/pip"
    fi
    
    echo_info "Instalando dependencias requeridas..."
    $PIP_CMD install --quiet --upgrade pip
    if [ -f "$PROJECT_DIR/requirements.txt" ]; then
        $PIP_CMD install --quiet -r "$PROJECT_DIR/requirements.txt"
    else
        $PIP_CMD install --quiet cryptography platformdirs argon2-cffi requests zxcvbn qrcode
    fi
else
    echo_info "Entorno virtual local (.venv) detectado."
fi

# Crear el acceso global (wrapper)
echo_info "Creando ejecutable global en $BIN_LINK..."
cat > "$BIN_LINK" << EOF
#!/usr/bin/env bash
# Wrapper generado automáticamente para CipherPass CLI
# Ejecuta el script dentro de su propio entorno virtual aislado

source "$VENV_DIR/bin/activate"
python3 "$CLI_SCRIPT" "\$@"
EOF

chmod +x "$BIN_LINK"

echo_info "✅ CipherPass CLI instalado exitosamente."
echo_info "Ahora puedes usar la herramienta globalmente en tu terminal:"
echo -e "  ${GREEN}cipherpass-cli --help${NC}"
