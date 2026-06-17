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
  echo_warn "Este script requiere permisos de administrador para instalar en el sistema."
  echo_warn "Por favor, ejecútalo usando: sudo bash $0"
  exit 1
fi

BIN_LINK="/usr/local/bin/cipherpass-cli"

# Determinar modo de ejecución (Local vs Standalone)
# Si el archivo está dentro de un entorno que tiene cipherpass_cli.py, usamos modo local.
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

if [ -f "$CURRENT_DIR/cipherpass_cli.py" ] && [ -d "$CURRENT_DIR/cipherpass_core" ]; then
    echo_info "Ejecutando en Modo Local (Repositorio clonado)..."
    INSTALL_DIR="$CURRENT_DIR"
    CLI_SCRIPT="$INSTALL_DIR/cipherpass_cli.py"
    VENV_DIR="$INSTALL_DIR/.venv"
    
    chmod +x "$CLI_SCRIPT"
else
    echo_info "Ejecutando en Modo Standalone (Instalación limpia en /opt)..."
    INSTALL_DIR="/opt/cipherpass-cli"
    CLI_SCRIPT="$INSTALL_DIR/cipherpass_cli.py"
    VENV_DIR="$INSTALL_DIR/.venv"
    
    mkdir -p "$INSTALL_DIR"
    
    echo_info "Descargando cipherpass_cli.py..."
    if command -v curl >/dev/null 2>&1; then
        curl -sL "https://raw.githubusercontent.com/Eduardo-ci/cipherpass_pro/main/cipherpass_cli.py" -o "$CLI_SCRIPT"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$CLI_SCRIPT" "https://raw.githubusercontent.com/Eduardo-ci/cipherpass_pro/main/cipherpass_cli.py"
    else
        echo_err "Necesitas tener instalado 'curl' o 'wget' para descargar los archivos."
    fi
    chmod +x "$CLI_SCRIPT"
    
    if [ ! -d "$INSTALL_DIR/cipherpass_core" ]; then
        echo_info "Clonando repositorio criptográfico base (cipherpass_core)..."
        if ! command -v git >/dev/null 2>&1; then
            echo_err "Se requiere 'git' instalado para descargar el core criptográfico."
        fi
        git clone -q "https://github.com/Eduardo-ci/cipherpass_core.git" "$INSTALL_DIR/cipherpass_core"
    else
        echo_info "Actualizando repositorio criptográfico base..."
        git -C "$INSTALL_DIR/cipherpass_core" pull -q origin main
    fi
fi

echo_info "Preparando CipherPass CLI en $INSTALL_DIR..."

# Detectar y preparar entorno virtual
if [ ! -d "$VENV_DIR" ]; then
    echo_info "Creando entorno virtual aislado para dependencias..."
    
    # Si ejecutamos en la carpeta local, podríamos querer asignar permisos al usuario normal
    # En /opt, usualmente root es el dueño, pero es seguro que el entorno virtual lo sea.
    if [ "$INSTALL_DIR" == "$CURRENT_DIR" ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" python3 -m venv "$VENV_DIR"
        PIP_CMD="sudo -u $SUDO_USER $VENV_DIR/bin/pip"
    else
        python3 -m venv "$VENV_DIR"
        PIP_CMD="$VENV_DIR/bin/pip"
    fi
    
    echo_info "Instalando dependencias requeridas..."
    $PIP_CMD install --quiet --upgrade pip
    if [ -f "$INSTALL_DIR/requirements.txt" ]; then
        $PIP_CMD install --quiet -r "$INSTALL_DIR/requirements.txt"
    else
        # Dependencias core de la CLI si no hay requirements.txt
        $PIP_CMD install --quiet cryptography platformdirs argon2-cffi requests zxcvbn qrcode
    fi
else
    echo_info "Entorno virtual (.venv) ya existente."
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
