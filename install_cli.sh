#!/usr/bin/env bash
set -euo pipefail

# Opciones estrictas de bash para tolerancia a fallos:
# -e: Detiene el script si cualquier comando falla.
# -u: Falla si se intenta utilizar una variable no definida.
# -o pipefail: El código de salida de un pipeline es el del último comando que falló.

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

# ==========================================
# CONFIGURACIÓN DE INSTALACIÓN
# ==========================================
# Cambia estas versiones por un tag específico (ej. 'v1.0.3') o un hash de commit
# para garantizar instalaciones inmutables y 100% predecibles en producción.
CLI_VERSION="v1.0.3"
CORE_VERSION="v1.0.3"

# Ubicación del ejecutable global
BIN_LINK="/usr/local/bin/cipherpass-cli"

# Validar dependencias esenciales
for cmd in python3 git; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo_err "Dependencia faltante: '$cmd'. Por favor, instálalo antes de continuar."
    fi
done

# ==========================================
# DETERMINAR MODO DE EJECUCIÓN
# ==========================================
# Local: Instalación orientada a desarrollo (se asume repositorio clonado).
# Standalone: Instalación global en el sistema (descarga e instala en /opt).
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
    
    echo_info "Descargando cipherpass_cli.py (versión: $CLI_VERSION)..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://raw.githubusercontent.com/Eduardo-ci/cipherpass_pro/${CLI_VERSION}/cipherpass_cli.py" -o "$CLI_SCRIPT" || echo_err "Fallo al descargar cipherpass_cli.py."
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$CLI_SCRIPT" "https://raw.githubusercontent.com/Eduardo-ci/cipherpass_pro/${CLI_VERSION}/cipherpass_cli.py" || echo_err "Fallo al descargar cipherpass_cli.py."
    else
        echo_err "Necesitas tener instalado 'curl' o 'wget' para descargar los archivos."
    fi
    chmod +x "$CLI_SCRIPT"
    
    if [ ! -d "$INSTALL_DIR/cipherpass_core" ]; then
        echo_info "Clonando repositorio criptográfico base (versión: $CORE_VERSION)..."
        git clone -q "https://github.com/Eduardo-ci/cipherpass_core.git" "$INSTALL_DIR/cipherpass_core"
        git -C "$INSTALL_DIR/cipherpass_core" checkout -q "$CORE_VERSION"
    else
        echo_info "Actualizando repositorio criptográfico base (versión: $CORE_VERSION)..."
        git -C "$INSTALL_DIR/cipherpass_core" fetch -q origin
        git -C "$INSTALL_DIR/cipherpass_core" checkout -q "$CORE_VERSION"
        # Solo hacemos pull si estamos en una rama (no en un hash/tag fijo)
        if git -C "$INSTALL_DIR/cipherpass_core" symbolic-ref -q HEAD >/dev/null 2>&1; then
             git -C "$INSTALL_DIR/cipherpass_core" pull -q origin "$CORE_VERSION"
        fi
    fi
fi

echo_info "Preparando CipherPass CLI en $INSTALL_DIR..."

# Detectar y preparar entorno virtual
if [ ! -d "$VENV_DIR" ]; then
    echo_info "Creando entorno virtual aislado para dependencias..."
    
    # Prevención de escalada accidental de permisos en desarrollo:
    # Si la instalación es local, creamos el entorno virtual a nombre del usuario
    # original (SUDO_USER) para no dejar carpetas propiedad de root en su workspace.
    # En instalaciones standalone (/opt), el dueño será root (comportamiento estándar).
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
        # NOTA: En un entorno de producción estricto, es mejor fijar las versiones exactas aquí (ej. cryptography==42.0.5)
        $PIP_CMD install --quiet cryptography platformdirs argon2-cffi requests zxcvbn-python qrcode rich pyperclip
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
exec python3 "$CLI_SCRIPT" "\$@"
EOF

chmod +x "$BIN_LINK"

echo_info "✅ CipherPass CLI instalado exitosamente."
echo_info "Ahora puedes usar la herramienta globalmente en tu terminal:"
echo -e "  ${GREEN}cipherpass-cli --help${NC}"
