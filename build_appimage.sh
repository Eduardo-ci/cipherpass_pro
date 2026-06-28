#!/usr/bin/env bash
# set -euo pipefail
set -euo pipefail

# 📦 Configuración del paquete
APP_NAME="cipherpass"
VERSION="1.0.4"
ARCH="x86_64"
APPDIR="AppDir"
DIST_DIR="dist"
VENV_DIR=".venv"

# 🎨 Colores para terminal
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ✅ Validaciones iniciales
check_prerequisites() {
    command -v python3 >/dev/null 2>&1 || echo_err "python3 no encontrado"
    command -v python3-config >/dev/null 2>&1 || echo_err "Cabeceras de Python no encontradas (instala: sudo apt install python3-dev)"
    command -v gcc >/dev/null 2>&1 || echo_err "Compilador C (gcc) no encontrado (instala: sudo apt install build-essential)"
    command -v patchelf >/dev/null 2>&1 || echo_err "patchelf no encontrado (instala: sudo apt install patchelf)"
    command -v wget >/dev/null 2>&1 || echo_err "wget no encontrado (instala: sudo apt install wget)"
    
    [ -f "main.py" ] || echo_err "No se encontró main.py. Ejecuta el script desde la raíz del proyecto"
}

# 🛠 Paso 1: Entorno virtual e instalación de dependencias
setup_venv() {
    echo_info "📦 Creando entorno virtual limpio..."
    [ -d "$VENV_DIR" ] && rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    
    echo_info "📥 Instalando dependencias..."
    pip install --quiet --upgrade pip setuptools wheel
    if [ -f "requirements.txt" ]; then
        pip install --quiet -r requirements.txt
        pip install --quiet nuitka
    else
        echo_warn "requirements.txt no encontrado. Instalando dependencias manualmente."
        pip install --quiet PySide6 zxcvbn cryptography platformdirs nuitka qrcode pillow requests argon2-cffi
    fi
}

# 📥 Paso 1.5: Sincronizar el Core Criptográfico
fetch_core() {
    local gh_user="${GH_USER:?'ERROR: La variable GH_USER debe estar definida. Ej: GH_USER=mi_usuario ./build_appimage.sh'}"
    
    echo_info "🌐 Obteniendo el núcleo criptográfico (cipherpass_core)..."
    if [ -d "cipherpass_core/.git" ]; then
        echo_info "Actualizando el repositorio público local..."
        git -C cipherpass_core pull origin main
    elif [ -d "cipherpass_core" ]; then
        echo_warn "La carpeta 'cipherpass_core' ya existe. Se usará la versión local."
    else
        echo_info "Clonando repositorio público cipherpass_core..."
        git clone "git@github.com:${gh_user}/cipherpass_core.git" cipherpass_core
    fi
}

# ⚙️ Paso 2: Compilación con Nuitka
build_executable() {
    echo_info "🔨 Traduciendo a C y compilando ejecutable nativo (esto tomará varios minutos)..."
    
    python3 -m nuitka \
        --standalone \
        --onefile \
        --enable-plugin=pyside6 \
        --include-data-dir="resources=resources" \
        --include-data-dir="ui=ui" \
        --include-package=cipherpass_core \
        --output-dir="$DIST_DIR" \
        --output-filename="$APP_NAME" \
        --remove-output \
        --disable-console \
        main.py
    
    [ -f "$DIST_DIR/$APP_NAME" ] || echo_err "Fallo en la compilación con Nuitka"
}

# 📥 Paso 3: Obtener appimagetool si no existe
setup_appimagetool() {
    if ! command -v appimagetool >/dev/null 2>&1; then
        if [ ! -f "appimagetool-x86_64.AppImage" ]; then
            echo_info "⬇️ Descargando appimagetool para generar el paquete..."
            wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
            chmod +x appimagetool-x86_64.AppImage
        fi
        APPIMAGETOOL="./appimagetool-x86_64.AppImage"
    else
        APPIMAGETOOL="appimagetool"
    fi
}

# 📁 Paso 4: Estructura del AppDir
prepare_appdir() {
    echo_info "🗂 Preparando estructura AppDir..."
    rm -rf "$APPDIR"
    mkdir -p "$APPDIR/usr/bin"
    
    # Copiar binario
    cp "$DIST_DIR/$APP_NAME" "$APPDIR/usr/bin/"
    chmod +x "$APPDIR/usr/bin/$APP_NAME"
    
    # Crear enlace AppRun (requerido por AppImage)
    ln -s "usr/bin/$APP_NAME" "$APPDIR/AppRun"
    
    # Copiar icono principal
    if [ -f "cipherpass.png" ]; then
        cp "cipherpass.png" "$APPDIR/${APP_NAME}.png"
    else
        echo_warn "cipherpass.png no encontrado en la raíz. El AppImage no tendrá icono personalizado."
        touch "$APPDIR/${APP_NAME}.png"
    fi

    # Archivo .desktop (requerido por AppImage)
    cat > "$APPDIR/$APP_NAME.desktop" << EOF
[Desktop Entry]
Name=CipherPass
Exec=$APP_NAME
Icon=$APP_NAME
Type=Application
Categories=Utility;Security;
Comment=Generador y validador de contraseñas criptográficas
EOF
}

# 🏗 Paso 5: Construcción del AppImage
build_appimage() {
    echo_info "📦 Empaquetando en formato AppImage..."
    
    # AppImage tool necesita saber la arquitectura
    export ARCH=$ARCH
    
    # Si descargamos el appimagetool local, puede que falle sin FUSE en algunos entornos (como CI).
    # Usamos --appimage-extract-and-run como fallback de seguridad.
    if [[ "$APPIMAGETOOL" == "./appimagetool-x86_64.AppImage" ]]; then
        $APPIMAGETOOL --appimage-extract-and-run "$APPDIR"
    else
        $APPIMAGETOOL "$APPDIR"
    fi
    
    echo_info "✅ Generado con éxito: ${APP_NAME}-${ARCH}.AppImage"
}

# 🧹 Paso 6: Limpieza opcional
cleanup() {
    echo_info "🧹 Limpiando temporales..."
    rm -rf "$APPDIR"
    deactivate 2>/dev/null || true
    echo_info "✨ Proceso finalizado"
}

# 🚀 Ejecución principal
main() {
    check_prerequisites
    setup_venv
    fetch_core
    build_executable
    setup_appimagetool
    prepare_appdir
    build_appimage
    cleanup
}

main "$@"
