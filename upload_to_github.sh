#!/usr/bin/env bash
set -euo pipefail

# 🎨 Colores y funciones de logging
GREEN='\033[0;32m' YELLOW='\033[1;33m' RED='\033[0;31m' NC='\033[0m'
echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 🔍 1. Validación de dependencias y autenticación
check_prerequisites() {
    command -v git >/dev/null 2>&1 || echo_err "Git no está instalado: sudo apt install git"
    
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        USE_GH=true
        echo_info "✅ GitHub CLI autenticado correctamente"
    elif ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
        USE_GH=false
        echo_info "✅ SSH configurado correctamente para GitHub"
    else
        echo_err "🔐 Autenticación no configurada. Ejecuta:\n   1. gh auth login (recomendado)\n   2. O configura SSH: ssh-keygen -t ed25519 && eval \$(ssh-agent) && ssh-add ~/.ssh/id_ed25519"
    fi
}

# 📄 2. Generar .gitignore específico para este proyecto
create_gitignore() {
    if [ ! -f ".gitignore" ]; then
        cat > .gitignore << 'EOF'
# 🐍 Python & Virtualenv
.venv/
venv/
env/
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
dist/
*.egg-info/
.eggs/

# 📦 Empaquetado y Compilación
cipherpass-deb/
*.deb
build_package.sh
g19_rc.py  # Generado dinámicamente por PySide6

# 🔑 Secretos y Config (CRÍTICO)
secret.key
*.pem
*.key
*.secret
.env
id_rsa
id_ed25519

# 🖥️ IDE y OS
.idea/
.vscode/
*.swp
*.swo
.DS_Store
Thumbs.db

# 🌐 Translaciones compiladas
resources/lang/*.qm
EOF
        echo_info "✅ Generado .gitignore seguro para CipherPass"
    else
        echo_warn "⚠️  .gitignore ya existe. Verifica que incluya secret.key, .venv/ y dist/"
    fi
}

# 🛡️ 3. Escaneo de seguridad antes de commitear
security_scan() {
    echo_info "🔍 Escaneando directorio en busca de secretos..."
    local sensitive_patterns=("secret.key" ".env" "*.pem" "id_rsa" "id_ed25519" "*.secret")
    local found=false
    
    for pattern in "${sensitive_patterns[@]}"; do
        while IFS= read -r file; do
            # Si encuentra un archivo, verifica si Git lo está ignorando
            if [ -n "$file" ] && ! git check-ignore -q "$file" 2>/dev/null; then
                echo_warn "⚠️  Detectado archivo sensible y NO ignorado: $file"
                found=true
            fi
        done < <(find . -type f -name "$pattern" -not -path "./.git/*" 2>/dev/null)
    done
    
    if [ "$found" = true ]; then
        echo_err "🛑 Abortado. Elimina o excluye los archivos sensibles antes de continuar."
    fi
    echo_info "✅ Escaneo de seguridad completado"
}

# ⚙️ 4. Configuración local de Git (no afecta globalmente)
setup_git_local() {
    if ! git config user.name >/dev/null 2>&1; then
        read -rp "👤 Nombre para commits (user.name): " GIT_NAME
        git config user.name "$GIT_NAME"
    fi
    if ! git config user.email >/dev/null 2>&1; then
        read -rp "📧 Email para commits (user.email): " GIT_EMAIL
        git config user.email "$GIT_EMAIL"
    fi
}

# 📦 5. Inicialización y configuración del remote
setup_repository() {
    if [ ! -d ".git" ]; then
        git init -q
        git branch -M main
        echo_info "📂 Repositorio Git inicializado (rama: main)"
    else
        echo_info "📂 Repositorio Git ya existente"
    fi

    read -rp "👤 Usuario/Organización GitHub: " GH_USER
    read -rp "📦 Nombre del repositorio: " REPO_NAME
    read -rp "👁️  Visibilidad (public/private) [private]: " VISIBILITY
    VISIBILITY=${VISIBILITY:-private}

    REMOTE_URL="git@github.com:${GH_USER}/${REPO_NAME}.git"

    if git remote get-url origin >/dev/null 2>&1; then
        echo_warn "⚠️  Remote 'origin' ya apunta a: $(git remote get-url origin)"
        read -rp "🔄 ¿Cambiar URL de origin? (y/N): " CHANGE
        [[ "$CHANGE" =~ ^[Yy]$ ]] && git remote set-url origin "$REMOTE_URL"
    else
        if [ "$USE_GH" = true ]; then
            echo_info "🌐 Creando repositorio vía GitHub CLI..."
            gh repo create "${GH_USER}/${REPO_NAME}" --"$VISIBILITY" --source=. --remote=origin --push=false || true
        else
            git remote add origin "$REMOTE_URL"
        fi
    fi
}

# 📝 6. Staging, revisión y commit
stage_and_commit() {
    git add -A
    echo -e "\n📋 Archivos a subir:"
    git status --short --untracked-files=all
    echo ""
    
    echo_warn "🛑 Revisa la lista anterior. ¿Continuar? (y/N): "
    read -r CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] || echo_err "🛑 Cancelado por el usuario"

    read -rp "💬 Mensaje de commit [feat: initial secure deployment]: " COMMIT_MSG
    COMMIT_MSG=${COMMIT_MSG:-"feat: initial secure deployment"}
    
    git commit -m "$COMMIT_MSG"
    echo_info "✅ Commit creado exitosamente"
}

# 📤 7. Push seguro
push_to_github() {
    echo_warn "📤 ¿Enviar cambios a origin/main? (y/N): "
    read -r PUSH_CONFIRM
    [[ "$PUSH_CONFIRM" =~ ^[Yy]$ ]] || echo_err "🛑 Push cancelado"

    echo_info "🚀 Subiendo a GitHub..."
    git push -u origin main
    echo_info "✅ Deploy completado. URL: https://github.com/${GH_USER}/${REPO_NAME}"
}

# 🏁 Ejecución principal
main() {
    echo_info "🔐 Iniciando despliegue seguro a GitHub..."
    check_prerequisites
    create_gitignore
    setup_repository
    setup_git_local
    security_scan
    stage_and_commit
    push_to_github
    echo_info "✨ Proceso finalizado correctamente"
}

main "$@"