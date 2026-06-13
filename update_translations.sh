#!/bin/bash

# Activar el entorno virtual si existe (descomentar si es necesario)
# source .venv/bin/activate

LANG_DIR="resources/lang"

echo "🔍 Extrayendo cadenas y limpiando referencias obsoletas (PRO)..."
# pylupdate6 escanea los archivos fuente y actualiza los .ts
# Las cadenas eliminadas pasarán a tener el estado "obsolete"
pylupdate6 main.py ui/main_es.ui -ts $LANG_DIR/lang_en.ts $LANG_DIR/lang_pt.ts $LANG_DIR/lang_es.ts

echo "⚙️ Compilando archivos de traducción a binarios .qm..."
# lrelease toma los .ts limpios y genera los .qm optimizados
lrelease $LANG_DIR/lang_en.ts -qm $LANG_DIR/lang_en.qm
lrelease $LANG_DIR/lang_pt.ts -qm $LANG_DIR/lang_pt.qm
lrelease $LANG_DIR/lang_es.ts -qm $LANG_DIR/lang_es.qm

echo "✅ ¡Traducciones actualizadas y compiladas correctamente!"