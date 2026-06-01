#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
# install_patch.sh — Smart NetSec SOC v3.0 Patch Applier
# Usage: bash install_patch.sh [chemin_projet]
# Par défaut: ~/smart_netsec
# ══════════════════════════════════════════════════════════════
set -e

PROJ="${1:-$HOME/smart_netsec}"
PATCH_SRC="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step()    { echo -e "\n${BOLD}══ $1 ══${NC}"; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║     Smart NetSec SOC — Patch Installeur v3.0        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Vérification projet ───────────────────────────────────
[ -d "$PROJ" ] || error "Répertoire projet introuvable: $PROJ"
info "Projet détecté: $PROJ"

# ── Backup ────────────────────────────────────────────────
step "Backup"
BKUP="$PROJ/_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BKUP"
for f in backend/app.py backend/database/db.py \
          backend/database/repositories.py \
          backend/services/firewall_service.py \
          backend/services/snort_service.py \
          backend/services/monitoring_service.py \
          backend/api/firewall_api.py \
          backend/api/ids_api.py \
          frontend/static/js/app.js; do
    src="$PROJ/$f"
    if [ -f "$src" ]; then
        dst="$BKUP/$(dirname $f)"
        mkdir -p "$dst"
        cp "$src" "$dst/"
        info "Backup: $f"
    fi
done
success "Backup dans $BKUP"

# ── Créer répertoires manquants ───────────────────────────
step "Répertoires"
mkdir -p "$PROJ/backend/api"
mkdir -p "$PROJ/backend/services"
mkdir -p "$PROJ/backend/database"
mkdir -p "$PROJ/backend/utils"
mkdir -p "$PROJ/frontend/static/js"
mkdir -p "$PROJ/logs"
success "Répertoires OK"

# ── __init__.py ───────────────────────────────────────────
step "Packages Python"
for d in backend backend/api backend/services backend/database backend/utils; do
    touch "$PROJ/$d/__init__.py"
done
success "__init__.py OK"

# ── Copie des fichiers patchés ────────────────────────────
step "Application des patches"

copy_file() {
    local src="$PATCH_SRC/$1"
    local dst="$PROJ/$1"
    if [ -f "$src" ]; then
        cp "$src" "$dst"
        success "Patché: $1"
    else
        warn "Source introuvable: $src"
    fi
}

copy_file "backend/app.py"
copy_file "backend/config.py"
copy_file "backend/database/db.py"
copy_file "backend/database/repositories.py"
copy_file "backend/services/firewall_service.py"
copy_file "backend/services/snort_service.py"
copy_file "backend/services/monitoring_service.py"
copy_file "backend/api/firewall_api.py"
copy_file "backend/api/ids_api.py"
copy_file "backend/api/monitoring_api.py"
copy_file "backend/api/auth_api.py"
copy_file "backend/api/intel_api.py"
copy_file "backend/utils/auth.py"
copy_file "backend/utils/logger.py"
copy_file "frontend/static/js/app.js"
copy_file "frontend/static/js/firewall.js"
copy_file "frontend/static/js/ids.js"
copy_file "run.py"

# ── Patch index.html ─────────────────────────────────────
step "Patch index.html"
INDEX="$PROJ/frontend/templates/index.html"
if [ -f "$INDEX" ]; then
    # Ajouter firewall.js et ids.js avant </body> si absent
    if ! grep -q "firewall.js" "$INDEX"; then
        sed -i 's|</body>|<script src="/static/js/firewall.js"></script>\n<script src="/static/js/ids.js"></script>\n</body>|' "$INDEX"
        success "firewall.js + ids.js injectés dans index.html"
    else
        info "Scripts JS déjà présents dans index.html"
    fi
    # Ajouter conteneurs si absents
    if ! grep -q "fw-main-container" "$INDEX"; then
        warn "fw-main-container absent de index.html — à ajouter manuellement (voir PATCH_HTML.md)"
    fi
    if ! grep -q "ids-main-container" "$INDEX"; then
        warn "ids-main-container absent de index.html — à ajouter manuellement"
    fi
else
    warn "index.html introuvable : $INDEX"
fi

# ── pip dependencies ──────────────────────────────────────
step "Dépendances Python"
pip install --quiet psutil flask 2>/dev/null && success "psutil + flask OK" || warn "pip install échoué"

# ── Réinitialiser DB ──────────────────────────────────────
step "Base de données"
cd "$PROJ"
python3 - <<'PYEOF'
import sys, os
sys.path.insert(0, os.getcwd())
try:
    from backend.database.db import init_db
    init_db()
    print("✅ DB initialisée/migrée")
except Exception as e:
    print(f"⚠️  DB: {e}")
PYEOF

# ── Résumé ────────────────────────────────────────────────
echo -e "\n${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║              ✅ Patch appliqué avec succès           ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Démarrer :  cd $PROJ && python3 run.py             ║"
echo "║  URL      :  http://localhost:5000                  ║"
echo "║  Admin    :  admin / admin123                       ║"
echo "║  Backup   :  $BKUP"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
