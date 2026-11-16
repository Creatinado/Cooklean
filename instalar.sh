#!/usr/bin/env bash
# Instala o Limpa Cookies para o usuário atual, sem sudo: atalho no menu de aplicativos e ícone.
#
#   ./instalar.sh            instala (ou atualiza)
#   ./instalar.sh --fixar    instala e fixa na barra de favoritos do GNOME
#   ./instalar.sh --remover  remove atalho, ícone, o favorito e o início com o sistema
#
# O atalho aponta para esta pasta. Se mover a pasta, rode o instalador de novo.
set -euo pipefail

APP_ID="local.LimpaCookies"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
APPS="$DATA/applications"
ICONS="$DATA/icons/hicolor"
DESKTOP="$APPS/$APP_ID.desktop"

favorito() { # $1 = fixar | desafixar
    if ! command -v gsettings >/dev/null || ! gsettings list-schemas 2>/dev/null | grep -qx org.gnome.shell; then
        echo "GNOME Shell não encontrado: barra de favoritos não alterada."
        return 0
    fi
    python3 -I - "$1" "$APP_ID.desktop" <<'PY'
import ast, subprocess, sys
acao, item = sys.argv[1], sys.argv[2]
cmd = ["gsettings", "get", "org.gnome.shell", "favorite-apps"]
texto = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
atual = ast.literal_eval(texto.removeprefix("@as "))
novo = [x for x in atual if x != item] + ([item] if acao == "fixar" else [])
if novo != atual:
    subprocess.run(["gsettings", "set", "org.gnome.shell", "favorite-apps", str(novo)], check=True)
print("Fixado na barra de favoritos." if acao == "fixar" else "Retirado da barra de favoritos.")
PY
}

atualizar_caches() {
    command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -f -t -q "$ICONS" 2>/dev/null || true
    command -v update-desktop-database >/dev/null && update-desktop-database -q "$APPS" 2>/dev/null || true
}

if [[ "${1:-}" == "--remover" ]]; then
    favorito desafixar
    rm -f "$DESKTOP"
    # "Iniciar com o sistema", ligado na aba Configurações do programa
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/$APP_ID.desktop"
    find "$ICONS" -name "$APP_ID.*" -delete 2>/dev/null || true
    atualizar_caches
    echo "Limpa Cookies removido do menu. A pasta $DIR não foi apagada."
    exit 0
fi

if [[ -n "${1:-}" && "$1" != "--fixar" ]]; then
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

# Dependências: Python 3 com GTK 4 e libadwaita
if ! python3 -c 'import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1"); from gi.repository import Gtk, Adw' 2>/dev/null; then
    echo "Faltam GTK 4 / libadwaita para Python. No Debian/Ubuntu:"
    echo "    sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1"
    exit 1
fi

# O caminho vai dentro do Exec= do atalho; recusa caracteres que exigiriam escape especial.
case "$DIR" in
    *[\"\`\$\\]* | *$'\n'*)
        echo "O caminho desta pasta tem caracteres que o atalho não aceita (\" \` \$ \\ ou quebra de linha)."
        echo "Mova a pasta para outro lugar e rode de novo."
        exit 1 ;;
esac
EXEC_DIR="${DIR//%/%%}"

# Ícone: SVG mais PNG em tamanhos fixos (para painéis que não usam o SVG)
mkdir -p "$ICONS/scalable/apps" "$APPS"
cp "$DIR/icone.svg" "$ICONS/scalable/apps/$APP_ID.svg"
python3 -I - "$DIR/icone.svg" "$ICONS" "$APP_ID" <<'PY'
import os, sys
try:
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf
except Exception:
    sys.exit(0)  # sem GdkPixbuf: fica só o SVG
src, base, app = sys.argv[1:]
for s in (16, 24, 32, 48, 64, 128, 256):
    d = os.path.join(base, f"{s}x{s}", "apps")
    os.makedirs(d, exist_ok=True)
    GdkPixbuf.Pixbuf.new_from_file_at_size(src, s, s).savev(os.path.join(d, app + ".png"), "png", [], [])
PY

cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=Limpa Cookies
Comment=Verifica e elimina os cookies guardados pelos navegadores
Exec=python3 "$EXEC_DIR/limpa_cookies.py"
Icon=$APP_ID
Terminal=false
Categories=System;Security;
Keywords=cookies;privacidade;navegador;limpar;
StartupNotify=true
StartupWMClass=$APP_ID
EOF
chmod +x "$DIR/limpa_cookies.py"
atualizar_caches
echo "Instalado: procure \"Limpa Cookies\" no menu de aplicativos."

if [[ "${1:-}" == "--fixar" ]]; then
    favorito fixar
fi
