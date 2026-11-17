#!/usr/bin/env bash
# Gera o pacote .deb do Limpa Cookies, para Debian e Ubuntu.
#
#   ./gerar_deb.sh      cria dist/limpa-cookies.deb
#
# Instalar:  sudo apt install ./dist/limpa-cookies.deb
# Remover:   sudo apt remove limpa-cookies
#
# O nome do arquivo não leva a versão (ela fica dentro do pacote): assim o link
# releases/latest/download/limpa-cookies.deb do README leva sempre à versão mais nova.
#
# O pacote instala para todos os usuários: comando limpa-cookies, atalho no menu e ícone.
# Com GTK 4 e libadwaita 1.5 ou mais novos (Debian 13, Ubuntu 24.04) abre a janela GTK;
# em sistemas mais antigos (Debian 12, Ubuntu 22.04) o apt instala o python3-tk no lugar
# e o programa abre a janela Tk.
set -euo pipefail

APP_ID="local.LimpaCookies"
PACOTE="limpa-cookies"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v dpkg-deb >/dev/null || { echo "Falta o dpkg-deb (pacote dpkg)."; exit 1; }
VERSAO="$(sed -n 's/^APP_VERSION = "\(.*\)"$/\1/p' "$DIR/limpa_cookies.py")"
[[ -n "$VERSAO" ]] || { echo "Não achei APP_VERSION em limpa_cookies.py."; exit 1; }

RAIZ="$(mktemp -d)"
trap 'rm -rf "$RAIZ"' EXIT
ICONES="$RAIZ/usr/share/icons/hicolor"
mkdir -p "$RAIZ/DEBIAN" "$RAIZ/usr/bin" "$RAIZ/usr/share/$PACOTE" \
         "$RAIZ/usr/share/applications" "$ICONES/scalable/apps"

cp "$DIR/limpa_cookies.py" "$RAIZ/usr/share/$PACOTE/limpa_cookies.py"
cp "$DIR/icone.svg" "$ICONES/scalable/apps/$APP_ID.svg"

# PNG em tamanhos fixos, para painéis que não usam o SVG (como no instalar.sh)
python3 -I - "$DIR/icone.svg" "$ICONES" "$APP_ID" <<'PY'
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

cat > "$RAIZ/usr/bin/$PACOTE" <<EOF
#!/bin/sh
exec python3 /usr/share/$PACOTE/limpa_cookies.py "\$@"
EOF

cat > "$RAIZ/usr/share/applications/$APP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Limpa Cookies
Comment=Verifica e elimina os cookies guardados pelos navegadores
Exec=$PACOTE
Icon=$APP_ID
Terminal=false
Categories=System;Security;
Keywords=cookies;privacidade;navegador;limpar;
StartupNotify=true
StartupWMClass=$APP_ID
EOF

# Permissões iguais em qualquer máquina, seja qual for o umask de quem gera
find "$RAIZ" -type d -exec chmod 755 {} +
find "$RAIZ" -type f -exec chmod 644 {} +
chmod 755 "$RAIZ/usr/bin/$PACOTE"

cat > "$RAIZ/DEBIAN/control" <<EOF
Package: $PACOTE
Version: $VERSAO
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-gi | python3-tk, gir1.2-gtk-4.0 | python3-tk, gir1.2-adw-1 (>= 1.5) | python3-tk
Installed-Size: $(du -sk --exclude=DEBIAN "$RAIZ" | cut -f1)
Maintainer: Limpa Cookies <limpa-cookies@localhost>
Description: Lista e elimina os cookies guardados pelos navegadores
 Mostra os cookies que navegadores e aplicativos (Firefox, Chrome, Chromium,
 Brave, Edge, aplicativos Electron...) guardaram em disco nesta conta e
 permite eliminar todos ou só os escolhidos.
 .
 O valor dos cookies nunca é lido nem mostrado.
EOF

mkdir -p "$DIR/dist"
SAIDA="$DIR/dist/${PACOTE}.deb"
# xz: lido por qualquer Debian/Ubuntu (o zstd, padrão no Ubuntu, não é lido por dpkg antigos)
dpkg-deb --root-owner-group -Zxz --build "$RAIZ" "$SAIDA" >/dev/null
echo "Pacote criado: $SAIDA (versão $VERSAO)"
echo "Instalar com:  sudo apt install \"$SAIDA\""
