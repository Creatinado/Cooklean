#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Limpa Cookies: lista e elimina os cookies guardados em disco por navegadores e
aplicativos desta conta (Firefox, Chrome, Chromium, Brave, Edge, apps Electron...).

O programa nunca lê nem mostra o VALOR dos cookies: só aplicativo, perfil, site, nome,
tipo, validade e onde está guardado.

Uso:
    limpa_cookies.py              abre a janela
    limpa_cookies.py --resumo     imprime só a contagem por aplicativo (sem sites)
    limpa_cookies.py --home DIR   usa DIR no lugar da pasta pessoal (para testes)
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import struct
import sys
import threading
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass

APP_ID = "local.LimpaCookies"
APP_NAME = "Limpa Cookies"

KIND_SESSION = "Sessão"
KIND_PERSISTENT = "Permanente"
STORE_DB = "Banco de cookies"
STORE_SESSION = "Restauração de sessão"

MOZ_MAGIC = b"mozLz40\0"

# pasta (relativa à pasta pessoal) -> nome do aplicativo
FIREFOX_ROOTS = [
    (".mozilla/firefox", "Firefox"),
    ("snap/firefox/common/.mozilla/firefox", "Firefox (snap)"),
    (".var/app/org.mozilla.firefox/.mozilla/firefox", "Firefox (flatpak)"),
    (".librewolf", "LibreWolf"),
    (".zen", "Zen"),
    (".waterfox", "Waterfox"),
    (".thunderbird", "Thunderbird"),
    ("snap/thunderbird/common/.thunderbird", "Thunderbird (snap)"),
]

# primeira pasta abaixo de ~/.config (em minúsculas) -> nome do aplicativo
CHROMIUM_NAMES = {
    "google-chrome": "Google Chrome",
    "google-chrome-beta": "Google Chrome Beta",
    "google-chrome-unstable": "Google Chrome Dev",
    "google-chrome-for-testing": "Chrome for Testing",
    "chromium": "Chromium",
    "bravesoftware": "Brave",
    "brave": "Brave",
    "microsoft-edge": "Microsoft Edge",
    "vivaldi": "Vivaldi",
    "opera": "Opera",
    "claude": "Claude (aplicativo)",
    "code": "VS Code",
    "discord": "Discord",
    "slack": "Slack",
    "com.google.chrome": "Google Chrome",
    "org.chromium.chromium": "Chromium",
    "com.brave.browser": "Brave",
}

# pastas grandes que nunca contêm o banco de cookies
SKIP_DIRS = {
    "Cache", "Code Cache", "GPUCache", "GrShaderCache", "ShaderCache", "DawnCache",
    "DawnGraphiteCache", "DawnWebGPUCache", "IndexedDB", "Service Worker", "blob_storage",
    "Local Storage", "Session Storage", "File System", "Extensions", "extensions",
    "node_modules", "Crashpad", "Crash Reports", "logs", "component_crx_cache",
    "CachedData", "CachedExtensionVSIXs", "WebStorage", "shared_proto_db", "databases",
    "Dictionaries", "Sessions", "Sync Data", "optimization_guide_model_store",
}
MAX_DEPTH = 7


@dataclass(frozen=True)
class Cookie:
    app: str        # aplicativo que guardou o cookie
    profile: str    # perfil dentro do aplicativo
    host: str       # site
    name: str       # nome do cookie
    kind: str       # KIND_SESSION ou KIND_PERSISTENT
    expires: str    # data dd/mm/aaaa ou "ao fechar"
    expires_sort: str
    store: str      # STORE_DB ou STORE_SESSION
    source: str     # arquivo onde está
    fmt: str        # firefox_db | firefox_session | chromium_db
    key: tuple      # identificação dentro do arquivo
    in_use: bool    # o aplicativo está aberto agora


# --------------------------------------------------------------------------- utilidades

def fmt_num(n: int) -> str:
    return f"{n:,}".replace(",", ".")


def _date(epoch: float) -> tuple[str, str]:
    """(texto para mostrar, texto para ordenar)."""
    try:
        t = time.localtime(epoch)
        return time.strftime("%d/%m/%Y", t), time.strftime("%Y-%m-%d", t)
    except (OverflowError, OSError, ValueError):
        return "sem data", "9999-99-99"


def _ro(path: str) -> sqlite3.Connection:
    """Abre um SQLite sem gravar nada. Se estiver travado, lê em modo imutável."""
    quoted = urllib.parse.quote(path)
    err: Exception | None = None
    for query in ("mode=ro", "mode=ro&immutable=1"):
        try:
            conn = sqlite3.connect(f"file:{quoted}?{query}", uri=True, timeout=1.5)
            conn.execute("select 1 from sqlite_master limit 1").fetchall()
            return conn
        except sqlite3.Error as exc:
            err = exc
    raise err  # type: ignore[misc]


def open_files() -> set[str]:
    """Caminhos de todos os arquivos abertos por processos desta conta."""
    found: set[str] = set()
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return found
    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                found.add(os.readlink(f"{fd_dir}/{fd}"))
            except OSError:
                pass
    return found


def _in_use(source: str, fmt: str, opened: set[str]) -> bool:
    if fmt == "firefox_session":
        prof = os.path.dirname(source)
        if os.path.basename(prof) == "sessionstore-backups":
            prof = os.path.dirname(prof)
        guards = [os.path.join(prof, "cookies.sqlite"), os.path.join(prof, "places.sqlite")]
    else:
        guards = [source]
    return any(os.path.realpath(g) in opened for g in guards)


# --------------------------------------------------------------------------- mozlz4

def _lz4_block(src: bytes) -> bytes:
    dst = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        dst += src[i:i + lit]
        i += lit
        if i >= n:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        mlen = token & 15
        if mlen == 15:
            while True:
                b = src[i]
                i += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        start = len(dst) - off
        if off >= mlen:
            dst += dst[start:start + mlen]
        else:
            for k in range(mlen):
                dst.append(dst[start + k])
    return bytes(dst)


def _lz4_literals(data: bytes) -> bytes:
    """Bloco LZ4 válido só com literais (sem compressão)."""
    n = len(data)
    out = bytearray([min(n, 15) << 4])
    if n >= 15:
        rest = n - 15
        while rest >= 255:
            out.append(255)
            rest -= 255
        out.append(rest)
    return bytes(out) + data


def _mozlz4_read(path: str) -> dict:
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw[:8] != MOZ_MAGIC:
        raise ValueError("não é um arquivo de sessão do Firefox")
    size = struct.unpack("<I", raw[8:12])[0]
    body = _lz4_block(raw[12:])
    if len(body) != size:
        raise ValueError("arquivo de sessão corrompido")
    return json.loads(body.decode("utf-8"))


def _mozlz4_write(path: str, data: dict) -> None:
    body = json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    blob = MOZ_MAGIC + struct.pack("<I", len(body)) + _lz4_literals(body)
    if _lz4_block(blob[12:]) != body:
        raise ValueError("verificação do arquivo novo falhou")
    st = os.stat(path)
    tmp = path + ".limpa-cookies.tmp"
    with open(tmp, "wb") as fh:
        fh.write(blob)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, st.st_mode & 0o777)
    with open(path, "r+b") as fh:          # apaga o conteúdo antigo antes de trocar
        fh.write(b"\0" * st.st_size)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _session_cookie_lists(node, out: list) -> None:
    if isinstance(node, dict):
        for key, val in node.items():
            if key == "cookies" and isinstance(val, list):
                out.append((node, val))
            else:
                _session_cookie_lists(val, out)
    elif isinstance(node, list):
        for val in node:
            _session_cookie_lists(val, out)


# --------------------------------------------------------------------------- leitura

def _firefox_profiles(home: str):
    for rel, app in FIREFOX_ROOTS:
        root = os.path.join(home, rel)
        try:
            entries = sorted(os.scandir(root), key=lambda e: e.name)
        except OSError:
            continue
        for ent in entries:
            if not ent.is_dir():
                continue
            if (os.path.exists(os.path.join(ent.path, "cookies.sqlite"))
                    or os.path.exists(os.path.join(ent.path, "sessionstore.jsonlz4"))
                    or os.path.isdir(os.path.join(ent.path, "sessionstore-backups"))):
                label = ent.name.split(".", 1)[1] if "." in ent.name else ent.name
                yield app, label, ent.path


def _scan_firefox_db(app, profile, path, opened, out, warnings):
    used = _in_use(path, "firefox_db", opened)
    try:
        conn = _ro(path)
        try:
            rows = conn.execute("select id, host, name, expiry from moz_cookies").fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        warnings.append(f"{app} ({profile}): não consegui ler o banco de cookies ({exc})")
        return
    for rid, host, name, expiry in rows:
        expiry = expiry or 0
        shown, sort = _date(expiry / 1000 if expiry > 10**11 else expiry)
        out.append(Cookie(app, profile, host or "", name or "", KIND_PERSISTENT, shown, sort,
                          STORE_DB, path, "firefox_db", (rid, host, name), used))


def _scan_firefox_session(app, profile, path, opened, out, warnings):
    used = _in_use(path, "firefox_session", opened)
    try:
        data = _mozlz4_read(path)
    except (OSError, ValueError, IndexError) as exc:
        warnings.append(f"{app} ({profile}): não consegui ler {os.path.basename(path)} ({exc})")
        return
    lists: list = []
    _session_cookie_lists(data, lists)
    seen = set()
    for _owner, cookies in lists:
        for ck in cookies:
            if not isinstance(ck, dict):
                continue
            key = (ck.get("host", ""), ck.get("name", ""), ck.get("path", ""))
            if key in seen:
                continue
            seen.add(key)
            if ck.get("expiry"):
                shown, sort = _date(ck["expiry"])
                kind = KIND_PERSISTENT
            else:
                shown, sort, kind = "ao fechar", "0000-00-00", KIND_SESSION
            out.append(Cookie(app, profile, str(key[0]), str(key[1]), kind, shown, sort,
                              STORE_SESSION, path, "firefox_session", key, used))


def _chromium_files(home: str):
    bases = [(os.path.join(home, ".config"), ""),
             (os.path.join(home, "snap"), " (snap)"),
             (os.path.join(home, ".var", "app"), " (flatpak)")]
    for base, suffix in bases:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            rel = os.path.relpath(root, base)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            if depth >= MAX_DEPTH:
                dirs[:] = []
            else:
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            if "Cookies" not in files or rel == ".":
                continue
            comps = rel.split(os.sep)
            first = comps[0]
            app = CHROMIUM_NAMES.get(first.lower())
            if app is None:
                app = first.split(".")[-1] if suffix == " (flatpak)" else first
            app += suffix
            rest = [c for c in comps[1:] if c != "Network"]
            yield app, "/".join(rest) or "principal", os.path.join(root, "Cookies")


def _scan_chromium_db(app, profile, path, opened, out, warnings):
    try:
        with open(path, "rb") as fh:
            if fh.read(15) != b"SQLite format 3":
                return
    except OSError:
        return
    used = _in_use(path, "chromium_db", opened)
    try:
        conn = _ro(path)
        try:
            cols = {r[1] for r in conn.execute("pragma table_info(cookies)")}
            if not {"host_key", "name", "expires_utc"} <= cols:
                return
            has_exp = "has_expires" if "has_expires" in cols else "1"
            rows = conn.execute(
                f"select rowid, host_key, name, expires_utc, {has_exp} from cookies").fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        warnings.append(f"{app} ({profile}): não consegui ler o banco de cookies ({exc})")
        return
    for rid, host, name, exp, has in rows:
        if has and exp:
            shown, sort = _date(exp / 1e6 - 11644473600)
            kind = KIND_PERSISTENT
        else:
            shown, sort, kind = "ao fechar", "0000-00-00", KIND_SESSION
        out.append(Cookie(app, profile, host or "", name or "", kind, shown, sort,
                          STORE_DB, path, "chromium_db", (rid, host, name), used))


def scan(home: str | None = None) -> tuple[list[Cookie], list[str]]:
    """Lê todos os cookies guardados. Devolve (cookies, avisos)."""
    home = home or os.path.expanduser("~")
    opened = open_files()
    out: list[Cookie] = []
    warnings: list[str] = []
    for app, profile, pdir in _firefox_profiles(home):
        db = os.path.join(pdir, "cookies.sqlite")
        if os.path.exists(db):
            _scan_firefox_db(app, profile, db, opened, out, warnings)
        sessions = [os.path.join(pdir, "sessionstore.jsonlz4")]
        bdir = os.path.join(pdir, "sessionstore-backups")
        if os.path.isdir(bdir):
            sessions += sorted(os.path.join(bdir, f) for f in os.listdir(bdir) if "lz4" in f)
        for sess in sessions:
            if os.path.isfile(sess):
                _scan_firefox_session(app, profile, sess, opened, out, warnings)
    for app, profile, path in _chromium_files(home):
        _scan_chromium_db(app, profile, path, opened, out, warnings)
    return out, warnings


# --------------------------------------------------------------------------- eliminação

def _delete_sqlite(path: str, fmt: str, keys: list[tuple]) -> int:
    if fmt == "firefox_db":
        sql = "delete from moz_cookies where id=? and host is ? and name is ?"
    else:
        sql = "delete from cookies where rowid=? and host_key is ? and name is ?"
    conn = sqlite3.connect(path, timeout=3)
    try:
        conn.execute("pragma secure_delete=on").fetchall()
        removed = 0
        for key in keys:
            removed += conn.execute(sql, key).rowcount
        conn.commit()
        try:
            conn.execute("pragma wal_checkpoint(truncate)").fetchall()
            conn.execute("vacuum")
        except sqlite3.Error:
            pass                              # a remoção já foi gravada
        return removed
    finally:
        conn.close()


def _delete_session(path: str, keys: list[tuple]) -> int:
    targets = set(keys)
    data = _mozlz4_read(path)
    lists: list = []
    _session_cookie_lists(data, lists)
    removed_keys = set()
    for owner, cookies in lists:
        keep = []
        for ck in cookies:
            key = (ck.get("host", ""), ck.get("name", ""), ck.get("path", "")) \
                if isinstance(ck, dict) else None
            if key in targets:
                removed_keys.add(key)
            else:
                keep.append(ck)
        owner["cookies"] = keep
    if removed_keys:
        _mozlz4_write(path, data)
    return len(removed_keys)


def delete(cookies: list[Cookie]) -> dict:
    """Elimina os cookies dados. Pula os arquivos de aplicativos abertos.
    Devolve {"deleted": int, "skipped": Counter(app -> n), "errors": [str]}."""
    opened = open_files()
    groups: dict[tuple[str, str], list[Cookie]] = defaultdict(list)
    for ck in cookies:
        groups[(ck.source, ck.fmt)].append(ck)
    result = {"deleted": 0, "skipped": Counter(), "errors": []}
    for (source, fmt), items in groups.items():
        app = items[0].app
        if _in_use(source, fmt, opened):
            result["skipped"][app] += len(items)
            continue
        keys = [c.key for c in items]
        try:
            if fmt == "firefox_session":
                result["deleted"] += _delete_session(source, keys)
            else:
                result["deleted"] += _delete_sqlite(source, fmt, keys)
        except (sqlite3.Error, OSError, ValueError, IndexError) as exc:
            result["errors"].append(f"{app} ({items[0].profile}): {exc}")
    return result


# --------------------------------------------------------------------------- resumo (texto)

def print_summary(home: str | None) -> None:
    cookies, warnings = scan(home)
    by = Counter((c.app, c.profile, c.store, c.kind) for c in cookies)
    apps = Counter(c.app for c in cookies)
    print(f"{fmt_num(len(cookies))} cookies em {len(apps)} aplicativo(s)")
    for app in sorted(apps):
        state = " [aberto agora]" if any(c.in_use for c in cookies if c.app == app) else ""
        print(f"\n{app}: {fmt_num(apps[app])}{state}")
        for (a, profile, store, kind), n in sorted(by.items()):
            if a == app:
                print(f"   perfil {profile} | {store} | {kind}: {fmt_num(n)}")
    for w in warnings:
        print("aviso:", w)


# --------------------------------------------------------------------------- janela

def run_gui(home: str | None) -> int:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gio, GLib, GObject, Gtk, Pango

    GLib.set_prgname(APP_ID)
    GLib.set_application_name(APP_NAME)
    # ícone instalado em ~/.local/share/icons/hicolor/*/apps/local.LimpaCookies.*
    Gtk.Window.set_default_icon_name(APP_ID)

    class Row(GObject.Object):
        app = GObject.Property(type=str, default="")
        profile = GObject.Property(type=str, default="")
        host = GObject.Property(type=str, default="")
        name = GObject.Property(type=str, default="")
        kind = GObject.Property(type=str, default="")
        expires = GObject.Property(type=str, default="")
        expires_sort = GObject.Property(type=str, default="")
        store = GObject.Property(type=str, default="")

        def __init__(self, cookie: Cookie):
            super().__init__(app=cookie.app + (" · aberto" if cookie.in_use else ""),
                             profile=cookie.profile, host=cookie.host, name=cookie.name,
                             kind=cookie.kind, expires=cookie.expires,
                             expires_sort=cookie.expires_sort, store=cookie.store)
            self.cookie = cookie
            self.hay = " ".join((cookie.app, cookie.profile, cookie.host, cookie.name,
                                 cookie.kind, cookie.store)).lower()

    # título, propriedade mostrada, propriedade de ordenação, largura fixa, expande
    COLUMNS = [
        ("Aplicativo", "app", "app", 170, False),
        ("Perfil", "profile", "profile", 120, False),
        ("Site", "host", "host", 0, True),
        ("Cookie", "name", "name", 170, False),
        ("Tipo", "kind", "kind", 100, False),
        ("Expira", "expires", "expires_sort", 100, False),
        ("Guardado em", "store", "store", 170, False),
    ]

    class Window(Adw.ApplicationWindow):
        def __init__(self, app):
            super().__init__(application=app, title=APP_NAME,
                             default_width=1200, default_height=680)
            self.cookies: list[Cookie] = []
            self.app_choices: list[str | None] = [None]
            self.app_selected: str | None = None
            self.needle = ""
            self.busy = False
            self.updating_dropdown = False

            self.btn_scan = Gtk.Button(label="Verificar cookies")
            self.btn_scan.add_css_class("suggested-action")
            self.btn_scan.connect("clicked", self.on_scan)
            self.btn_delete = Gtk.Button(label="Eliminar cookies", sensitive=False)
            self.btn_delete.add_css_class("destructive-action")
            self.btn_delete.connect("clicked", self.on_delete)
            header = Adw.HeaderBar()
            header.pack_start(self.btn_scan)
            header.pack_end(self.btn_delete)

            # lista
            self.store = Gio.ListStore(item_type=Row)
            self.filter = Gtk.CustomFilter.new(self._match, None)
            self.filtered = Gtk.FilterListModel(model=self.store, filter=self.filter)
            self.view = Gtk.ColumnView(show_row_separators=True, reorderable=False)
            for title, prop, sort_prop, width, expand in COLUMNS:
                self.view.append_column(self._column(title, prop, sort_prop, width, expand))
            self.sorted = Gtk.SortListModel(model=self.filtered, sorter=self.view.get_sorter())
            self.selection = Gtk.MultiSelection(model=self.sorted)
            self.selection.connect("selection-changed", lambda *_: self._update_footer())
            self.view.set_model(self.selection)
            scroller = Gtk.ScrolledWindow(vexpand=True, hexpand=True, child=self.view)

            self.dropdown = Gtk.DropDown.new_from_strings(["Todos os aplicativos"])
            self.dropdown.connect("notify::selected", self.on_app_changed)
            self.search = Gtk.SearchEntry(hexpand=True,
                                          placeholder_text="Filtrar por site, cookie ou tipo")
            self.search.connect("search-changed", self.on_search)
            bar = Gtk.Box(spacing=8, margin_top=8, margin_bottom=8, margin_start=10, margin_end=10)
            bar.append(self.dropdown)
            bar.append(self.search)
            page_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            page_list.append(bar)
            page_list.append(Gtk.Separator())
            page_list.append(scroller)

            start_btn = Gtk.Button(label="Verificar cookies", halign=Gtk.Align.CENTER)
            start_btn.add_css_class("pill")
            start_btn.add_css_class("suggested-action")
            start_btn.connect("clicked", self.on_scan)
            page_start = Adw.StatusPage(
                icon_name="edit-find-symbolic", title="Nenhuma verificação ainda",
                description="Lista os cookies guardados pelos navegadores e aplicativos "
                            "desta conta.\nO valor dos cookies nunca é lido nem mostrado.",
                child=start_btn)
            spinner = Gtk.Spinner(spinning=True, width_request=32, height_request=32,
                                  halign=Gtk.Align.CENTER)
            page_busy = Adw.StatusPage(title="Trabalhando…", child=spinner)
            self.page_empty = Adw.StatusPage(icon_name="emblem-ok-symbolic",
                                             title="Nenhum cookie guardado")

            self.stack = Gtk.Stack(vexpand=True)
            self.stack.add_named(page_start, "start")
            self.stack.add_named(page_busy, "busy")
            self.stack.add_named(self.page_empty, "empty")
            self.stack.add_named(page_list, "list")

            self.footer = Gtk.Label(xalign=0, wrap=True, margin_top=6, margin_bottom=6,
                                    margin_start=10, margin_end=10,
                                    label="Pronto.")
            self.footer.add_css_class("dim-label")
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            body.append(self.stack)
            body.append(Gtk.Separator())
            body.append(self.footer)
            self.toasts = Adw.ToastOverlay(child=body)
            layout = Adw.ToolbarView(content=self.toasts)
            layout.add_top_bar(header)
            self.set_content(layout)

        # ---- montagem das colunas
        def _column(self, title, prop, sort_prop, width, expand):
            factory = Gtk.SignalListItemFactory()

            def setup(_factory, item):
                item.set_child(Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END))

            def bind(_factory, item):
                item.get_child().set_text(item.get_item().get_property(prop))

            factory.connect("setup", setup)
            factory.connect("bind", bind)
            column = Gtk.ColumnViewColumn(title=title, factory=factory,
                                          resizable=True, expand=expand)
            if width:
                column.set_fixed_width(width)
            column.set_sorter(Gtk.StringSorter.new(
                Gtk.PropertyExpression.new(Row, None, sort_prop)))
            return column

        # ---- filtro
        def _match(self, row, *_):
            if self.app_selected and row.cookie.app != self.app_selected:
                return False
            return not self.needle or self.needle in row.hay

        def _refilter(self):
            self.filter.changed(Gtk.FilterChange.DIFFERENT)
            self._update_footer()

        def on_search(self, entry):
            self.needle = entry.get_text().strip().lower()
            self._refilter()

        def on_app_changed(self, dropdown, _pspec):
            if self.updating_dropdown:
                return
            idx = dropdown.get_selected()
            self.app_selected = self.app_choices[idx] if idx < len(self.app_choices) else None
            self._refilter()

        # ---- seleção
        def _selected_rows(self):
            bits = self.selection.get_selection()
            return [self.selection.get_item(bits.get_nth(i)) for i in range(bits.get_size())]

        def _visible_rows(self):
            return [self.sorted.get_item(i) for i in range(self.sorted.get_n_items())]

        def _update_footer(self):
            if not self.cookies:
                return
            shown = self.sorted.get_n_items()
            total = len(self.cookies)
            picked = self.selection.get_selection().get_size()
            sess = sum(1 for c in self.cookies if c.store == STORE_SESSION)
            text = f"Mostrando {fmt_num(shown)} de {fmt_num(total)} cookies."
            if sess:
                text += f" {fmt_num(sess)} em arquivos de restauração de sessão."
            if picked:
                text += f" {fmt_num(picked)} selecionado(s): Eliminar remove só esses."
            else:
                text += " Sem seleção, Eliminar remove tudo o que está na lista."
            self.footer.set_text(text)
            self.btn_delete.set_sensitive(not self.busy and shown > 0)

        # ---- verificar
        def _set_busy(self, busy):
            self.busy = busy
            self.btn_scan.set_sensitive(not busy)
            self.btn_delete.set_sensitive(False)
            if busy:
                self.stack.set_visible_child_name("busy")

        # Os cliques só agendam o trabalho: mexer na tela (trocar de página, abrir diálogo)
        # dentro do próprio "clicked" deixa o GTK com o botão preso como "pressionado".
        def on_scan(self, *_):
            GLib.idle_add(self._start_scan)

        def on_delete(self, *_):
            GLib.idle_add(self._ask_delete)

        def _start_scan(self):
            if self.busy:
                return False
            self._set_busy(True)
            self.footer.set_text("Verificando os cookies guardados…")

            def work():
                try:
                    result = scan(home)
                except Exception as exc:          # nunca deixar a janela presa
                    result = ([], [f"Falha na verificação: {exc}"])
                GLib.idle_add(self._scan_done, result)

            threading.Thread(target=work, daemon=True).start()
            return False

        def _scan_done(self, result):
            cookies, warnings = result
            self.cookies = cookies
            self.store.remove_all()
            self.store.splice(0, 0, [Row(c) for c in cookies])
            counts = Counter(c.app for c in cookies)
            self.app_choices = [None] + sorted(counts)
            labels = ["Todos os aplicativos"] + [
                f"{app} ({fmt_num(counts[app])})" for app in self.app_choices[1:]]
            keep = self.app_selected if self.app_selected in counts else None
            self.updating_dropdown = True
            self.dropdown.set_model(Gtk.StringList.new(labels))
            self.dropdown.set_selected(self.app_choices.index(keep))
            self.updating_dropdown = False
            self.app_selected = keep
            self._set_busy(False)
            self.filter.changed(Gtk.FilterChange.DIFFERENT)
            if cookies:
                self.stack.set_visible_child_name("list")
                self._update_footer()
            else:
                self.stack.set_visible_child_name("empty")
                self.footer.set_text("Nenhum cookie guardado em disco foi encontrado.")
            if warnings:
                self._alert("Alguns locais não puderam ser lidos", "\n".join(warnings))
            return False

        # ---- eliminar
        def _ask_delete(self):
            if self.busy:
                return False
            picked = self._selected_rows()
            rows = picked or self._visible_rows()
            if not rows:
                return False
            targets = [r.cookie for r in rows]
            n = len(targets)
            if picked:
                scope = "Só o que está selecionado."
            elif n == len(self.cookies):
                scope = "Todos os cookies encontrados."
            else:
                scope = "Tudo o que está na lista filtrada."
            counts = Counter(c.app for c in targets)
            lines = [f"{app}: {fmt_num(k)}" for app, k in sorted(counts.items())]
            busy_apps = sorted({c.app for c in targets if c.in_use})
            body = scope + "\n\n" + "\n".join(lines)
            body += ("\n\nIsso não pode ser desfeito. Você será desconectado dos sites "
                     "correspondentes nesses aplicativos.")
            if busy_apps:
                body += ("\n\nAbertos agora, serão pulados: " + ", ".join(busy_apps)
                         + ". Feche-os e repita para limpá-los.")
            dialog = Adw.AlertDialog(
                heading=f"Eliminar {fmt_num(n)} cookie{'s' if n != 1 else ''}?",
                body=body)
            dialog.add_response("cancel", "Cancelar")
            dialog.add_response("delete", "Eliminar")
            dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            dialog.connect("response", self._delete_answer, targets)
            dialog.present(self)
            return False

        def _delete_answer(self, _dialog, response, targets):
            if response == "delete":
                GLib.idle_add(self._start_delete, targets)

        def _start_delete(self, targets):
            if self.busy:
                return False
            self._set_busy(True)
            self.footer.set_text("Eliminando…")

            def work():
                try:
                    outcome = delete(targets)
                except Exception as exc:
                    outcome = {"deleted": 0, "skipped": Counter(), "errors": [str(exc)]}
                try:
                    result = scan(home)
                except Exception as exc:
                    result = ([], [f"Falha na verificação: {exc}"])
                GLib.idle_add(self._delete_done, outcome, result)

            threading.Thread(target=work, daemon=True).start()
            return False

        def _delete_done(self, outcome, result):
            self._scan_done(result)
            n = outcome["deleted"]
            self.toasts.add_toast(Adw.Toast(
                title=f"{fmt_num(n)} cookie{'s' if n != 1 else ''} "
                      f"eliminado{'s' if n != 1 else ''}"))
            notes = []
            if outcome["skipped"]:
                parts = ", ".join(f"{app} ({fmt_num(k)})"
                                  for app, k in sorted(outcome["skipped"].items()))
                notes.append("Não eliminados porque o aplicativo está aberto: " + parts
                             + ".\nFeche o aplicativo e clique em Eliminar de novo.")
            if outcome["errors"]:
                notes.append("Erros:\n" + "\n".join(outcome["errors"]))
            if notes:
                self._alert("Nem tudo foi eliminado", "\n\n".join(notes))
            return False

        def _alert(self, heading, body):
            dialog = Adw.AlertDialog(heading=heading, body=body)
            dialog.add_response("ok", "Entendi")
            dialog.present(self)

    def on_activate(app):
        win = app.get_active_window() or Window(app)
        win.present()

    application = Adw.Application(application_id=APP_ID)
    application.connect("activate", on_activate)
    return application.run(None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--resumo", action="store_true",
                        help="imprime só a contagem por aplicativo e sai")
    parser.add_argument("--home", metavar="DIR", default=None,
                        help="usa DIR no lugar da pasta pessoal (para testes)")
    args = parser.parse_args()
    if args.resumo:
        print_summary(args.home)
        return 0
    return run_gui(args.home)


if __name__ == "__main__":
    sys.exit(main())
