#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Limpa Cookies: lista e elimina os cookies guardados em disco por navegadores e
aplicativos desta conta (Firefox, Chrome, Chromium, Brave, Edge, apps Electron...).
Funciona no Linux (janela GTK 4) e no Windows 10 e 11 (janela Tk).

O programa nunca lê nem mostra o VALOR dos cookies: só aplicativo, perfil, site, nome,
tipo, validade e onde está guardado.

Uso:
    limpa_cookies.py              abre a janela
    limpa_cookies.py --resumo     imprime só a contagem por aplicativo (sem sites)
    limpa_cookies.py --home DIR   usa DIR no lugar da pasta pessoal (para testes)
    limpa_cookies.py --tk         no Linux, abre a janela Tk (a mesma do Windows)
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sqlite3
import struct
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass

APP_ID = "local.LimpaCookies"
APP_NAME = "Limpa Cookies"
APP_VERSION = "1.1.0"
WINDOWS = sys.platform == "win32"

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

# o mesmo no Windows, relativo a %APPDATA%
FIREFOX_ROOTS_WINDOWS = [
    ("Mozilla/Firefox/Profiles", "Firefox"),
    ("librewolf/Profiles", "LibreWolf"),
    ("zen/Profiles", "Zen"),
    ("Waterfox/Profiles", "Waterfox"),
    ("Thunderbird/Profiles", "Thunderbird"),
]

# primeiras pastas (uma ou duas, em minúsculas) abaixo de ~/.config no Linux ou de
# %LOCALAPPDATA% e %APPDATA% no Windows -> nome do aplicativo
CHROMIUM_NAMES = {
    "google/chrome": "Google Chrome",
    "google/chrome beta": "Google Chrome Beta",
    "google/chrome dev": "Google Chrome Dev",
    "google/chrome sxs": "Google Chrome Canary",
    "google/chrome for testing": "Chrome for Testing",
    "microsoft/edge": "Microsoft Edge",
    "microsoft/edge beta": "Microsoft Edge Beta",
    "microsoft/edge dev": "Microsoft Edge Dev",
    "microsoft/edge sxs": "Microsoft Edge Canary",
    "microsoft/teams": "Microsoft Teams",
    "bravesoftware/brave-browser": "Brave",
    "opera software/opera stable": "Opera",
    "opera software/opera gx stable": "Opera GX",
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
# idem, só no Windows: pastas enormes do sistema dentro de AppData
SKIP_DIRS_WINDOWS = {
    "Temp", "Packages", "Programs", "Application Data", "Temporary Internet Files",
    "History", "Windows", "WindowsApps", "INetCache", "INetCookies", "Package Cache",
    "CrashDumps", "D3DSCache", "pip", "npm-cache",
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
    uri = pathlib.Path(os.path.abspath(path)).as_uri()      # serve para / e para C:\
    err: Exception | None = None
    for query in ("mode=ro", "mode=ro&immutable=1"):
        try:
            conn = sqlite3.connect(f"{uri}?{query}", uri=True, timeout=1.5)
            conn.execute("select 1 from sqlite_master limit 1").fetchall()
            return conn
        except sqlite3.Error as exc:
            err = exc
    raise err  # type: ignore[misc]


def open_files() -> set[str] | None:
    """Caminhos de todos os arquivos abertos por processos desta conta.
    No Windows devolve None: lá cada arquivo é testado na hora, em _busy."""
    if WINDOWS:
        return None
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


def _busy(path: str, opened: set[str] | None) -> bool:
    """O arquivo está aberto por algum programa agora?"""
    if opened is not None:
        return os.path.realpath(path) in opened
    # Windows: pede acesso exclusivo; o sistema recusa se outro programa tiver o arquivo aberto.
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    # GENERIC_READ, sem compartilhar, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL
    handle = kernel32.CreateFileW(path, 0x80000000, 0, None, 3, 0x80, None)
    if handle == wintypes.HANDLE(-1).value:
        return ctypes.get_last_error() in (32, 33)      # violação de compartilhamento/bloqueio
    kernel32.CloseHandle(handle)
    return False


def _in_use(source: str, fmt: str, opened: set[str] | None) -> bool:
    if fmt == "firefox_session":
        prof = os.path.dirname(source)
        if os.path.basename(prof) == "sessionstore-backups":
            prof = os.path.dirname(prof)
        guards = [os.path.join(prof, "cookies.sqlite"), os.path.join(prof, "places.sqlite")]
    else:
        guards = [source]
    return any(_busy(g, opened) for g in guards)


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

def _layout(home: str | None, windows: bool):
    """Onde procurar: ([(pasta de perfis tipo Firefox, aplicativo)],
    [(pasta base para bancos tipo Chromium, sufixo do nome)])."""
    if not windows:
        home = home or os.path.expanduser("~")
        firefox = [(os.path.join(home, *rel.split("/")), app) for rel, app in FIREFOX_ROOTS]
        return firefox, [(os.path.join(home, ".config"), ""),
                         (os.path.join(home, "snap"), " (snap)"),
                         (os.path.join(home, ".var", "app"), " (flatpak)")]
    if home:
        roaming = os.path.join(home, "AppData", "Roaming")
        local = os.path.join(home, "AppData", "Local")
    else:
        appdata = os.path.join(os.path.expanduser("~"), "AppData")
        roaming = os.environ.get("APPDATA") or os.path.join(appdata, "Roaming")
        local = os.environ.get("LOCALAPPDATA") or os.path.join(appdata, "Local")
    firefox = [(os.path.join(roaming, *rel.split("/")), app)
               for rel, app in FIREFOX_ROOTS_WINDOWS]
    packages = os.path.join(local, "Packages")           # Firefox da Microsoft Store
    try:
        for name in sorted(os.listdir(packages)):
            if name.lower().startswith("mozilla.firefox"):
                firefox.append((os.path.join(packages, name, "LocalCache", "Roaming",
                                             "Mozilla", "Firefox", "Profiles"),
                                "Firefox (Microsoft Store)"))
    except OSError:
        pass
    return firefox, [(local, ""), (roaming, "")]


def _firefox_profiles(roots):
    for root, app in roots:
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


def _chromium_label(comps: list[str], suffix: str) -> tuple[str, str]:
    """(aplicativo, perfil) a partir das pastas entre a base e o arquivo Cookies."""
    for used in (2, 1):
        app = CHROMIUM_NAMES.get("/".join(comps[:used]).lower())
        if app:
            break
    else:
        used = 1
        app = comps[0].split(".")[-1] if suffix == " (flatpak)" else comps[0]
    rest = [c for c in comps[used:] if c not in ("Network", "User Data")]
    return app + suffix, "/".join(rest) or "principal"


def _chromium_files(bases, windows: bool):
    if windows:                         # lá maiúsculas e minúsculas não distinguem pastas
        skip = {d.lower() for d in SKIP_DIRS | SKIP_DIRS_WINDOWS}
    for base, suffix in bases:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            rel = os.path.relpath(root, base)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            if depth >= MAX_DEPTH:
                dirs[:] = []
            elif windows:
                dirs[:] = sorted(d for d in dirs if d.lower() not in skip)
            else:
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            if "Cookies" not in files or rel == ".":
                continue
            app, profile = _chromium_label(rel.split(os.sep), suffix)
            yield app, profile, os.path.join(root, "Cookies")


def _scan_chromium_db(app, profile, path, opened, out, warnings):
    used = _in_use(path, "chromium_db", opened)
    try:
        with open(path, "rb") as fh:
            if fh.read(15) != b"SQLite format 3":
                return
    except OSError:
        if used:        # no Windows, Chrome e Edge abertos travam o arquivo até para leitura
            warnings.append(f"{app} ({profile}): está aberto e não deixa ler os cookies. "
                            "Feche o aplicativo e verifique de novo.")
        return
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


def scan(home: str | None = None, windows: bool = WINDOWS) -> tuple[list[Cookie], list[str]]:
    """Lê todos os cookies guardados. Devolve (cookies, avisos).
    windows escolhe onde procurar: pastas do Windows (AppData) ou do Linux."""
    firefox_roots, chromium_bases = _layout(home, windows)
    opened = open_files()
    out: list[Cookie] = []
    warnings: list[str] = []
    for app, profile, pdir in _firefox_profiles(firefox_roots):
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
    for app, profile, path in _chromium_files(chromium_bases, windows):
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


# --------------------------------------------------------------------------- comum às janelas

# título, campo mostrado, campo de ordenação, largura fixa (0 = ocupa o que sobra)
COLUMNS = [
    ("Aplicativo", "app", "app", 170),
    ("Perfil", "profile", "profile", 120),
    ("Site", "host", "host", 0),
    ("Cookie", "name", "name", 170),
    ("Tipo", "kind", "kind", 100),
    ("Expira", "expires", "expires_sort", 100),
    ("Guardado em", "store", "store", 170),
]
ALL_APPS = "Todos os aplicativos"

# Cores do tema escuro do Claude, usadas pela janela GTK e pela janela Tk.
THEME = {
    "bg": "#262624",            # fundo da janela e da lista
    "bar": "#1f1e1d",           # cabeçalho e rodapé
    "surface": "#30302e",       # campos e diálogos
    "raised": "#3a3937",        # botão neutro, barra de rolagem
    "raised_hover": "#46453f",
    "border": "#42413e",        # linhas divisórias
    "fg": "#faf9f5",            # texto
    "fg_dim": "#c2c0b6",        # texto secundário
    "fg_muted": "#9c9a92",      # dicas e itens desativados
    "accent": "#d97757",        # laranja do Claude: foco e destaques
    "accent_bg": "#c6613f",     # botão principal
    "on_accent": "#ffffff",
    "selected": "#533a31",      # linha selecionada (laranja a 25% sobre o fundo)
    "danger": "#fe8181",        # texto de ação destrutiva
    "danger_bg": "#b53333",     # botão destrutivo cheio
    "danger_soft": "#3e2c2b",   # botão destrutivo discreto (vermelho a 14% sobre a barra)
    "danger_soft_hover": "#503433",
}


def app_label(cookie: Cookie) -> str:
    return cookie.app + (" · aberto" if cookie.in_use else "")


def search_text(cookie: Cookie) -> str:
    """Texto em minúsculas onde o filtro procura."""
    return " ".join((cookie.app, cookie.profile, cookie.host, cookie.name,
                     cookie.kind, cookie.store)).lower()


def scan_safely(home: str | None) -> tuple[list[Cookie], list[str]]:
    try:
        return scan(home)
    except Exception as exc:                  # nunca deixar a janela presa
        return [], [f"Falha na verificação: {exc}"]


def delete_safely(cookies: list[Cookie]) -> dict:
    try:
        return delete(cookies)
    except Exception as exc:
        return {"deleted": 0, "skipped": Counter(), "errors": [str(exc)]}


def footer_text(total: int, shown: int, picked: int, in_session: int) -> str:
    text = f"Mostrando {fmt_num(shown)} de {fmt_num(total)} cookies."
    if in_session:
        text += f" {fmt_num(in_session)} em arquivos de restauração de sessão."
    if picked:
        text += f" {fmt_num(picked)} selecionado(s): Eliminar remove só esses."
    else:
        text += " Sem seleção, Eliminar remove tudo o que está na lista."
    return text


def delete_question(targets: list[Cookie], picked: bool, total: int) -> tuple[str, str]:
    """(título, texto) da confirmação antes de eliminar."""
    n = len(targets)
    if picked:
        scope = "Só o que está selecionado."
    elif n == total:
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
    return f"Eliminar {fmt_num(n)} cookie{'s' if n != 1 else ''}?", body


def deleted_text(n: int) -> str:
    return f"{fmt_num(n)} cookie{'s' if n != 1 else ''} eliminado{'s' if n != 1 else ''}"


def delete_notes(outcome: dict) -> str:
    """O que ficou por eliminar; vazio se correu tudo bem."""
    notes = []
    if outcome["skipped"]:
        parts = ", ".join(f"{app} ({fmt_num(k)})"
                          for app, k in sorted(outcome["skipped"].items()))
        notes.append("Não eliminados porque o aplicativo está aberto: " + parts
                     + ".\nFeche o aplicativo e clique em Eliminar de novo.")
    if outcome["errors"]:
        notes.append("Erros:\n" + "\n".join(outcome["errors"]))
    return "\n\n".join(notes)


# --------------------------------------------------------------------------- janela GTK (Linux)

def gtk_ready() -> bool:
    """Há GTK 4 com libadwaita 1.5 ou mais novo (Debian 13+, Ubuntu 24.04+)?"""
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw
    except (ImportError, ValueError):
        return False
    return (Adw.get_major_version(), Adw.get_minor_version()) >= (1, 5)


def _gtk_css() -> str:
    """Troca as cores do libadwaita pelas do tema."""
    t = THEME
    colors = {
        "window_bg_color": t["bg"], "window_fg_color": t["fg"],
        "view_bg_color": t["bg"], "view_fg_color": t["fg"],
        "headerbar_bg_color": t["bar"], "headerbar_fg_color": t["fg"],
        "headerbar_backdrop_color": t["bar"],
        "card_bg_color": t["surface"], "card_fg_color": t["fg"],
        "dialog_bg_color": t["surface"], "dialog_fg_color": t["fg"],
        "popover_bg_color": t["surface"], "popover_fg_color": t["fg"],
        "accent_bg_color": t["accent_bg"], "accent_fg_color": t["on_accent"],
        "accent_color": t["accent"],
        "destructive_bg_color": t["danger_bg"], "destructive_fg_color": t["on_accent"],
        "destructive_color": t["danger"],
    }
    css = "".join(f"@define-color {name} {value};\n" for name, value in colors.items())
    return css + f"""
        .rodape {{ background-color: {t["bar"]}; color: {t["fg_dim"]}; }}
        columnview > header > button > box {{ color: {t["fg_muted"]}; }}
        columnview > header > button:hover > box {{ color: {t["fg_dim"]}; }}
        button.eliminar {{ background-color: alpha({t["danger"]}, 0.14); color: {t["danger"]}; }}
        button.eliminar:hover {{ background-color: alpha({t["danger"]}, 0.22); }}
        button.eliminar:active {{ background-color: alpha({t["danger"]}, 0.30); }}
    """


def run_gui(home: str | None) -> int:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango

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
            super().__init__(app=app_label(cookie),
                             profile=cookie.profile, host=cookie.host, name=cookie.name,
                             kind=cookie.kind, expires=cookie.expires,
                             expires_sort=cookie.expires_sort, store=cookie.store)
            self.cookie = cookie
            self.hay = search_text(cookie)

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
            self.btn_delete.add_css_class("eliminar")
            self.btn_delete.connect("clicked", self.on_delete)
            header = Adw.HeaderBar()
            header.pack_start(self.btn_scan)
            header.pack_end(self.btn_delete)

            # lista
            self.store = Gio.ListStore(item_type=Row)
            self.filter = Gtk.CustomFilter.new(self._match, None)
            self.filtered = Gtk.FilterListModel(model=self.store, filter=self.filter)
            self.view = Gtk.ColumnView(show_row_separators=True, reorderable=False)
            for title, prop, sort_prop, width in COLUMNS:
                self.view.append_column(self._column(title, prop, sort_prop, width, not width))
            self.sorted = Gtk.SortListModel(model=self.filtered, sorter=self.view.get_sorter())
            self.selection = Gtk.MultiSelection(model=self.sorted)
            self.selection.connect("selection-changed", lambda *_: self._update_footer())
            self.view.set_model(self.selection)
            scroller = Gtk.ScrolledWindow(vexpand=True, hexpand=True, child=self.view)

            self.dropdown = Gtk.DropDown.new_from_strings([ALL_APPS])
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
            footer_bar = Gtk.Box()
            footer_bar.add_css_class("rodape")
            footer_bar.append(self.footer)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            body.append(self.stack)
            body.append(Gtk.Separator())
            body.append(footer_bar)
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
            picked = self.selection.get_selection().get_size()
            sess = sum(1 for c in self.cookies if c.store == STORE_SESSION)
            self.footer.set_text(footer_text(len(self.cookies), shown, picked, sess))
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
                GLib.idle_add(self._scan_done, scan_safely(home))

            threading.Thread(target=work, daemon=True).start()
            return False

        def _scan_done(self, result):
            cookies, warnings = result
            self.cookies = cookies
            self.store.remove_all()
            self.store.splice(0, 0, [Row(c) for c in cookies])
            counts = Counter(c.app for c in cookies)
            self.app_choices = [None] + sorted(counts)
            labels = [ALL_APPS] + [
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
            heading, body = delete_question(targets, bool(picked), len(self.cookies))
            dialog = Adw.AlertDialog(heading=heading, body=body)
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
                outcome = delete_safely(targets)
                GLib.idle_add(self._delete_done, outcome, scan_safely(home))

            threading.Thread(target=work, daemon=True).start()
            return False

        def _delete_done(self, outcome, result):
            self._scan_done(result)
            self.toasts.add_toast(Adw.Toast(title=deleted_text(outcome["deleted"])))
            notes = delete_notes(outcome)
            if notes:
                self._alert("Nem tudo foi eliminado", notes)
            return False

        def _alert(self, heading, body):
            dialog = Adw.AlertDialog(heading=heading, body=body)
            dialog.add_response("ok", "Entendi")
            dialog.present(self)

    def on_startup(_app):
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
        provider = Gtk.CssProvider()
        provider.load_from_string(_gtk_css())
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def on_activate(app):
        win = app.get_active_window() or Window(app)
        win.present()

    application = Adw.Application(application_id=APP_ID)
    application.connect("startup", on_startup)
    application.connect("activate", on_activate)
    return application.run(None)


# --------------------------------------------------------------------------- janela Tk (Windows)

def _resource(name: str) -> str | None:
    """Arquivo que acompanha o programa: ao lado dele, em windows/ ou dentro do .exe."""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(base, name), os.path.join(base, "windows", name)):
        if os.path.exists(path):
            return path
    return None


def _win_setup() -> None:
    """Windows: nitidez em telas de alta densidade e identidade própria na barra de tarefas."""
    import ctypes
    for call in (lambda: ctypes.windll.shcore.SetProcessDpiAwareness(1),
                 lambda: ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)):
        try:
            call()
        except (AttributeError, OSError):
            pass


def _win_dark_titlebar(window) -> None:
    """Windows 10 e 11: barra de título escura; no 11, na cor do cabeçalho."""
    import ctypes
    from ctypes import wintypes
    try:
        user32, dwmapi = ctypes.windll.user32, ctypes.windll.dwmapi
        user32.GetParent.restype = wintypes.HWND
        user32.GetParent.argtypes = [wintypes.HWND]
        set_attr = dwmapi.DwmSetWindowAttribute
        set_attr.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        window.update_idletasks()
        hwnd = user32.GetParent(window.winfo_id())
        on = ctypes.c_int(1)
        if set_attr(hwnd, 20, ctypes.byref(on), ctypes.sizeof(on)):     # modo escuro
            set_attr(hwnd, 19, ctypes.byref(on), ctypes.sizeof(on))     # Windows 10 antes da 2004
        red, green, blue = (int(THEME["bar"][i:i + 2], 16) for i in (1, 3, 5))
        color = ctypes.c_int(red | green << 8 | blue << 16)             # cor da barra: só no 11
        set_attr(hwnd, 35, ctypes.byref(color), ctypes.sizeof(color))
    except (AttributeError, OSError):
        pass


def run_gui_tk(home: str | None) -> int:
    try:
        import tkinter as tk
        from tkinter import font as tkfont, ttk
    except ImportError:
        print("Falta a parte gráfica do Python. No Debian/Ubuntu:\n"
              "    sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1\n"
              "ou, para a janela simples (Tk):\n"
              "    sudo apt install python3-tk", file=sys.stderr)
        return 1
    import queue

    T = THEME
    if WINDOWS:
        _win_setup()
    root = tk.Tk()
    root.withdraw()
    root.title(APP_NAME)
    root.configure(bg=T["bg"])
    scale = root.winfo_fpixels("1i") / 96.0

    def px(n):
        return int(round(n * scale))

    def line(parent):
        return tk.Frame(parent, height=1, bg=T["border"], bd=0, highlightthickness=0)

    # ---- fontes e estilos
    base = tkfont.nametofont("TkDefaultFont")
    if WINDOWS:
        base.configure(family="Segoe UI", size=10)
    for other in ("TkTextFont", "TkHeadingFont"):
        tkfont.nametofont(other).configure(family=base.cget("family"), size=base.cget("size"))
    bold = base.copy()
    bold.configure(weight="bold")
    big = base.copy()
    big.configure(size=int(base.cget("size") * 1.6), weight="bold")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=T["bg"], foreground=T["fg"], fieldbackground=T["surface"],
                    bordercolor=T["border"], lightcolor=T["bg"], darkcolor=T["bg"],
                    troughcolor=T["bg"], focuscolor=T["accent"], insertcolor=T["fg"],
                    selectbackground=T["selected"], selectforeground=T["fg"], font=base)
    style.configure("Bar.TFrame", background=T["bar"])
    style.configure("Bar.TLabel", background=T["bar"], foreground=T["fg_dim"])
    style.configure("Dim.TLabel", foreground=T["fg_dim"])
    style.configure("Title.TLabel", font=big)

    def button_style(name, bg, hover, fg):
        fill = [("disabled", T["bar"]), ("pressed", hover), ("active", hover)]
        style.configure(name, background=bg, foreground=fg, bordercolor=bg, lightcolor=bg,
                        darkcolor=bg, focuscolor=bg, borderwidth=1, relief="flat",
                        padding=(px(14), px(6)), font=bold)
        style.map(name, background=fill, lightcolor=fill, darkcolor=fill, focuscolor=fill,
                  bordercolor=[("disabled", T["border"]), ("focus", T["fg_dim"])] + fill[1:],
                  foreground=[("disabled", T["fg_muted"])])

    button_style("TButton", T["raised"], T["raised_hover"], T["fg"])
    button_style("Accent.TButton", T["accent_bg"], T["accent"], T["on_accent"])
    button_style("Danger.TButton", T["danger_soft"], T["danger_soft_hover"], T["danger"])

    field = dict(fieldbackground=T["surface"], foreground=T["fg"], bordercolor=T["border"],
                 lightcolor=T["surface"], darkcolor=T["surface"], padding=(px(8), px(5)))
    focus = dict(bordercolor=[("focus", T["accent"])], lightcolor=[("focus", T["surface"])],
                 darkcolor=[("focus", T["surface"])])
    style.configure("TEntry", insertcolor=T["fg"], **field)
    style.map("TEntry", **focus)
    style.configure("TCombobox", background=T["surface"], arrowcolor=T["fg_dim"],
                    arrowsize=px(14), **field)
    style.map("TCombobox", fieldbackground=[("readonly", T["surface"])],
              background=[("active", T["raised"]), ("readonly", T["surface"])],
              foreground=[("readonly", T["fg"])], selectbackground=[("readonly", T["surface"])],
              selectforeground=[("readonly", T["fg"])], **focus)
    for option, value in (("background", T["surface"]), ("foreground", T["fg"]),
                          ("selectBackground", T["selected"]), ("selectForeground", T["fg"]),
                          ("font", base)):
        root.option_add(f"*TCombobox*Listbox.{option}", value)

    style.configure("Treeview", background=T["bg"], fieldbackground=T["bg"], foreground=T["fg"],
                    bordercolor=T["bg"], lightcolor=T["bg"], darkcolor=T["bg"], borderwidth=0,
                    rowheight=base.metrics("linespace") + px(12))
    style.map("Treeview", background=[("selected", T["selected"])],
              foreground=[("selected", T["fg"])])
    style.configure("Treeview.Heading", background=T["bg"], foreground=T["fg_muted"],
                    bordercolor=T["border"], lightcolor=T["bg"], darkcolor=T["bg"],
                    relief="flat", padding=(px(2), px(6)), font=bold)
    style.map("Treeview.Heading", background=[("active", T["surface"])],
              foreground=[("active", T["fg_dim"])])

    # barra de rolagem fina, sem setas
    style.layout("Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
        "sticky": "ns", "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
    thumb = [("active", T["fg_muted"])]
    style.configure("Vertical.TScrollbar", background=T["raised"], troughcolor=T["bg"],
                    bordercolor=T["bg"], lightcolor=T["raised"], darkcolor=T["raised"],
                    gripcount=0, arrowsize=px(12))
    style.map("Vertical.TScrollbar", background=thumb, lightcolor=thumb, darkcolor=thumb)
    style.configure("Horizontal.TProgressbar", background=T["accent"], troughcolor=T["surface"],
                    bordercolor=T["surface"], lightcolor=T["accent"], darkcolor=T["accent"])

    class App:
        def __init__(self):
            self.cookies: list[Cookie] = []
            self.hay: list[str] = []           # texto de busca de cada cookie
            self.visible: list[str] = []       # linhas mostradas, em ordem; o id é a posição
            self.app_choices: list[str | None] = [None]
            self.app_selected: str | None = None
            self.needle = ""
            self.sort_col: str | None = None
            self.sort_desc = False
            self.busy = False
            self.note = ""                     # resultado da última eliminação, vai no rodapé
            self.search_job = None
            self.results: queue.Queue = queue.Queue()
            self._build()
            self._poll()

        # ---- montagem
        def _build(self):
            header = ttk.Frame(root, style="Bar.TFrame", padding=(px(10), px(8)))
            header.pack(fill="x")
            self.btn_scan = ttk.Button(header, text="Verificar cookies", style="Accent.TButton",
                                       command=self.start_scan)
            self.btn_scan.pack(side="left")
            self.btn_delete = ttk.Button(header, text="Eliminar cookies", style="Danger.TButton",
                                         command=self.ask_delete)
            self.btn_delete.state(["disabled"])
            self.btn_delete.pack(side="right")
            line(root).pack(fill="x")

            footer = ttk.Frame(root, style="Bar.TFrame", padding=(px(10), px(6)))
            footer.pack(side="bottom", fill="x")
            self.footer = ttk.Label(footer, text="Pronto.", style="Bar.TLabel", anchor="w")
            self.footer.pack(fill="x")
            self.footer.bind("<Configure>",
                             lambda event: self.footer.configure(wraplength=event.width))
            line(root).pack(side="bottom", fill="x")

            body = ttk.Frame(root)
            body.pack(fill="both", expand=True)
            body.rowconfigure(0, weight=1)
            body.columnconfigure(0, weight=1)
            self.pages = {}
            for name in ("start", "busy", "empty", "list"):
                self.pages[name] = ttk.Frame(body)
                self.pages[name].grid(row=0, column=0, sticky="nsew")

            def centered(page):
                box = ttk.Frame(self.pages[page])
                box.place(relx=0.5, rely=0.45, anchor="center")
                return box

            box = centered("start")
            ttk.Label(box, text="Nenhuma verificação ainda", style="Title.TLabel").pack()
            ttk.Label(box, style="Dim.TLabel", justify="center",
                      text="Lista os cookies guardados pelos navegadores e aplicativos "
                           "desta conta.\nO valor dos cookies nunca é lido nem mostrado."
                      ).pack(pady=(px(10), px(22)))
            ttk.Button(box, text="Verificar cookies", style="Accent.TButton",
                       command=self.start_scan).pack()
            box = centered("busy")
            ttk.Label(box, text="Trabalhando…", style="Title.TLabel").pack(pady=(0, px(16)))
            self.progress = ttk.Progressbar(box, mode="indeterminate", length=px(220))
            self.progress.pack()
            ttk.Label(centered("empty"), text="Nenhum cookie guardado",
                      style="Title.TLabel").pack()

            page = self.pages["list"]
            bar = ttk.Frame(page, padding=(px(10), px(8)))
            bar.pack(fill="x")
            self.combo = ttk.Combobox(bar, state="readonly", values=[ALL_APPS], width=30)
            self.combo.current(0)
            self.combo.pack(side="left")
            self.combo.bind("<<ComboboxSelected>>", self.on_app)
            self.search_var = tk.StringVar()
            self.search = ttk.Entry(bar, textvariable=self.search_var)
            self.search.pack(side="left", fill="x", expand=True, padx=(px(8), 0))
            # dica dentro do campo, visível enquanto ele está vazio
            self.hint = tk.Label(self.search, text="Filtrar por site, cookie ou tipo", bd=0,
                                 bg=T["surface"], fg=T["fg_muted"], font=base, cursor="xterm")
            self.hint.place(x=px(9), rely=0.5, anchor="w")
            self.hint.bind("<Button-1>", lambda _event: self.search.focus_set())
            self.search_var.trace_add("write", self.on_search)
            line(page).pack(fill="x")

            table = ttk.Frame(page)
            table.pack(fill="both", expand=True)
            self.tree = ttk.Treeview(table, columns=[col for _t, col, _s, _w in COLUMNS],
                                     show="headings", selectmode="extended")
            for title, col, _sort, width in COLUMNS:
                self.tree.heading(col, text=title, anchor="w",
                                  command=lambda c=col: self.sort_by(c))
                self.tree.column(col, width=px(width or 300), minwidth=px(70),
                                 stretch=not width, anchor="w")
            scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")
            self.tree.pack(side="left", fill="both", expand=True)
            self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_footer())
            for key in ("<Control-a>", "<Control-A>"):
                self.tree.bind(key, lambda _event: self.tree.selection_set(self.visible))
            self.tree.bind("<Escape>", lambda _event: self.tree.selection_set(()))
            self.show("start")

        def show(self, name):
            self.pages[name].tkraise()

        def dialog(self, heading, body, buttons, answer=None):
            """Diálogo modal. buttons: [(resposta, texto, estilo)]; a primeira vale para o Esc."""
            top = tk.Toplevel(root, bg=T["surface"])
            top.withdraw()
            top.title(APP_NAME)
            top.transient(root)
            top.resizable(False, False)
            box = tk.Frame(top, bg=T["surface"], padx=px(24), pady=px(20))
            box.pack(fill="both", expand=True)
            text = dict(bg=T["surface"], justify="left", anchor="w", wraplength=px(460))
            tk.Label(box, text=heading, fg=T["fg"], font=big, **text).pack(fill="x")
            tk.Label(box, text=body, fg=T["fg_dim"], font=base, **text).pack(
                fill="x", pady=(px(10), px(20)))
            row = tk.Frame(box, bg=T["surface"])
            row.pack(fill="x")

            def close(response):
                top.destroy()
                if answer:
                    answer(response)

            for response, label, look in reversed(buttons):
                ttk.Button(row, text=label, style=look,
                           command=lambda r=response: close(r)).pack(side="right",
                                                                     padx=(px(8), 0))
            top.protocol("WM_DELETE_WINDOW", lambda: close(buttons[0][0]))
            top.bind("<Escape>", lambda _event: close(buttons[0][0]))
            top.update_idletasks()
            x = root.winfo_rootx() + (root.winfo_width() - top.winfo_reqwidth()) // 2
            y = root.winfo_rooty() + (root.winfo_height() - top.winfo_reqheight()) // 3
            top.geometry(f"+{max(x, 0)}+{max(y, 0)}")
            if WINDOWS:
                _win_dark_titlebar(top)
            top.deiconify()
            top.wait_visibility()
            top.grab_set()
            top.focus_set()

        # ---- trabalho fora da janela
        def work(self, job, done):
            """Roda job() em segundo plano e entrega o que ele devolver a done(*resultado)."""
            threading.Thread(target=lambda: self.results.put((done, job())),
                             daemon=True).start()

        def _poll(self):
            try:
                while True:
                    done, result = self.results.get_nowait()
                    done(*result)
            except queue.Empty:
                pass
            root.after(60, self._poll)

        def set_busy(self, busy, text=""):
            self.busy = busy
            self.btn_scan.state(["disabled" if busy else "!disabled"])
            self.btn_delete.state(["disabled"])
            if busy:
                self.footer.configure(text=text)
                self.progress.start(12)
                self.show("busy")
            else:
                self.progress.stop()

        # ---- filtro e ordenação
        def refilter(self):
            app, needle = self.app_selected, self.needle
            rows = [i for i, c in enumerate(self.cookies)
                    if (not app or c.app == app) and (not needle or needle in self.hay[i])]
            if self.sort_col:
                attr = next(sort for _t, col, sort, _w in COLUMNS if col == self.sort_col)
                rows.sort(key=lambda i: getattr(self.cookies[i], attr).casefold(),
                          reverse=self.sort_desc)
            self.visible = [str(i) for i in rows]
            keep = self.picked()
            self.tree.set_children("", *self.visible)
            self.tree.selection_set(keep)
            self.update_footer()

        def picked(self):
            shown = set(self.visible)
            return [iid for iid in self.tree.selection() if iid in shown]

        def update_footer(self):
            if not self.cookies:
                return
            sess = sum(1 for c in self.cookies if c.store == STORE_SESSION)
            text = footer_text(len(self.cookies), len(self.visible), len(self.picked()), sess)
            self.footer.configure(text=f"{self.note} {text}".strip())
            self.btn_delete.state(["!disabled" if self.visible and not self.busy
                                   else "disabled"])

        def sort_by(self, col):
            self.sort_desc = self.sort_col == col and not self.sort_desc
            self.sort_col = col
            for title, other, _sort, _width in COLUMNS:
                arrow = ("  ▼" if self.sort_desc else "  ▲") if other == col else ""
                self.tree.heading(other, text=title + arrow)
            self.refilter()

        def on_search(self, *_):
            if self.search_var.get():
                self.hint.place_forget()
            else:
                self.hint.place(x=px(9), rely=0.5, anchor="w")
            if self.search_job:
                root.after_cancel(self.search_job)
            self.search_job = root.after(150, self.apply_search)

        def apply_search(self):
            self.search_job = None
            self.needle = self.search_var.get().strip().lower()
            self.refilter()

        def on_app(self, _event):
            self.app_selected = self.app_choices[self.combo.current()]
            self.combo.selection_clear()
            self.refilter()

        # ---- verificar
        def start_scan(self):
            if self.busy:
                return
            self.note = ""
            self.set_busy(True, "Verificando os cookies guardados…")
            self.work(lambda: (scan_safely(home),), self.scan_done)

        def scan_done(self, result):
            cookies, warnings = result
            self.tree.delete(*(str(i) for i in range(len(self.cookies))))
            self.cookies = cookies
            self.hay = [search_text(c) for c in cookies]
            for i, c in enumerate(cookies):
                self.tree.insert("", "end", iid=str(i), values=(
                    app_label(c), c.profile, c.host, c.name, c.kind, c.expires, c.store))
            counts = Counter(c.app for c in cookies)
            self.app_choices = [None] + sorted(counts)
            if self.app_selected not in counts:
                self.app_selected = None
            self.combo.configure(values=[ALL_APPS] + [
                f"{app} ({fmt_num(counts[app])})" for app in self.app_choices[1:]])
            self.combo.current(self.app_choices.index(self.app_selected))
            self.set_busy(False)
            self.refilter()
            if cookies:
                self.show("list")
            else:
                self.show("empty")
                self.footer.configure(text=f"{self.note} Nenhum cookie guardado em disco "
                                           "foi encontrado.".strip())
            if warnings:
                self.dialog("Alguns locais não puderam ser lidos", "\n".join(warnings),
                            [("ok", "Entendi", "TButton")])

        # ---- eliminar
        def ask_delete(self):
            if self.busy:
                return
            picked = self.picked()
            rows = picked or self.visible
            if not rows:
                return
            targets = [self.cookies[int(iid)] for iid in rows]
            heading, body = delete_question(targets, bool(picked), len(self.cookies))
            self.dialog(heading, body, [("cancel", "Cancelar", "TButton"),
                                        ("delete", "Eliminar", "Danger.TButton")],
                        lambda response: response == "delete" and self.start_delete(targets))

        def start_delete(self, targets):
            if self.busy:
                return
            self.set_busy(True, "Eliminando…")
            self.work(lambda: (delete_safely(targets), scan_safely(home)), self.delete_done)

        def delete_done(self, outcome, result):
            self.note = deleted_text(outcome["deleted"]) + "."
            self.scan_done(result)
            notes = delete_notes(outcome)
            if notes:
                self.dialog("Nem tudo foi eliminado", notes, [("ok", "Entendi", "TButton")])

    App()
    root.geometry(f"{min(px(1200), root.winfo_screenwidth() - px(80))}"
                  f"x{min(px(680), root.winfo_screenheight() - px(120))}")
    root.minsize(px(720), px(400))
    if WINDOWS:
        icon = _resource("icone.ico")
        if icon:
            try:
                root.iconbitmap(default=icon)
            except tk.TclError:
                pass
        _win_dark_titlebar(root)
    root.deiconify()
    root.mainloop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--resumo", action="store_true",
                        help="imprime só a contagem por aplicativo e sai")
    parser.add_argument("--home", metavar="DIR", default=None,
                        help="usa DIR no lugar da pasta pessoal (para testes)")
    parser.add_argument("--tk", action="store_true",
                        help="no Linux, abre a janela Tk (a mesma do Windows)")
    args = parser.parse_args()
    if args.resumo:
        print_summary(args.home)
        return 0
    # Linux: janela GTK; sem GTK 4 / libadwaita recentes (ou com --tk), a janela Tk
    if not WINDOWS and not args.tk and gtk_ready():
        return run_gui(args.home)
    return run_gui_tk(args.home)


if __name__ == "__main__":
    sys.exit(main())
