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
    limpa_cookies.py --minimizado abre a janela minimizada (usado ao iniciar com o sistema)

A janela também programa limpezas automáticas (ao iniciar a sessão, num horário, ao
desligar), de todos os sites ou só de alguns; ver "limpeza automática" mais abaixo.
Guarda quantos cookies foram eliminados (ver "estatísticas") e pode abrir sozinha
quando o sistema inicia (ver "configurações").
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, timedelta

APP_ID = "local.LimpaCookies"
APP_NAME = "Limpa Cookies"
APP_VERSION = "1.3.0"
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


# --------------------------------------------------------------------------- limpeza automática
#
# Uma regra diz QUAIS sites limpar (lista vazia = todos) e QUANDO. As regras ficam em
# regras.json; quem dispara é o próprio sistema (autostart e systemd no Linux, registro e
# Agendador de Tarefas no Windows), chamando este programa com --automatico GATILHO.

WHEN_LOGIN, WHEN_TIME, WHEN_SHUTDOWN = "inicio", "horario", "desligar"
WHEN_LABELS = [
    (WHEN_LOGIN, "Ao iniciar a sessão"),
    (WHEN_TIME, "Todos os dias, num horário"),
    # o Windows não deixa um programa comum rodar durante o desligamento
    (WHEN_SHUTDOWN, "Ao desligar o computador (limpa no início seguinte)" if WINDOWS
     else "Ao desligar o computador"),
]


def config_dir(home: str | None) -> str:
    if WINDOWS:
        base = os.path.join(home, "AppData", "Roaming") if home else (
            os.environ.get("APPDATA")
            or os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
        return os.path.join(base, "LimpaCookies")
    base = os.path.join(home, ".config") if home else _xdg_config()
    return os.path.join(base, "limpa-cookies")


def _xdg_config() -> str:
    return os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")


def _read_json(path: str, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _write_text(path: str, text: str) -> bool:
    """Grava só se o conteúdo mudou. Devolve se gravou."""
    try:
        with open(path, encoding="utf-8") as fh:
            if fh.read() == text:
                return False
    except (OSError, ValueError):
        pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)
    return True


def parse_sites(text: str) -> list[str]:
    """'https://www.Exemplo.com/x, loja.org' -> ['exemplo.com', 'loja.org']"""
    sites: list[str] = []
    for piece in re.split(r"[\s,;]+", text.strip().lower()):
        piece = piece.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].strip(".")
        if piece.startswith("www."):
            piece = piece[4:]
        if piece and piece not in sites:
            sites.append(piece)
    return sites


def valid_time(text: str) -> str | None:
    """'8:30' ou '8h30' -> '08:30'; None se não for um horário."""
    found = re.fullmatch(r"\s*(\d{1,2})[:hH](\d{2})\s*", text)
    if found and int(found[1]) < 24 and int(found[2]) < 60:
        return f"{int(found[1]):02d}:{found[2]}"
    return None


def site_matches(host: str, sites: list[str]) -> bool:
    """O cookie é de um dos sites (ou de um subdomínio deles)? Lista vazia aceita tudo."""
    host = host.lstrip(".").lower()
    return not sites or any(host == site or host.endswith("." + site) for site in sites)


def new_rule(sites_text: str, when: str, time_text: str) -> tuple[dict | None, str]:
    """(regra, "") ou (None, o que está errado)."""
    hour = ""
    if when == WHEN_TIME:
        hour = valid_time(time_text) or ""
        if not hour:
            return None, "Escreva o horário como HH:MM, por exemplo 08:30."
    return {"id": os.urandom(4).hex(), "sites": parse_sites(sites_text), "quando": when,
            "hora": hour, "ativa": True}, ""


def rule_sites_text(rule: dict) -> str:
    return ", ".join(rule["sites"]) or "Todos os sites"


def rule_when_text(rule: dict) -> str:
    if rule["quando"] == WHEN_TIME:
        return f"Todos os dias às {rule['hora']}"
    return dict(WHEN_LABELS)[rule["quando"]]


def rules_summary(rules: list[dict]) -> str:
    active = sum(1 for rule in rules if rule["ativa"])
    if not rules:
        return "Nenhuma regra ainda"
    return f"{active} regra{'s' if active != 1 else ''} ativa{'s' if active != 1 else ''}"


def load_rules(home: str | None = None) -> list[dict]:
    data = _read_json(os.path.join(config_dir(home), "regras.json"), {})
    rules = []
    for raw in data.get("regras", []) if isinstance(data, dict) else []:
        if not isinstance(raw, dict) or raw.get("quando") not in dict(WHEN_LABELS):
            continue
        hour = valid_time(str(raw.get("hora", ""))) or ""
        if raw["quando"] == WHEN_TIME and not hour:
            continue
        rules.append({"id": str(raw.get("id") or os.urandom(4).hex()),
                      "sites": parse_sites(" ".join(map(str, raw.get("sites") or []))),
                      "quando": raw["quando"], "hora": hour,
                      "ativa": bool(raw.get("ativa", True))})
    return rules


def save_rules(rules: list[dict], home: str | None = None) -> list[str]:
    """Grava as regras e ajusta os agendamentos do sistema. Devolve avisos."""
    _write_text(os.path.join(config_dir(home), "regras.json"),
                json.dumps({"regras": rules}, ensure_ascii=False, indent=2) + "\n")
    return sync_schedules(rules, home)


def last_runs(home: str | None = None) -> dict:
    """id da regra -> texto da última execução automática."""
    data = _read_json(os.path.join(config_dir(home), "execucoes.json"), {})
    return {k: str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def _shutting_down() -> bool:
    """Linux: o computador está desligando ou reiniciando (e não só fechando a sessão)?"""
    try:
        state = subprocess.run(["systemctl", "is-system-running"], capture_output=True,
                               text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return True
    return state not in ("running", "degraded", "starting", "initializing", "maintenance")


def run_rules(trigger: str, home: str | None = None) -> int:
    """Executa as regras ativas de um gatilho: inicio, desligar ou horario:HH:MM.
    Devolve quantos cookies eliminou."""
    when, _, hour = trigger.partition(":")
    wanted = {when}
    if WINDOWS and when == WHEN_LOGIN:
        wanted.add(WHEN_SHUTDOWN)                 # ver WHEN_LABELS
    elif when == WHEN_SHUTDOWN and not _shutting_down():
        return 0
    rules = [rule for rule in load_rules(home) if rule["ativa"] and rule["quando"] in wanted
             and (rule["quando"] != WHEN_TIME or rule["hora"] == hour)]
    if not rules:
        return 0
    # ao desligar, os navegadores ainda podem estar fechando: insiste por alguns segundos
    tries = 8 if when == WHEN_SHUTDOWN else 1
    deleted: Counter = Counter()
    skipped: dict[str, int] = {}
    for attempt in range(tries):
        for rule in rules:
            cookies, _warnings = scan(home)       # relê a cada regra: eliminar muda os bancos
            outcome = delete([c for c in cookies if site_matches(c.host, rule["sites"])])
            deleted[rule["id"]] += outcome["deleted"]
            skipped[rule["id"]] = sum(outcome["skipped"].values())
        if not any(skipped.values()) or attempt + 1 == tries:
            break
        time.sleep(1.5)
    runs = last_runs(home)
    stamp = time.strftime("%d/%m/%Y %H:%M")
    for rule in rules:
        text = f"{stamp}: {deleted_text(deleted[rule['id']])}"
        if skipped[rule["id"]]:
            text += f", {fmt_num(skipped[rule['id']])} pulados (aplicativo aberto)"
        runs[rule["id"]] = text
    known = {rule["id"] for rule in load_rules(home)}
    _write_text(os.path.join(config_dir(home), "execucoes.json"),
                json.dumps({k: v for k, v in runs.items() if k in known},
                           ensure_ascii=False, indent=2) + "\n")
    record_cleanup(sum(deleted.values()), home)
    return sum(deleted.values())


# ---- agendamento no sistema

def _self_command() -> list[str]:
    """Como chamar este programa sem janela."""
    if getattr(sys, "frozen", False):             # .exe gerado pelo PyInstaller
        return [sys.executable]
    python = sys.executable
    if WINDOWS:                                   # pythonw não abre janela de console
        windowless = os.path.join(os.path.dirname(python), "pythonw.exe")
        if os.path.exists(windowless):
            python = windowless
    return [python, os.path.abspath(__file__)]


def _quoted(args: list[str], doubled: str, escaped: str = "") -> str:
    """Linha de comando com cada parte entre aspas. Os caracteres de doubled são dobrados;
    os de escaped (além de aspas e barra invertida) ganham uma barra invertida."""
    parts = []
    for arg in args:
        for char in '\\"' + escaped:
            arg = arg.replace(char, "\\" + char)
        for char in doubled:
            arg = arg.replace(char, char * 2)
        parts.append(f'"{arg}"')
    return " ".join(parts)


def linux_schedule_files(whens: set[str], times: list[str], command: list[str]) -> dict:
    """Arquivos (caminho relativo a ~/.config -> conteúdo) de que as regras ativas precisam."""
    files = {}
    if WHEN_LOGIN in whens:
        # no .desktop a barra invertida é escapada mais uma vez e o % é dobrado
        line = _quoted(command + ["--automatico", WHEN_LOGIN], "%", "`$").replace("\\", "\\\\")
        files[f"autostart/{APP_ID}.inicio.desktop"] = (
            "[Desktop Entry]\nType=Application\n"
            f"Name={APP_NAME} (limpeza ao iniciar a sessão)\n"
            f"Exec={line}\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n")
    if WHEN_SHUTDOWN in whens:
        line = _quoted(command + ["--automatico", WHEN_SHUTDOWN], "%$")
        files["systemd/user/limpa-cookies-desligar.service"] = (
            f"[Unit]\nDescription={APP_NAME}: limpeza ao desligar o computador\n\n"
            # fica "ativo" durante a sessão; o trabalho é feito quando o systemd o para
            "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n"
            f"ExecStop={line}\nTimeoutStopSec=45\n\n"
            "[Install]\nWantedBy=default.target\n")
    for hour in times:
        name = "systemd/user/limpa-cookies-" + hour.replace(":", "")
        line = _quoted(command + ["--automatico", f"{WHEN_TIME}:{hour}"], "%$")
        files[name + ".service"] = (
            f"[Unit]\nDescription={APP_NAME}: limpeza diária às {hour}\n\n"
            f"[Service]\nType=oneshot\nExecStart={line}\n")
        files[name + ".timer"] = (
            f"[Unit]\nDescription={APP_NAME}: limpeza diária às {hour}\n\n"
            # Persistent: se o computador estava desligado na hora, roda ao ligar
            f"[Timer]\nOnCalendar=*-*-* {hour}:00\nPersistent=true\n\n"
            "[Install]\nWantedBy=timers.target\n")
    return files


def _sync_linux(whens: set[str], times: list[str]) -> list[str]:
    base = _xdg_config()
    wanted = linux_schedule_files(whens, times, _self_command())
    units_dir = os.path.join(base, "systemd", "user")
    existing = {f"autostart/{APP_ID}.inicio.desktop"}
    try:
        existing |= {"systemd/user/" + name for name in os.listdir(units_dir)
                     if name.startswith("limpa-cookies-")
                     and name.endswith((".service", ".timer"))}
    except OSError:
        pass
    problems: list[str] = []

    def systemctl(*args) -> None:
        try:
            done = subprocess.run(["systemctl", "--user", *args], capture_output=True,
                                  text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            problems.append(f"systemctl {' '.join(args)}: {exc}")
            return
        if done.returncode:
            problems.append(f"systemctl {' '.join(args)}: {done.stderr.strip()}")

    def started(rel: str) -> bool:                # unidades que o systemd precisa ativar
        return rel.endswith(".timer") or rel.endswith("-desligar.service")

    changed = False
    for rel in sorted(existing - set(wanted)):
        path = os.path.join(base, rel)
        if not os.path.exists(path):
            continue
        if started(rel):
            systemctl("disable", "--now", os.path.basename(rel))
        os.remove(path)
        changed = True
    for rel, text in wanted.items():
        changed = _write_text(os.path.join(base, rel), text) or changed
    units = [os.path.basename(rel) for rel in wanted if started(rel)]
    if changed and (units or any(r.startswith("systemd/") for r in existing | set(wanted))):
        systemctl("daemon-reload")
    if units:
        systemctl("enable", "--now", *units)
    if problems:
        problems.insert(0, "As regras foram gravadas, mas o agendamento no systemd falhou:")
    return problems


def _windows_run_value(name: str, command: str | None) -> None:
    """Põe (ou, com None, tira) um programa do início de sessão: valor Run do registro
    do usuário, que não pede administrador."""
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                          r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
        if command:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
        else:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass


def _sync_windows(whens: set[str], times: list[str]) -> list[str]:
    command = subprocess.list2cmdline(_self_command())
    hidden = {"creationflags": 0x08000000}        # CREATE_NO_WINDOW
    problems: list[str] = []
    _windows_run_value("LimpaCookies", f"{command} --automatico {WHEN_LOGIN}"
                       if whens & {WHEN_LOGIN, WHEN_SHUTDOWN} else None)
    # horários: uma tarefa diária por horário no Agendador de Tarefas
    state = os.path.join(config_dir(None), "agendado.json")
    old = _read_json(state, [])
    old = {str(hour) for hour in old} if isinstance(old, list) else set()

    def task(hour: str) -> str:
        return f"Limpa Cookies {hour.replace(':', 'h')}"

    for hour in sorted(old - set(times)):
        subprocess.run(["schtasks", "/Delete", "/F", "/TN", task(hour)],
                       capture_output=True, timeout=30, **hidden)
    for hour in times:
        done = subprocess.run(
            ["schtasks", "/Create", "/F", "/SC", "DAILY", "/ST", hour, "/TN", task(hour),
             "/TR", f"{command} --automatico {WHEN_TIME}:{hour}"],
            capture_output=True, text=True, timeout=30, **hidden)
        if done.returncode:
            problems.append(f"Agendador de Tarefas ({hour}): {done.stderr.strip()}")
    _write_text(state, json.dumps(times) + "\n")
    return problems


def sync_schedules(rules: list[dict], home: str | None = None) -> list[str]:
    """Deixa os agendamentos do sistema iguais ao que as regras ativas pedem."""
    if home:                                      # pasta de teste: não agenda nada de verdade
        return []
    active = [rule for rule in rules if rule["ativa"]]
    whens = {rule["quando"] for rule in active}
    times = sorted({rule["hora"] for rule in active if rule["quando"] == WHEN_TIME})
    try:
        return _sync_windows(whens, times) if WINDOWS else _sync_linux(whens, times)
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"As regras foram gravadas, mas não consegui agendar: {exc}"]


# --------------------------------------------------------------------------- estatísticas
#
# Cada eliminação (pela janela ou automática) fica em estatisticas.json: quando, quantos
# cookies e em que sessão. Uma sessão é uma execução do programa: a janela aberta, ou uma
# limpeza automática disparada pelo sistema.

SESSION_ID = f"{int(time.time())}-{os.getpid()}"
STATS_KEEP_DAYS = 60
WEEKDAYS = ["seg", "ter", "qua", "qui", "sex", "sáb", "dom"]


def _cleanups(home: str | None) -> list[dict]:
    data = _read_json(os.path.join(config_dir(home), "estatisticas.json"), {})
    events = []
    for raw in data.get("limpezas", []) if isinstance(data, dict) else []:
        try:
            event = {"quando": int(raw["quando"]), "cookies": int(raw["cookies"]),
                     "sessao": str(raw["sessao"])}
            date.fromtimestamp(event["quando"])
        except (KeyError, TypeError, ValueError, OverflowError, OSError):
            continue
        if event["cookies"] > 0:
            events.append(event)
    return sorted(events, key=lambda event: event["quando"])


def record_cleanup(count: int, home: str | None = None) -> None:
    """Anota que esta sessão eliminou count cookies agora. Nunca falha: a estatística
    não pode atrapalhar a limpeza."""
    if count <= 0:
        return
    try:
        now = int(time.time())
        events = [event for event in _cleanups(home)
                  if event["quando"] >= now - STATS_KEEP_DAYS * 86400]
        events.append({"quando": now, "cookies": count, "sessao": SESSION_ID})
        _write_text(os.path.join(config_dir(home), "estatisticas.json"),
                    json.dumps({"limpezas": events}, indent=1) + "\n")
    except OSError:
        pass


def load_stats(home: str | None = None, now: float | None = None) -> dict:
    """Cookies eliminados na última sessão que limpou algo e nos últimos 7 dias (hoje e
    os 6 anteriores): {"session", "session_when", "week", "week_runs", "days"}."""
    events = _cleanups(home)
    today = date.fromtimestamp(time.time() if now is None else now)
    days = [today - timedelta(days=back) for back in range(6, -1, -1)]
    per_day: Counter = Counter()
    runs = 0
    for event in events:
        day = date.fromtimestamp(event["quando"])
        if days[0] <= day <= today:
            per_day[day] += event["cookies"]
            runs += 1
    last = events[-1] if events else None
    return {"session": sum(e["cookies"] for e in events if e["sessao"] == last["sessao"])
            if last else 0,
            "session_when": last["quando"] if last else None,
            "week": sum(per_day.values()), "week_runs": runs,
            "days": [(day, per_day[day]) for day in days]}


def when_text(epoch: float, now: float | None = None) -> str:
    day = date.fromtimestamp(epoch)
    today = date.fromtimestamp(time.time() if now is None else now)
    hour = time.strftime("%H:%M", time.localtime(epoch))
    if day == today:
        return f"hoje às {hour}"
    if day == today - timedelta(days=1):
        return f"ontem às {hour}"
    return f"{day:%d/%m/%Y} às {hour}"


def stats_view(stats: dict, now: float | None = None) -> dict:
    """Os textos do monitor da página inicial, iguais nas duas janelas.
    bars: [(dia da semana, fração da barra mais alta, dica, é hoje)]."""
    top = max(n for _day, n in stats["days"]) or 1
    runs = stats["week_runs"]
    return {
        "session": fmt_num(stats["session"]),
        "session_note": when_text(stats["session_when"], now)
        if stats["session_when"] else "Nenhuma limpeza ainda",
        "week": fmt_num(stats["week"]),
        "week_note": f"em {fmt_num(runs)} limpeza{'s' if runs != 1 else ''}" if runs
        else "Nenhuma limpeza nestes dias",
        "bars": [(WEEKDAYS[day.weekday()], n / top,
                  f"{WEEKDAYS[day.weekday()]}, {day:%d/%m}: {deleted_text(n)}",
                  index == 6) for index, (day, n) in enumerate(stats["days"])],
    }


# --------------------------------------------------------------------------- configurações
#
# config.json guarda as escolhas da aba Configurações. "Iniciar com o sistema" abre a
# janela no início da sessão: arquivo em ~/.config/autostart no Linux, valor Run do
# registro do usuário no Windows.

SETTINGS = {"iniciar_com_sistema": False, "iniciar_minimizado": False}
SETTING_TEXTS = {
    "iniciar_com_sistema": (
        "Iniciar com o sistema",
        f"Abre o {APP_NAME} sozinho quando você liga o computador e entra na sua conta."),
    "iniciar_minimizado": (
        "Abrir minimizado",
        "Ao iniciar com o sistema, a janela fica minimizada até você precisar dela."),
}


def load_settings(home: str | None = None) -> dict:
    data = _read_json(os.path.join(config_dir(home), "config.json"), {})
    data = data if isinstance(data, dict) else {}
    return {key: bool(data.get(key, default)) for key, default in SETTINGS.items()}


def linux_autostart_file(command: list[str], minimized: bool) -> str:
    """O .desktop que abre a janela no início da sessão."""
    args = command + (["--minimizado"] if minimized else [])
    # no .desktop a barra invertida é escapada mais uma vez e o % é dobrado
    line = _quoted(args, "%", "`$").replace("\\", "\\\\")
    return ("[Desktop Entry]\nType=Application\n"
            f"Name={APP_NAME}\nExec={line}\nIcon={APP_ID}\nTerminal=false\n"
            "X-GNOME-Autostart-enabled=true\n")


def sync_autostart(settings: dict, home: str | None = None) -> list[str]:
    """Deixa o início com o sistema igual ao que as configurações pedem. Devolve avisos."""
    if home:                                      # pasta de teste: não mexe no sistema
        return []
    enabled, minimized = settings["iniciar_com_sistema"], settings["iniciar_minimizado"]
    try:
        if WINDOWS:
            args = _self_command() + (["--minimizado"] if minimized else [])
            _windows_run_value("LimpaCookiesJanela",
                               subprocess.list2cmdline(args) if enabled else None)
        else:
            path = os.path.join(_xdg_config(), "autostart", APP_ID + ".desktop")
            if enabled:
                _write_text(path, linux_autostart_file(_self_command(), minimized))
            elif os.path.exists(path):
                os.remove(path)
    except OSError as exc:
        return [f"Não consegui configurar o início com o sistema: {exc}"]
    return []


def save_settings(settings: dict, home: str | None = None) -> list[str]:
    """Grava as configurações e aplica no sistema. Devolve avisos."""
    try:
        _write_text(os.path.join(config_dir(home), "config.json"),
                    json.dumps(settings, ensure_ascii=False, indent=2) + "\n")
    except OSError as exc:
        return [f"Não consegui gravar as configurações: {exc}"]
    return sync_autostart(settings, home)


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


def delete_safely(cookies: list[Cookie], home: str | None) -> dict:
    """Elimina e anota nas estatísticas."""
    try:
        outcome = delete(cookies)
    except Exception as exc:
        return {"deleted": 0, "skipped": Counter(), "errors": [str(exc)]}
    record_cleanup(outcome["deleted"], home)
    return outcome


TABS = [("inicio", "Início"), ("cookies", "Cookies"), ("config", "Configurações")]
IDLE_TITLE = "Nenhuma verificação ainda"
IDLE_TEXT = "Clique em Verificar cookies para listar o que está guardado nesta conta."


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
        .inicio {{ background-image: radial-gradient(circle at 50% 12%,
                   alpha({t["accent"]}, 0.13), transparent 38%); }}
        .inicio-titulo {{ font-size: 26pt; font-weight: 800; }}
        .inicio-texto {{ color: {t["fg_dim"]}; font-size: 11.5pt; }}
        .inicio-nota {{ color: {t["fg_muted"]}; font-size: 9.5pt; }}
        button.cartao {{ background-color: {t["surface"]}; border: 1px solid {t["border"]};
                        border-radius: 16px; padding: 18px; font-weight: normal; }}
        button.cartao:hover {{ background-color: {t["raised"]};
                              border-color: alpha({t["accent"]}, 0.6); }}
        button.cartao.principal {{ border-color: alpha({t["accent"]}, 0.6); }}
        .cartao-icone {{ background-color: alpha({t["accent"]}, 0.16); color: {t["accent"]};
                        border-radius: 10px; padding: 9px; }}
        .cartao-texto {{ color: {t["fg_dim"]}; }}
        .cartao-estado {{ color: {t["accent"]}; font-size: 9.5pt; font-weight: 600; }}
        .monitor {{ background-color: {t["surface"]}; border: 1px solid {t["border"]};
                   border-radius: 16px; padding: 16px 18px; }}
        .monitor-rotulo {{ color: {t["fg_muted"]}; font-size: 9.5pt; font-weight: 600; }}
        .monitor-numero {{ font-size: 21pt; font-weight: 800;
                          font-feature-settings: "tnum"; }}
        .monitor-nota {{ color: {t["fg_dim"]}; font-size: 9.5pt; }}
        .barra {{ background-color: {t["accent"]}; border-radius: 4px 4px 0 0;
                 min-width: 18px; }}
        .barra.vazia {{ background-color: {t["border"]}; border-radius: 0; }}
        .barra-dia {{ color: {t["fg_muted"]}; font-size: 8.5pt; }}
        .barra-dia.hoje {{ color: {t["fg"]}; font-weight: 700; }}
    """


def run_gui(home: str | None, minimized: bool = False) -> int:
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
            self.rules = load_rules(home)
            self.settings = load_settings(home)
            sync_autostart(self.settings, home)   # o programa pode ter mudado de pasta

            self.btn_scan = Gtk.Button(label="Verificar cookies")
            self.btn_scan.add_css_class("suggested-action")
            self.btn_scan.connect("clicked", self.on_scan)
            self.btn_delete = Gtk.Button(label="Eliminar cookies", sensitive=False)
            self.btn_delete.add_css_class("eliminar")
            self.btn_delete.connect("clicked", self.on_delete)
            btn_rules = Gtk.Button(icon_name="alarm-symbolic",
                                   tooltip_text="Limpeza automática")
            btn_rules.connect("clicked", self.on_rules)
            header = Adw.HeaderBar()
            header.pack_start(self.btn_scan)
            header.pack_start(btn_rules)
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

            scan_now = Gtk.Button(label="Verificar cookies", halign=Gtk.Align.CENTER)
            scan_now.add_css_class("pill")
            scan_now.add_css_class("suggested-action")
            scan_now.connect("clicked", self.on_scan)
            page_idle = Adw.StatusPage(icon_name="edit-find-symbolic", title=IDLE_TITLE,
                                       description=IDLE_TEXT, child=scan_now)
            spinner = Gtk.Spinner(spinning=True, width_request=32, height_request=32,
                                  halign=Gtk.Align.CENTER)
            page_busy = Adw.StatusPage(title="Trabalhando…", child=spinner)
            self.page_empty = Adw.StatusPage(icon_name="emblem-ok-symbolic",
                                             title="Nenhum cookie guardado")

            # aba Cookies: uma página por situação
            self.stack = Gtk.Stack()
            self.stack.add_named(page_idle, "idle")
            self.stack.add_named(page_busy, "busy")
            self.stack.add_named(self.page_empty, "empty")
            self.stack.add_named(page_list, "list")

            self.tabs = Adw.ViewStack(vexpand=True)
            pages = {"inicio": (self._start_page(), "go-home-symbolic"),
                     "cookies": (self.stack, "view-list-symbolic"),
                     "config": (self._settings_page(), "emblem-system-symbolic")}
            for key, title in TABS:
                self.tabs.add_titled_with_icon(pages[key][0], key, title, pages[key][1])
            self.tabs.connect("notify::visible-child-name", self._on_tab)
            header.set_title_widget(Adw.ViewSwitcher(stack=self.tabs,
                                                     policy=Adw.ViewSwitcherPolicy.WIDE))

            self.footer = Gtk.Label(xalign=0, wrap=True, margin_top=6, margin_bottom=6,
                                    margin_start=10, margin_end=10,
                                    label="Pronto.")
            footer_bar = Gtk.Box()
            footer_bar.add_css_class("rodape")
            footer_bar.append(self.footer)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            body.append(self.tabs)
            body.append(Gtk.Separator())
            body.append(footer_bar)
            self.toasts = Adw.ToastOverlay(child=body)
            layout = Adw.ToolbarView(content=self.toasts)
            layout.add_top_bar(header)
            self.set_content(layout)
            self._refresh_stats()

        def _on_tab(self, *_):
            if self.tabs.get_visible_child_name() == "inicio":
                self._refresh_stats()             # limpezas automáticas contam também

        # ---- página inicial
        def _card(self, icon_name, title, text, state, handler, primary=False):
            """Cartão clicável. Devolve (botão, rótulo da linha de estado)."""
            badge = Gtk.Image(icon_name=icon_name, pixel_size=20, halign=Gtk.Align.START)
            badge.add_css_class("cartao-icone")
            head = Gtk.Label(label=title, xalign=0, margin_top=6)
            head.add_css_class("heading")
            body = Gtk.Label(label=text, xalign=0, wrap=True, max_width_chars=32)
            body.add_css_class("cartao-texto")
            status = Gtk.Label(label=state, xalign=0, margin_top=4)
            status.add_css_class("cartao-estado")
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            for widget in (badge, head, body, status):
                box.append(widget)
            button = Gtk.Button(child=box)
            button.add_css_class("cartao")
            if primary:
                button.add_css_class("principal")
            button.connect("clicked", handler)
            return button, status

        BAR_HEIGHT = 46

        def _monitor(self):
            """Painel com os cookies eliminados: última sessão, 7 dias e um gráfico por dia."""
            def tile(title):
                head = Gtk.Label(label=title, xalign=0)
                head.add_css_class("monitor-rotulo")
                number = Gtk.Label(xalign=0)
                number.add_css_class("monitor-numero")
                note = Gtk.Label(xalign=0)
                note.add_css_class("monitor-nota")
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True,
                              valign=Gtk.Align.END)
                for widget in (head, number, note):
                    box.append(widget)
                return box, number, note

            session, self.stat_session, self.stat_session_note = tile("Última sessão")
            week, self.stat_week, self.stat_week_note = tile("Últimos 7 dias")
            chart = Gtk.Box(spacing=8, valign=Gtk.Align.END)
            self.stat_bars = []
            for _day in range(7):
                bar = Gtk.Box(valign=Gtk.Align.END)
                bar.add_css_class("barra")
                slot = Gtk.Box(height_request=self.BAR_HEIGHT, halign=Gtk.Align.CENTER)
                slot.append(bar)
                day = Gtk.Label()
                day.add_css_class("barra-dia")
                column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                column.append(slot)
                column.append(day)
                chart.append(column)
                self.stat_bars.append((column, bar, day))
            tiles = Gtk.Box(spacing=18, homogeneous=True, hexpand=True)
            tiles.append(session)
            tiles.append(week)
            row = Gtk.Box(spacing=18)
            row.append(tiles)
            row.append(chart)
            head = Gtk.Label(label="Cookies eliminados", xalign=0)
            head.add_css_class("heading")
            panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=22)
            panel.add_css_class("monitor")
            panel.append(head)
            panel.append(row)
            return panel

        def _refresh_stats(self):
            view = stats_view(load_stats(home))
            self.stat_session.set_text(view["session"])
            self.stat_session_note.set_text(view["session_note"])
            self.stat_week.set_text(view["week"])
            self.stat_week_note.set_text(view["week_note"])
            for (column, bar, day), (label, share, tip, today) in zip(self.stat_bars,
                                                                      view["bars"]):
                bar.set_size_request(-1, max(2, round(self.BAR_HEIGHT * share)))
                column.set_tooltip_text(tip)
                day.set_text(label)
                for widget, name, on in ((bar, "vazia", not share), (day, "hoje", today)):
                    if on:
                        widget.add_css_class(name)
                    else:
                        widget.remove_css_class(name)

        def _start_page(self):
            title = Gtk.Label(label=APP_NAME, margin_top=6)
            title.add_css_class("inicio-titulo")
            text = Gtk.Label(justify=Gtk.Justification.CENTER,
                             label="Veja e elimine os cookies que navegadores e aplicativos"
                                   "\nguardaram nesta conta.")
            text.add_css_class("inicio-texto")
            scan_card, _state = self._card(
                "edit-find-symbolic", "Verificar cookies",
                "Lista tudo o que está guardado, por aplicativo e por site.",
                "Nada é eliminado sem você confirmar", self.on_scan, primary=True)
            rules_card, self.rules_state = self._card(
                "alarm-symbolic", "Limpeza automática",
                "Programe: a cada sessão, num horário ou ao desligar, por site.",
                rules_summary(self.rules), self.on_rules)
            cards = Gtk.Box(spacing=14, homogeneous=True, margin_top=6)
            cards.append(scan_card)
            cards.append(rules_card)
            note = Gtk.Label(label="O valor dos cookies nunca é lido nem mostrado.",
                             margin_top=18)
            note.add_css_class("inicio-nota")
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8,
                             valign=Gtk.Align.CENTER, margin_top=24, margin_bottom=24,
                             margin_start=24, margin_end=24)
            for widget in (title, text, self._monitor(), cards, note):
                column.append(widget)
            page = Gtk.Box()
            page.add_css_class("inicio")
            page.append(Adw.Clamp(maximum_size=660, child=column, hexpand=True))
            return page

        # ---- configurações
        def _settings_page(self):
            startup = Adw.PreferencesGroup(title="Inicialização")
            self.setting_rows = {}
            for key, (title, text) in SETTING_TEXTS.items():
                row = Adw.SwitchRow(title=title, subtitle=text, active=self.settings[key])
                row.connect("notify::active", self._on_setting, key)
                startup.add(row)
                self.setting_rows[key] = row
            self.setting_rows["iniciar_minimizado"].set_sensitive(
                self.settings["iniciar_com_sistema"])
            about = Adw.PreferencesGroup(title="Sobre")
            about.add(Adw.ActionRow(title=APP_NAME, subtitle=f"Versão {APP_VERSION}"))
            page = Adw.PreferencesPage()
            page.add(startup)
            page.add(about)
            return page

        def _on_setting(self, row, _pspec, key):
            self.settings[key] = row.get_active()
            self.setting_rows["iniciar_minimizado"].set_sensitive(
                self.settings["iniciar_com_sistema"])
            warnings = save_settings(self.settings, home)
            if warnings:
                self._alert("Configuração não aplicada", "\n".join(warnings))

        # ---- limpeza automática
        def on_rules(self, *_):
            GLib.idle_add(self._show_rules)

        def _show_rules(self):
            when_keys = [key for key, _label in WHEN_LABELS]
            sites = Adw.EntryRow(title="Sites, separados por vírgula (vazio = todos)")
            when = Adw.ComboRow(title="Quando", model=Gtk.StringList.new(
                [label for _key, label in WHEN_LABELS]))
            hour = Adw.EntryRow(title="Horário (HH:MM)", text="08:00", visible=False)
            when.connect("notify::selected", lambda *_: hour.set_visible(
                when_keys[when.get_selected()] == WHEN_TIME))
            add = Gtk.Button(label="Adicionar regra", halign=Gtk.Align.END, margin_top=12)
            add.add_css_class("suggested-action")
            form = Adw.PreferencesGroup(
                title="Nova regra",
                description="Elimina sozinho os cookies dos sites escolhidos. "
                            "Aplicativos abertos na hora são pulados.")
            for widget in (sites, when, hour, add):
                form.add(widget)
            listing = Adw.PreferencesGroup(title="Regras")
            page = Adw.PreferencesPage()
            page.add(form)
            page.add(listing)
            toasts = Adw.ToastOverlay(child=page)
            rows = []

            def save():
                warnings = save_rules(self.rules, home)
                self.rules_state.set_text(rules_summary(self.rules))
                if warnings:
                    self._alert("Agendamento incompleto", "\n".join(warnings))

            def refresh():
                for row in rows:
                    listing.remove(row)
                rows.clear()
                runs = last_runs(home)
                for rule in self.rules:
                    detail = rule_when_text(rule)
                    if rule["id"] in runs:
                        detail += "\nÚltima limpeza em " + runs[rule["id"]]
                    row = Adw.ActionRow(title=GLib.markup_escape_text(rule_sites_text(rule)),
                                        subtitle=GLib.markup_escape_text(detail))
                    switch = Gtk.Switch(active=rule["ativa"], valign=Gtk.Align.CENTER,
                                        tooltip_text="Regra ativa")
                    switch.connect("notify::active", on_toggle, rule)
                    trash = Gtk.Button(icon_name="user-trash-symbolic",
                                       valign=Gtk.Align.CENTER, tooltip_text="Remover regra")
                    trash.add_css_class("flat")
                    trash.connect("clicked", on_remove, rule)
                    row.add_suffix(switch)
                    row.add_suffix(trash)
                    rows.append(row)
                if not self.rules:
                    rows.append(Adw.ActionRow(title="Nenhuma regra ainda",
                                              subtitle="Crie a primeira acima."))
                for row in rows:
                    listing.add(row)
                return False

            def on_toggle(switch, _pspec, rule):
                rule["ativa"] = switch.get_active()
                save()

            def on_remove(_button, rule):
                self.rules.remove(rule)
                save()
                GLib.idle_add(refresh)            # fora do "clicked", como nos outros botões

            def on_add(*_):
                rule, error = new_rule(sites.get_text(), when_keys[when.get_selected()],
                                       hour.get_text())
                if rule is None:
                    toasts.add_toast(Adw.Toast(title=error))
                    return
                self.rules.append(rule)
                sites.set_text("")
                save()
                GLib.idle_add(refresh)

            add.connect("clicked", on_add)
            refresh()
            layout = Adw.ToolbarView(content=toasts)
            layout.add_top_bar(Adw.HeaderBar())
            dialog = Adw.Dialog(title="Limpeza automática", content_width=560,
                                content_height=640, child=layout)
            dialog.present(self)
            return False

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
                self.tabs.set_visible_child_name("cookies")

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
            self.tabs.set_visible_child_name("cookies")   # a lista de que a pergunta fala
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
                outcome = delete_safely(targets, home)
                GLib.idle_add(self._delete_done, outcome, scan_safely(home))

            threading.Thread(target=work, daemon=True).start()
            return False

        def _delete_done(self, outcome, result):
            self._scan_done(result)
            self._refresh_stats()
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
        win = app.get_active_window()
        if win:
            win.present()
            return
        win = Window(app)
        win.present()
        if minimized:
            win.minimize()

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


def run_gui_tk(home: str | None, minimized: bool = False) -> int:
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
    hero = base.copy()
    hero.configure(size=int(base.cget("size") * 2.4), weight="bold")
    small = base.copy()
    small.configure(size=int(base.cget("size") * 0.9))
    small_bold = small.copy()
    small_bold.configure(weight="bold")
    stat = base.copy()
    stat.configure(size=int(base.cget("size") * 2.1), weight="bold")

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
    style.configure("Hero.TLabel", font=hero)
    style.configure("Muted.TLabel", foreground=T["fg_muted"], font=small)
    style.configure("Error.TLabel", foreground=T["danger"])

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
            self.rules = load_rules(home)
            self.rules_window = None
            self.settings = load_settings(home)
            sync_autostart(self.settings, home)    # o programa pode ter mudado de pasta
            self.tab = "inicio"
            self.cookie_page = "idle"              # página da aba Cookies
            self.bar_tips: list[str] = []
            self.results: queue.Queue = queue.Queue()
            self._build()
            self._poll()

        # ---- montagem
        def _build(self):
            header = ttk.Frame(root, style="Bar.TFrame", padding=(px(10), px(8)))
            header.pack(fill="x")
            self.tab_labels = {}
            for key, text in TABS:                 # abas, à esquerda
                label = tk.Label(header, text=text, font=bold, bd=0, padx=px(12), pady=px(6),
                                 cursor="hand2")
                label.pack(side="left", padx=(0, px(4)))
                label.bind("<Button-1>", lambda _event, k=key: self.select_tab(k))
                label.bind("<Enter>", lambda _event, k=key: self.paint_tab(k, True))
                label.bind("<Leave>", lambda _event, k=key: self.paint_tab(k, False))
                self.tab_labels[key] = label
            self.btn_delete = ttk.Button(header, text="Eliminar cookies", style="Danger.TButton",
                                         command=self.ask_delete)
            self.btn_delete.state(["disabled"])
            self.btn_delete.pack(side="right")
            ttk.Button(header, text="Limpeza automática",
                       command=self.show_rules).pack(side="right", padx=(0, px(8)))
            self.btn_scan = ttk.Button(header, text="Verificar cookies", style="Accent.TButton",
                                       command=self.start_scan)
            self.btn_scan.pack(side="right", padx=(0, px(8)))
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
            for name in ("start", "idle", "busy", "empty", "list", "config"):
                self.pages[name] = ttk.Frame(body)
                self.pages[name].grid(row=0, column=0, sticky="nsew")

            def centered(page):
                box = ttk.Frame(self.pages[page])
                box.place(relx=0.5, rely=0.45, anchor="center")
                return box

            box = centered("start")
            ttk.Label(box, text=APP_NAME, style="Hero.TLabel").pack()
            ttk.Label(box, style="Dim.TLabel", justify="center",
                      text="Veja e elimine os cookies que navegadores e aplicativos\n"
                           "guardaram nesta conta.").pack(pady=(px(6), px(22)))
            self.monitor(box).pack(fill="x", pady=(0, px(14)))
            cards = ttk.Frame(box)
            cards.pack()
            card, _state = self.card(
                cards, "Verificar cookies",
                "Lista tudo o que está guardado, por aplicativo e por site.",
                "Nada é eliminado sem você confirmar", self.start_scan, primary=True)
            card.grid(row=0, column=0, sticky="nsew", padx=(0, px(14)))
            card, self.rules_state = self.card(
                cards, "Limpeza automática",
                "Programe: a cada sessão, num horário ou ao desligar, por site.",
                rules_summary(self.rules), self.show_rules)
            card.grid(row=0, column=1, sticky="nsew")
            ttk.Label(box, text="O valor dos cookies nunca é lido nem mostrado.",
                      style="Muted.TLabel").pack(pady=(px(18), 0))
            box = centered("idle")
            ttk.Label(box, text=IDLE_TITLE, style="Title.TLabel").pack()
            ttk.Label(box, text=IDLE_TEXT, style="Dim.TLabel").pack(pady=(px(6), px(18)))
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
            self.build_settings()
            self.select_tab("inicio")

        # ---- abas
        def show(self, name):
            """Mostra uma das páginas da aba Cookies: idle, busy, empty ou list."""
            self.cookie_page = name
            self.select_tab("cookies")

        def select_tab(self, tab):
            self.tab = tab
            if tab == "inicio":
                self.refresh_stats()               # limpezas automáticas contam também
            self.pages[{"inicio": "start", "cookies": self.cookie_page,
                        "config": "config"}[tab]].tkraise()
            for key in self.tab_labels:
                self.paint_tab(key, False)

        def paint_tab(self, key, inside):
            chosen = key == self.tab
            self.tab_labels[key].configure(
                bg=T["raised"] if chosen else T["surface"] if inside else T["bar"],
                fg=T["fg"] if chosen or inside else T["fg_dim"])

        # ---- monitor da página inicial
        BAR, BAR_GAP, BAR_HEIGHT, BAR_SIDE = 18, 8, 46, 6

        def monitor(self, parent):
            """Painel com os cookies eliminados: última sessão, 7 dias e um gráfico por dia."""
            panel = tk.Frame(parent, bg=T["surface"], padx=px(18), pady=px(14),
                             highlightthickness=1, highlightbackground=T["border"])
            look = dict(bg=T["surface"], anchor="w")
            tk.Label(panel, text="Cookies eliminados", fg=T["fg"], font=bold, **look).grid(
                row=0, column=0, sticky="w", pady=(0, px(10)))
            # valor do dia sob o ponteiro, no gráfico
            self.bar_tip = tk.Label(panel, bg=T["surface"], fg=T["fg_dim"], font=small,
                                    anchor="e")
            self.bar_tip.grid(row=0, column=1, columnspan=2, sticky="e", pady=(0, px(10)))
            self.stat_labels = {}
            for column, (key, title) in enumerate((("session", "Última sessão"),
                                                   ("week", "Últimos 7 dias"))):
                cell = tk.Frame(panel, bg=T["surface"])
                cell.grid(row=1, column=column, sticky="sw", padx=(0, px(24)))
                panel.columnconfigure(column, weight=1)
                tk.Label(cell, text=title, fg=T["fg_muted"], font=small_bold, **look).pack(
                    fill="x")
                for name, color, font in ((key, T["fg"], stat),
                                          (key + "_note", T["fg_dim"], small)):
                    self.stat_labels[name] = tk.Label(cell, fg=color, font=font, **look)
                    self.stat_labels[name].pack(fill="x")
            self.chart = tk.Canvas(panel, bg=T["surface"], highlightthickness=0, bd=0,
                                   width=px(7 * self.BAR + 6 * self.BAR_GAP
                                            + 2 * self.BAR_SIDE),
                                   height=px(self.BAR_HEIGHT + 20))
            self.chart.grid(row=1, column=2, sticky="se")
            self.chart.bind("<Motion>", self.on_chart)
            self.chart.bind("<Leave>", lambda _event: self.bar_tip.configure(text=""))
            return panel

        def on_chart(self, event):
            step = px(self.BAR + self.BAR_GAP)
            index = int((event.x - px(self.BAR_SIDE) + px(self.BAR_GAP) / 2) // step)
            if 0 <= index < len(self.bar_tips):
                self.bar_tip.configure(text=self.bar_tips[index])

        def refresh_stats(self):
            view = stats_view(load_stats(home))
            for key in ("session", "session_note", "week", "week_note"):
                self.stat_labels[key].configure(text=view[key])
            self.bar_tips = [tip for _label, _share, tip, _today in view["bars"]]
            width, floor = px(self.BAR), px(self.BAR_HEIGHT)
            self.chart.delete("all")
            for index, (label, share, _tip, today) in enumerate(view["bars"]):
                left = px(self.BAR_SIDE) + index * px(self.BAR + self.BAR_GAP)
                tall = max(px(2), round(floor * share))
                self.chart.create_rectangle(left, floor - tall, left + width, floor, width=0,
                                            fill=T["accent"] if share else T["border"])
                self.chart.create_text(left + width / 2, floor + px(11), text=label,
                                       font=small_bold if today else small,
                                       fill=T["fg"] if today else T["fg_muted"])

        # ---- configurações
        def build_settings(self):
            box = ttk.Frame(self.pages["config"], padding=(px(24), px(26)))
            box.place(relx=0.5, y=0, anchor="n", width=px(640))
            ttk.Label(box, text="Configurações", style="Title.TLabel").pack(anchor="w")
            ttk.Label(box, text="Inicialização", style="Dim.TLabel", font=bold).pack(
                anchor="w", pady=(px(18), px(8)))
            card = tk.Frame(box, bg=T["surface"], padx=px(18), pady=px(4),
                            highlightthickness=1, highlightbackground=T["border"])
            card.pack(fill="x")
            self.setting_switches = {}
            for index, (key, (title, text)) in enumerate(SETTING_TEXTS.items()):
                if index:
                    line(card).pack(fill="x")
                row = tk.Frame(card, bg=T["surface"])
                row.pack(fill="x", pady=px(12))
                switch = tk.Canvas(row, bg=T["surface"], highlightthickness=0, bd=0,
                                   width=px(self.SWITCH[0]), height=px(self.SWITCH[1]))
                switch.pack(side="right", padx=(px(16), 0))
                switch.bind("<Button-1>", lambda _event, k=key: self.on_setting(k))
                look = dict(bg=T["surface"], anchor="w", justify="left")
                tk.Label(row, text=title, fg=T["fg"], font=bold, **look).pack(fill="x")
                tk.Label(row, text=text, fg=T["fg_dim"], font=base, wraplength=px(510),
                         **look).pack(fill="x", pady=(px(2), 0))
                self.setting_switches[key] = switch
            self.settings_message = ttk.Label(box, style="Error.TLabel", justify="left",
                                              wraplength=px(590))
            self.settings_message.pack(anchor="w", pady=(px(10), 0))
            ttk.Label(box, text=f"{APP_NAME} · versão {APP_VERSION}",
                      style="Muted.TLabel").pack(anchor="w", pady=(px(8), 0))
            self.paint_switches()

        SWITCH = (42, 24)                          # largura e altura do interruptor

        def setting_usable(self, key):
            """Abrir minimizado só vale com o início com o sistema ligado."""
            return key != "iniciar_minimizado" or self.settings["iniciar_com_sistema"]

        def paint_switches(self):
            width, height = (px(n) for n in self.SWITCH)
            for key, switch in self.setting_switches.items():
                on, usable = self.settings[key], self.setting_usable(key)
                track = T["border"] if not usable else T["accent_bg"] if on else T["raised_hover"]
                knob = T["fg_muted"] if not usable else T["on_accent"]
                switch.configure(cursor="hand2" if usable else "")
                switch.delete("all")
                for left in (0, width - height):   # trilho: duas pontas redondas e o meio
                    switch.create_oval(left, 0, left + height - 1, height - 1, width=0,
                                       fill=track)
                switch.create_rectangle(height / 2, 0, width - height / 2, height, width=0,
                                        fill=track)
                left, gap = (width - height if on else 0), px(3)
                switch.create_oval(left + gap, gap, left + height - 1 - gap, height - 1 - gap,
                                   width=0, fill=knob)

        def on_setting(self, key):
            if not self.setting_usable(key):
                return
            self.settings[key] = not self.settings[key]
            self.paint_switches()
            self.settings_message.configure(
                text="\n".join(save_settings(self.settings, home)))

        def card(self, parent, title, text, state, command, primary=False):
            """Cartão clicável da página inicial. Devolve (cartão, rótulo da linha de estado)."""
            edge = T["accent_bg"] if primary else T["border"]
            frame = tk.Frame(parent, bg=T["surface"], padx=px(18), pady=px(16), cursor="hand2",
                             highlightthickness=1, highlightbackground=edge)
            look = dict(bg=T["surface"], anchor="w", justify="left", cursor="hand2")
            parts = [tk.Label(frame, text=title, fg=T["fg"], font=bold, **look),
                     tk.Label(frame, text=text, fg=T["fg_dim"], font=base, wraplength=px(250),
                              **look),
                     tk.Label(frame, text=state, fg=T["accent"], font=small_bold, **look)]
            for part, gap in zip(parts, (0, px(6), px(10))):
                part.pack(fill="x", pady=(gap, 0))

            def paint(inside):
                frame.configure(bg=T["raised"] if inside else T["surface"],
                                highlightbackground=T["accent"] if inside else edge)
                for part in parts:
                    part.configure(bg=T["raised"] if inside else T["surface"])

            for widget in [frame] + parts:
                widget.bind("<Enter>", lambda _event: paint(True))
                widget.bind("<Leave>", lambda _event: paint(False))
                widget.bind("<Button-1>", lambda _event: command())
            return frame, parts[2]

        # ---- limpeza automática
        def show_rules(self):
            if self.rules_window and self.rules_window.winfo_exists():
                self.rules_window.lift()
                return
            when_keys = [key for key, _label in WHEN_LABELS]
            top = self.rules_window = tk.Toplevel(root, bg=T["bg"])
            top.withdraw()
            top.title("Limpeza automática")
            top.transient(root)
            box = ttk.Frame(top, padding=(px(22), px(18)))
            box.pack(fill="both", expand=True)
            ttk.Label(box, text="Limpeza automática", style="Title.TLabel").pack(anchor="w")
            ttk.Label(box, style="Dim.TLabel",
                      text="Elimina sozinho os cookies dos sites escolhidos. "
                           "Aplicativos abertos na hora são pulados."
                      ).pack(anchor="w", pady=(px(4), px(16)))

            form = ttk.Frame(box)
            form.pack(fill="x")
            form.columnconfigure(3, weight=1)
            ttk.Label(form, text="Sites").grid(row=0, column=0, sticky="w", padx=(0, px(12)))
            sites = ttk.Entry(form)
            sites.grid(row=0, column=1, columnspan=3, sticky="ew")
            ttk.Label(form, text="Separados por vírgula. Vazio = todos os sites.",
                      style="Muted.TLabel").grid(row=1, column=1, columnspan=3, sticky="w",
                                                 pady=(px(3), px(10)))
            ttk.Label(form, text="Quando").grid(row=2, column=0, sticky="w", padx=(0, px(12)))
            when = ttk.Combobox(form, state="readonly", width=46,
                                values=[label for _key, label in WHEN_LABELS])
            when.current(0)
            when.grid(row=2, column=1, sticky="w")
            hour_label = ttk.Label(form, text="às")
            hour = ttk.Entry(form, width=7)
            hour.insert(0, "08:00")
            hour_label.grid(row=2, column=2, padx=px(8))
            hour.grid(row=2, column=3, sticky="w")

            def on_when(_event=None):
                when.selection_clear()
                for widget in (hour_label, hour):       # o horário só aparece quando vale
                    if when_keys[when.current()] == WHEN_TIME:
                        widget.grid()
                    else:
                        widget.grid_remove()

            when.bind("<<ComboboxSelected>>", on_when)
            on_when()
            message = ttk.Label(form, style="Error.TLabel", wraplength=px(420), justify="left")
            message.grid(row=3, column=0, columnspan=3, sticky="w", pady=(px(12), 0))
            add = ttk.Button(form, text="Adicionar regra", style="Accent.TButton")
            add.grid(row=3, column=3, sticky="e", pady=(px(12), 0))

            columns = (("sites", "Sites", 230), ("quando", "Quando", 230),
                       ("estado", "Situação", 100), ("ultima", "Última limpeza", 280))
            tree = ttk.Treeview(box, columns=[col for col, _t, _w in columns],
                                show="headings", selectmode="browse", height=7)
            for col, title, width in columns:
                tree.heading(col, text=title, anchor="w")
                tree.column(col, width=px(width), anchor="w", stretch=col == "ultima")
            tree.pack(fill="both", expand=True, pady=(px(16), px(12)))
            actions = ttk.Frame(box)
            actions.pack(fill="x")
            toggle = ttk.Button(actions, text="Ativar ou desativar")
            toggle.pack(side="left")
            remove = ttk.Button(actions, text="Remover", style="Danger.TButton")
            remove.pack(side="left", padx=(px(8), 0))
            ttk.Button(actions, text="Fechar", command=top.destroy).pack(side="right")

            def refresh(select=None):
                tree.delete(*tree.get_children())
                runs = last_runs(home)
                for rule in self.rules:
                    tree.insert("", "end", iid=rule["id"], values=(
                        rule_sites_text(rule), rule_when_text(rule),
                        "Ativa" if rule["ativa"] else "Desativada",
                        runs.get(rule["id"], "ainda não rodou")))
                if select and tree.exists(select):
                    tree.selection_set(select)

            def save():
                warnings = save_rules(self.rules, home)
                self.rules_state.configure(text=rules_summary(self.rules))
                message.configure(text="\n".join(warnings))

            def chosen():
                picked = tree.selection()
                if not picked:
                    message.configure(text="Escolha uma regra na lista.")
                    return None
                return next(rule for rule in self.rules if rule["id"] == picked[0])

            def on_add(_event=None):
                rule, error = new_rule(sites.get(), when_keys[when.current()], hour.get())
                if rule is None:
                    message.configure(text=error)
                    return
                self.rules.append(rule)
                sites.delete(0, "end")
                save()
                refresh(rule["id"])

            def on_toggle():
                rule = chosen()
                if rule:
                    rule["ativa"] = not rule["ativa"]
                    save()
                    refresh(rule["id"])

            def on_remove():
                rule = chosen()
                if rule:
                    self.rules.remove(rule)
                    save()
                    refresh()

            add.configure(command=on_add)
            toggle.configure(command=on_toggle)
            remove.configure(command=on_remove)
            sites.bind("<Return>", on_add)
            top.bind("<Escape>", lambda _event: top.destroy())
            refresh()
            top.update_idletasks()
            x = root.winfo_rootx() + (root.winfo_width() - top.winfo_reqwidth()) // 2
            y = root.winfo_rooty() + (root.winfo_height() - top.winfo_reqheight()) // 3
            top.geometry(f"+{max(x, 0)}+{max(y, 0)}")
            if WINDOWS:
                _win_dark_titlebar(top)
            top.deiconify()
            sites.focus_set()

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
            self.select_tab("cookies")             # a lista de que a pergunta fala
            heading, body = delete_question(targets, bool(picked), len(self.cookies))
            self.dialog(heading, body, [("cancel", "Cancelar", "TButton"),
                                        ("delete", "Eliminar", "Danger.TButton")],
                        lambda response: response == "delete" and self.start_delete(targets))

        def start_delete(self, targets):
            if self.busy:
                return
            self.set_busy(True, "Eliminando…")
            self.work(lambda: (delete_safely(targets, home), scan_safely(home)),
                      self.delete_done)

        def delete_done(self, outcome, result):
            self.note = deleted_text(outcome["deleted"]) + "."
            self.scan_done(result)
            notes = delete_notes(outcome)
            if notes:
                self.dialog("Nem tudo foi eliminado", notes, [("ok", "Entendi", "TButton")])

    App()
    root.geometry(f"{min(px(1200), root.winfo_screenwidth() - px(80))}"
                  f"x{min(px(680), root.winfo_screenheight() - px(120))}")
    root.minsize(px(900), px(540))
    if WINDOWS:
        icon = _resource("icone.ico")
        if icon:
            try:
                root.iconbitmap(default=icon)
            except tk.TclError:
                pass
        _win_dark_titlebar(root)
    if minimized:
        root.iconify()
    else:
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
    parser.add_argument("--minimizado", action="store_true",
                        help="abre a janela minimizada (usado ao iniciar com o sistema)")
    parser.add_argument("--automatico", metavar="GATILHO", default=None,
                        help="executa as regras de limpeza automática de um gatilho "
                             "(inicio, desligar ou horario:HH:MM); usado pelo agendador")
    args = parser.parse_args()
    if args.resumo:
        print_summary(args.home)
        return 0
    if args.automatico:
        run_rules(args.automatico, args.home)
        return 0
    # Linux: janela GTK; sem GTK 4 / libadwaita recentes (ou com --tk), a janela Tk
    if not WINDOWS and not args.tk and gtk_ready():
        return run_gui(args.home, args.minimizado)
    return run_gui_tk(args.home, args.minimizado)


if __name__ == "__main__":
    sys.exit(main())
