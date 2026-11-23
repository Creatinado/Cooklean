#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Limpa Cookies: lista e elimina os cookies e as senhas salvas que navegadores e
aplicativos desta conta guardam em disco (Firefox, Chrome, Chromium, Brave, Edge, apps
Electron...). Funciona no Linux (janela GTK 4) e no Windows 10 e 11 (janela Tk).

O programa nunca lê nem mostra o VALOR dos cookies nem as senhas: só aplicativo, perfil,
site, nome do cookie ou usuário, datas e onde está guardado.

Uso:
    limpa_cookies.py              abre a janela
    limpa_cookies.py --resumo     imprime só a contagem por aplicativo (sem sites)
    limpa_cookies.py --home DIR   usa DIR no lugar da pasta pessoal (para testes)
    limpa_cookies.py --tk         no Linux, abre a janela Tk (a mesma do Windows)
    limpa_cookies.py --minimizado abre a janela minimizada (usado ao iniciar com o sistema)

A janela também programa limpezas automáticas de cookies, de senhas ou dos dois (ao
iniciar a sessão, num horário, ao desligar), de todos os sites ou só de alguns; ver
"limpeza automática" mais abaixo. Guarda quantos cookies foram eliminados (ver
"estatísticas") e pode abrir sozinha quando o sistema inicia (ver "configurações").
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
import pathlib
import re
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from urllib.parse import urlsplit

APP_ID = "local.LimpaCookies"
APP_NAME = "Limpa Cookies"
APP_VERSION = "1.5.0"
WINDOWS = sys.platform == "win32"

COOKIES, PASSWORDS = "cookies", "senhas"       # o que o programa limpa

KIND_SESSION = "Sessão"
KIND_PERSISTENT = "Permanente"
STORE_DB = "Banco de cookies"
STORE_SESSION = "Restauração de sessão"

# senhas dos navegadores tipo Chromium: as deste computador e as da conta (Google, Microsoft)
LOGIN_FILES = ("Login Data", "Login Data For Account")
# senhas do Firefox e parentes; a cópia de segurança também guarda tudo
FIREFOX_LOGINS = ("logins.json", "logins-backup.json")

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


@dataclass(frozen=True)
class Password:
    """Uma senha salva. A senha em si nunca é lida: só de onde ela é."""
    app: str
    profile: str
    host: str       # site
    user: str       # usuário; vazio no Firefox, que guarda o usuário criptografado
    created: str    # data dd/mm/aaaa
    created_sort: str
    last_used: str  # data dd/mm/aaaa ou "nunca"
    last_used_sort: str
    source: str     # arquivo onde está
    fmt: str        # chromium_logins | firefox_logins
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


def _date_or(epoch: float, missing: str) -> tuple[str, str]:
    """Como _date, mas com o texto missing quando não há data (zero ou negativa)."""
    return _date(epoch) if epoch > 0 else (missing, "0000-00-00")


def _chromium_epoch(value) -> float:
    """Data do Chromium (microssegundos desde 1601) em segundos desde 1970; 0 se não há."""
    return value / 1e6 - 11644473600 if isinstance(value, (int, float)) and value > 0 else 0


def _site_of(url: str) -> str:
    """'https://painel.exemplo.com/login' -> 'painel.exemplo.com'. Endereços que não são
    de sites (android://..., chrome://...) ficam como estão."""
    try:
        parts = urlsplit(url)
        if parts.scheme in ("http", "https", "ftp") and parts.hostname:
            return parts.hostname
    except ValueError:
        pass
    return url


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
    if fmt in ("firefox_session", "firefox_logins"):
        prof = os.path.dirname(source)
        if os.path.basename(prof) == "sessionstore-backups":
            prof = os.path.dirname(prof)
        names = ["cookies.sqlite", "places.sqlite"]
        if fmt == "firefox_logins":
            # o Firefox lê logins.json e fecha o arquivo; a trava do perfil fica aberta
            # enquanto ele roda (.parentlock no Linux, parent.lock no Windows)
            names += [".parentlock", "parent.lock"]
        guards = [os.path.join(prof, name) for name in names]
    else:
        guards = [source]
    return any(_busy(g, opened) for g in guards)


def _overwrite(path: str, blob: bytes) -> None:
    """Troca o conteúdo do arquivo por blob. Antes zera o conteúdo antigo, para que ele
    não fique esquecido no disco."""
    st = os.stat(path)
    tmp = path + ".limpa-cookies.tmp"
    with open(tmp, "wb") as fh:
        fh.write(blob)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, st.st_mode & 0o777)
    with open(path, "r+b") as fh:
        fh.write(b"\0" * st.st_size)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


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
    _overwrite(path, blob)


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
                    or os.path.isdir(os.path.join(ent.path, "sessionstore-backups"))
                    or any(os.path.exists(os.path.join(ent.path, name))
                           for name in FIREFOX_LOGINS)):
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


def _chromium_files(bases, windows: bool, names=("Cookies",)):
    """(aplicativo, perfil, caminho) de cada arquivo chamado names abaixo das bases."""
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
            if rel == ".":
                continue
            for name in names:
                if name in files:
                    app, profile = _chromium_label(rel.split(os.sep), suffix)
                    yield app, profile, os.path.join(root, name)


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


# --------------------------------------------------------------------------- senhas salvas
#
# Só se lê de onde é cada senha: site, usuário (no Chromium) e datas. A senha, que o
# navegador guarda criptografada, nunca é lida nem decifrada.

def _firefox_login_key(login: dict) -> tuple:
    return (str(login.get("guid") or ""), str(login.get("id") or ""),
            str(login.get("hostname") or ""))


def _ms_epoch(value) -> float:
    """Milissegundos desde 1970 (como o Firefox guarda) em segundos; 0 se não há."""
    return value / 1000 if isinstance(value, (int, float)) and value > 0 else 0


def _scan_firefox_logins(app, profile, path, opened, out, warnings, seen):
    used = _in_use(path, "firefox_logins", opened)
    try:
        with open(path, encoding="utf-8") as fh:
            logins = json.load(fh).get("logins")
    except (OSError, ValueError, AttributeError) as exc:
        warnings.append(f"{app} ({profile}): não consegui ler as senhas salvas ({exc})")
        return
    for login in logins if isinstance(logins, list) else []:
        if not isinstance(login, dict):
            continue
        key = _firefox_login_key(login)
        if key in seen:                     # a mesma senha no logins.json e na cópia
            continue
        seen.add(key)
        shown, sort = _date_or(_ms_epoch(login.get("timeCreated")), "sem data")
        last, last_sort = _date_or(_ms_epoch(login.get("timeLastUsed")), "nunca")
        out.append(Password(app, profile, _site_of(key[2]), "", shown, sort, last, last_sort,
                            path, "firefox_logins", key, used))


def _scan_chromium_logins(app, profile, path, opened, out, warnings):
    if os.path.basename(path) == "Login Data For Account":
        profile += " (conta)"
    used = _in_use(path, "chromium_logins", opened)
    try:
        with open(path, "rb") as fh:
            if fh.read(15) != b"SQLite format 3":
                return
    except OSError:
        if used:        # no Windows, Chrome e Edge abertos travam o arquivo até para leitura
            warnings.append(f"{app} ({profile}): está aberto e não deixa ler as senhas salvas. "
                            "Feche o aplicativo e verifique de novo.")
        return
    try:
        conn = _ro(path)
        try:
            cols = {r[1] for r in conn.execute("pragma table_info(logins)")}
            if not {"origin_url", "username_value"} <= cols:
                return

            def col(name, default="0"):
                return name if name in cols else default

            # blacklisted_by_user marca o "Nunca salvar neste site": não tem senha e fica
            rows = conn.execute(
                f"select rowid, origin_url, {col('signon_realm', 'origin_url')}, "
                f"username_value, {col('date_created')}, {col('date_last_used')} "
                f"from logins where {col('blacklisted_by_user')} = 0").fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        warnings.append(f"{app} ({profile}): não consegui ler as senhas salvas ({exc})")
        return
    for rid, origin, realm, user, created, last in rows:
        shown, sort = _date_or(_chromium_epoch(created), "sem data")
        last_shown, last_sort = _date_or(_chromium_epoch(last), "nunca")
        name = user.decode("utf-8", "replace") if isinstance(user, bytes) else str(user or "")
        out.append(Password(app, profile, _site_of(str(origin or realm or "")), name, shown,
                            sort, last_shown, last_sort, path, "chromium_logins",
                            (rid, origin, user), used))


def scan_passwords(home: str | None = None,
                   windows: bool = WINDOWS) -> tuple[list[Password], list[str]]:
    """Lê de onde são as senhas salvas. Devolve (senhas, avisos)."""
    firefox_roots, chromium_bases = _layout(home, windows)
    opened = open_files()
    out: list[Password] = []
    warnings: list[str] = []
    for app, profile, pdir in _firefox_profiles(firefox_roots):
        seen: set = set()
        # sem logins.json, o Firefox restaura a cópia de segurança: as duas contam
        for name in FIREFOX_LOGINS:
            path = os.path.join(pdir, name)
            if os.path.isfile(path):
                _scan_firefox_logins(app, profile, path, opened, out, warnings, seen)
    for app, profile, path in _chromium_files(chromium_bases, windows, LOGIN_FILES):
        _scan_chromium_logins(app, profile, path, opened, out, warnings)
    return out, warnings


def scan_kind(kind: str, home: str | None = None) -> tuple[list, list[str]]:
    """Cookies ou senhas salvas, conforme kind."""
    return scan_passwords(home) if kind == PASSWORDS else scan(home)


# --------------------------------------------------------------------------- eliminação

DELETE_SQL = {
    "firefox_db": "delete from moz_cookies where id=? and host is ? and name is ?",
    "chromium_db": "delete from cookies where rowid=? and host_key is ? and name is ?",
    "chromium_logins":
        "delete from logins where rowid=? and origin_url is ? and username_value is ?",
}


def _delete_sqlite(path: str, fmt: str, keys: list[tuple]) -> int:
    conn = sqlite3.connect(path, timeout=3)
    try:
        # zera no arquivo o que sai, em vez de só marcar o espaço como livre
        conn.execute("pragma secure_delete=on").fetchall()
        children = []
        if fmt == "chromium_logins":
            # tabelas presas a uma senha pelo id dela: avisos de senha vazada e anotações
            for table in ("insecure_credentials", "password_notes"):
                if "parent_id" in {r[1] for r in conn.execute(f"pragma table_info({table})")}:
                    children.append(table)
        removed = 0
        for key in keys:
            gone = conn.execute(DELETE_SQL[fmt], key).rowcount
            if gone:
                for table in children:
                    conn.execute(f"delete from {table} where parent_id=?", (key[0],))
            removed += gone
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


def _drop_firefox_logins(path: str, targets: set) -> int:
    """Tira de um logins.json (ou da cópia) as senhas de targets. Devolve quantas saíram."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    logins = data.get("logins") if isinstance(data, dict) else None
    if not isinstance(logins, list):
        return 0
    keep = [login for login in logins
            if not (isinstance(login, dict) and _firefox_login_key(login) in targets)]
    removed = len(logins) - len(keep)
    if removed:
        data["logins"] = keep
        alerts = data.get("dismissedBreachAlertsByLoginGUID")
        if isinstance(alerts, dict):                  # avisos de vazamento dessas senhas
            for guid, _id, _host in targets:
                alerts.pop(guid, None)
        _overwrite(path, json.dumps(data, ensure_ascii=False,
                                    separators=(",", ":")).encode("utf-8"))
    return removed


def _delete_firefox_logins(path: str, keys: list[tuple]) -> int:
    targets = set(keys)
    removed = _drop_firefox_logins(path, targets)
    for name in FIREFOX_LOGINS:          # a outra cópia (logins.json ou o backup) também
        other = os.path.join(os.path.dirname(path), name)
        if os.path.basename(path) != name and os.path.isfile(other):
            _drop_firefox_logins(other, targets)
    return removed


def delete(items: list) -> dict:
    """Elimina os cookies ou as senhas dados. Pula os arquivos de aplicativos abertos.
    Devolve {"deleted": int, "skipped": Counter(app -> n), "errors": [str]}."""
    opened = open_files()
    groups: dict[tuple[str, str], list] = defaultdict(list)
    for item in items:
        groups[(item.source, item.fmt)].append(item)
    result = {"deleted": 0, "skipped": Counter(), "errors": []}
    for (source, fmt), group in groups.items():
        app = group[0].app
        if _in_use(source, fmt, opened):
            result["skipped"][app] += len(group)
            continue
        keys = [item.key for item in group]
        try:
            if fmt == "firefox_session":
                result["deleted"] += _delete_session(source, keys)
            elif fmt == "firefox_logins":
                result["deleted"] += _delete_firefox_logins(source, keys)
            else:
                result["deleted"] += _delete_sqlite(source, fmt, keys)
        except (sqlite3.Error, OSError, ValueError, IndexError) as exc:
            result["errors"].append(f"{app} ({group[0].profile}): {exc}")
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
    passwords, more = scan_passwords(home)
    places = Counter((p.app, p.profile) for p in passwords)
    print(f"\n{fmt_num(len(passwords))} senha(s) salva(s) em "
          f"{len({p.app for p in passwords})} aplicativo(s)")
    for (app, profile), n in sorted(places.items()):
        print(f"   {app}, perfil {profile}: {fmt_num(n)}")
    for w in warnings + more:
        print("aviso:", w)


# --------------------------------------------------------------------------- limpeza automática
#
# Uma regra diz QUAIS sites limpar (lista vazia = todos), O QUE limpar (cookies, senhas
# salvas ou os dois) e QUANDO. As regras ficam em regras.json; quem dispara é o próprio
# sistema (autostart e systemd no Linux, registro e Agendador de Tarefas no Windows),
# chamando este programa com --automatico GATILHO.

WHEN_LOGIN, WHEN_TIME, WHEN_SHUTDOWN = "inicio", "horario", "desligar"
WHEN_LABELS = [
    (WHEN_LOGIN, "Ao iniciar a sessão"),
    (WHEN_TIME, "Todos os dias, num horário"),
    # o Windows não deixa um programa comum rodar durante o desligamento
    (WHEN_SHUTDOWN, "Ao desligar o computador (limpa no início seguinte)" if WINDOWS
     else "Ao desligar o computador"),
]
# o que limpar; regras antigas, sem essa escolha, limpam só cookies
WHAT_LABELS = [
    ((COOKIES, PASSWORDS), "Cookies e senhas"),
    ((COOKIES,), "Só cookies"),
    ((PASSWORDS,), "Só senhas"),
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


def new_rule(sites_text: str, when: str, time_text: str,
             what: tuple = (COOKIES,)) -> tuple[dict | None, str]:
    """(regra, "") ou (None, o que está errado)."""
    hour = ""
    if when == WHEN_TIME:
        hour = valid_time(time_text) or ""
        if not hour:
            return None, "Escreva o horário como HH:MM, por exemplo 08:30."
    return {"id": os.urandom(4).hex(), "sites": parse_sites(sites_text), "quando": when,
            "hora": hour, "limpar": list(what), "ativa": True}, ""


def rule_sites_text(rule: dict) -> str:
    return ", ".join(rule["sites"]) or "Todos os sites"


def rule_what_text(rule: dict) -> str:
    return dict(WHAT_LABELS)[tuple(rule["limpar"])]


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
        what = raw.get("limpar") if isinstance(raw.get("limpar"), list) else []
        rules.append({"id": str(raw.get("id") or os.urandom(4).hex()),
                      "sites": parse_sites(" ".join(map(str, raw.get("sites") or []))),
                      "quando": raw["quando"], "hora": hour,
                      "limpar": [kind for kind in (COOKIES, PASSWORDS) if kind in what]
                      or [COOKIES],
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
    Devolve quantos cookies e senhas eliminou, somados."""
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
    deleted = {COOKIES: Counter(), PASSWORDS: Counter()}
    skipped: dict[str, int] = {}
    for attempt in range(tries):
        for rule in rules:
            skipped[rule["id"]] = 0
            for kind in rule["limpar"]:
                # relê a cada regra: eliminar muda os arquivos
                found, _warnings = scan_kind(kind, home)
                outcome = delete([item for item in found
                                  if site_matches(item.host, rule["sites"])])
                deleted[kind][rule["id"]] += outcome["deleted"]
                skipped[rule["id"]] += sum(outcome["skipped"].values())
        if not any(skipped.values()) or attempt + 1 == tries:
            break
        time.sleep(1.5)
    runs = last_runs(home)
    stamp = time.strftime("%d/%m/%Y %H:%M")
    for rule in rules:
        text = f"{stamp}: " + ", ".join(deleted_text(deleted[kind][rule["id"]], kind)
                                        for kind in rule["limpar"])
        if skipped[rule["id"]]:
            text += f"; {fmt_num(skipped[rule['id']])} pulados (aplicativo aberto)"
        runs[rule["id"]] = text
    known = {rule["id"] for rule in load_rules(home)}
    _write_text(os.path.join(config_dir(home), "execucoes.json"),
                json.dumps({k: v for k, v in runs.items() if k in known},
                           ensure_ascii=False, indent=2) + "\n")
    record_cleanup(sum(deleted[COOKIES].values()), home)
    return sum(sum(counts.values()) for counts in deleted.values())


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
# config.json guarda as escolhas da aba Ajustes. "Iniciar com o sistema" abre a
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
PASSWORD_COLUMNS = [
    ("Aplicativo", "app", "app", 170),
    ("Perfil", "profile", "profile", 150),
    ("Site", "host", "host", 0),
    ("Usuário", "user", "user", 220),
    ("Salva em", "created", "created_sort", 110),
    ("Último uso", "last_used", "last_used_sort", 110),
]
LIST_COLUMNS = {COOKIES: COLUMNS, PASSWORDS: PASSWORD_COLUMNS}
ALL_APPS = "Todos os aplicativos"

# os textos que mudam entre a aba Cookies e a aba Senhas
KIND_TEXTS = {
    COOKIES: {
        "one": "cookie", "many": "cookies", "done": "eliminado",
        "scan": "Verificar cookies", "delete": "Eliminar cookies",
        "idle": "Clique em Verificar cookies para listar o que está guardado nesta conta.",
        "hint": "Filtrar por site, cookie ou tipo",
        "busy": "Verificando os cookies guardados…",
        "empty": "Nenhum cookie guardado",
        "empty_note": "Nenhum cookie guardado em disco foi encontrado.",
        "picked": "selecionado(s): Eliminar remove só esses.",
        "all": "Todos os cookies encontrados.",
        "effect": "Você será desconectado dos sites correspondentes nesses aplicativos.",
    },
    PASSWORDS: {
        "one": "senha", "many": "senhas", "done": "eliminada",
        "scan": "Verificar senhas", "delete": "Eliminar senhas",
        "idle": "Clique em Verificar senhas para listar os sites com senha salva nesta conta.",
        "hint": "Filtrar por site ou usuário",
        "busy": "Verificando as senhas salvas…",
        "empty": "Nenhuma senha salva",
        "empty_note": "Nenhuma senha salva foi encontrada.",
        "picked": "selecionada(s): Eliminar remove só essas.",
        "all": "Todas as senhas encontradas.",
        "effect": "Nesses sites, será preciso digitar a senha de novo. Se o navegador "
                  "sincroniza senhas com uma conta (Google, Microsoft, Firefox), apague-as "
                  "lá também, senão elas voltam.",
    },
}

# Cores da janela: a paleta do perfil do GitHub (github.com/Creatinado), verde-água
# #00d4aa sobre pretos esverdeados, com o verde médio #1f9a7c e o contorno #0b3b2e. Usadas
# pela janela GTK e pela janela Tk; os tons intermediários (linhas, campos, botões) saem
# destas, como o libadwaita faz.
THEME = {
    "bg": "#03100b",            # fundo da janela, do cabeçalho e da lista
    "bar": "#010504",           # rodapé
    "surface": "#081b15",       # cartões, grupos de ajustes e diálogos
    "raised": "#0d2820",        # cartão sob o ponteiro
    "border": "#0b3b2e",        # contorno dos cartões e dias sem limpeza no gráfico
    "fg": "#ffffff",            # texto
    "fg_dim": "#b4d8cd",        # texto secundário
    "fg_muted": "#1f9a7c",      # rótulos, dicas e dias da semana
    "accent": "#00d4aa",        # verde-água: destaques, foco e barras do gráfico
    "accent_bg": "#00d4aa",     # botão principal e interruptor ligado
    "on_accent": "#010504",     # texto sobre o verde-água
    "danger": "#fe8181",        # texto de ação destrutiva
    "danger_bg": "#b53333",     # botão destrutivo cheio
}


def app_label(item) -> str:
    return item.app + (" · aberto" if item.in_use else "")


def search_text(item) -> str:
    """Texto em minúsculas onde o filtro procura (de um cookie ou de uma senha)."""
    if isinstance(item, Password):
        return " ".join((item.app, item.profile, item.host, item.user)).lower()
    return " ".join((item.app, item.profile, item.host, item.name,
                     item.kind, item.store)).lower()


def row_values(item, kind: str) -> list[str]:
    """O que cada coluna da lista mostra."""
    return [app_label(item) if prop == "app" else getattr(item, prop) or "—"
            for _title, prop, _sort, _width in LIST_COLUMNS[kind]]


def scan_safely(home: str | None, kind: str = COOKIES) -> tuple[list, list[str]]:
    try:
        return scan_kind(kind, home)
    except Exception as exc:                  # nunca deixar a janela presa
        return [], [f"Falha na verificação: {exc}"]


def delete_safely(items: list, home: str | None, kind: str = COOKIES) -> dict:
    """Elimina e, se forem cookies, anota nas estatísticas."""
    try:
        outcome = delete(items)
    except Exception as exc:
        return {"deleted": 0, "skipped": Counter(), "errors": [str(exc)]}
    if kind == COOKIES:
        record_cleanup(outcome["deleted"], home)
    return outcome


TABS = [("inicio", "Início"), (COOKIES, "Cookies"), (PASSWORDS, "Senhas"),
        ("config", "Ajustes")]
IDLE_TITLE = "Nenhuma verificação ainda"

# página inicial: o texto, os cartões (título, texto, linha de estado; a do cartão das
# regras é o resumo delas) e a nota de rodapé
START_TEXT = ("Veja e elimine os cookies e as senhas que navegadores e aplicativos"
              "\nguardaram nesta conta.")
START_CARDS = [
    ("Verificar cookies", "Lista tudo o que está guardado, por aplicativo e por site.",
     "Nada é eliminado sem você confirmar"),
    ("Senhas salvas", "Lista os sites com senha guardada nos navegadores e apaga.",
     "A senha nunca é lida nem mostrada"),
    ("Limpeza automática", "Cookies e senhas: a cada sessão, num horário ou ao desligar.",
     ""),
]
START_NOTE = "O valor dos cookies e as senhas nunca são lidos nem mostrados."
RULES_TEXT = ("Elimina sozinho os cookies e as senhas salvas dos sites escolhidos. "
              "Aplicativos abertos na hora são pulados.")


def footer_text(total: int, shown: int, picked: int, in_session: int,
                kind: str = COOKIES) -> str:
    words = KIND_TEXTS[kind]
    text = f"Mostrando {fmt_num(shown)} de {fmt_num(total)} {words['many']}."
    if in_session:
        text += f" {fmt_num(in_session)} em arquivos de restauração de sessão."
    if picked:
        text += f" {fmt_num(picked)} {words['picked']}"
    else:
        text += " Sem seleção, Eliminar remove tudo o que está na lista."
    return text


def delete_question(targets: list, picked: bool, total: int,
                    kind: str = COOKIES) -> tuple[str, str]:
    """(título, texto) da confirmação antes de eliminar."""
    words = KIND_TEXTS[kind]
    n = len(targets)
    if picked:
        scope = "Só o que está selecionado."
    elif n == total:
        scope = words["all"]
    else:
        scope = "Tudo o que está na lista filtrada."
    counts = Counter(c.app for c in targets)
    lines = [f"{app}: {fmt_num(k)}" for app, k in sorted(counts.items())]
    busy_apps = sorted({c.app for c in targets if c.in_use})
    body = scope + "\n\n" + "\n".join(lines)
    body += "\n\nIsso não pode ser desfeito. " + words["effect"]
    if busy_apps:
        body += ("\n\nAbertos agora, serão pulados: " + ", ".join(busy_apps)
                 + ". Feche-os e repita para limpá-los.")
    return f"Eliminar {fmt_num(n)} {words['one'] if n == 1 else words['many']}?", body


def deleted_text(n: int, kind: str = COOKIES) -> str:
    words = KIND_TEXTS[kind]
    plural = "s" if n != 1 else ""
    return f"{fmt_num(n)} {words['one'] if n == 1 else words['many']} {words['done']}{plural}"


def delete_notes(outcome: dict) -> str:
    """O que ficou por eliminar; vazio se correu tudo bem."""
    notes = []
    if outcome["skipped"]:
        parts = ", ".join(f"{app} ({fmt_num(k)})"
                          for app, k in sorted(outcome["skipped"].items()))
        notes.append("Pulados porque o aplicativo está aberto: " + parts
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
        """Uma linha da lista: os campos de um cookie ou de uma senha que as colunas
        mostram ou usam para ordenar."""
        app = GObject.Property(type=str, default="")
        profile = GObject.Property(type=str, default="")
        host = GObject.Property(type=str, default="")
        name = GObject.Property(type=str, default="")
        kind = GObject.Property(type=str, default="")
        expires = GObject.Property(type=str, default="")
        expires_sort = GObject.Property(type=str, default="")
        store = GObject.Property(type=str, default="")
        user = GObject.Property(type=str, default="")
        created = GObject.Property(type=str, default="")
        created_sort = GObject.Property(type=str, default="")
        last_used = GObject.Property(type=str, default="")
        last_used_sort = GObject.Property(type=str, default="")

        def __init__(self, item, kind):
            props = {}
            for (_title, prop, sort_prop, _width), shown in zip(LIST_COLUMNS[kind],
                                                                row_values(item, kind)):
                props[prop] = shown
                if sort_prop != prop:
                    props[sort_prop] = getattr(item, sort_prop)
            super().__init__(**props)
            self.item = item
            self.hay = search_text(item)

    def make_column(title, prop, sort_prop, width, expand):
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

    class ListTab:
        """Uma aba com lista, de cookies ou de senhas: uma página por situação (sem
        verificação, trabalhando, vazia, lista), o filtro e a seleção."""

        def __init__(self, win, kind):
            self.win, self.kind = win, kind
            self.words = KIND_TEXTS[kind]
            self.items: list = []
            self.app_choices: list[str | None] = [None]
            self.app_selected: str | None = None
            self.needle = ""
            self.updating_dropdown = False
            self.status = "Pronto."                # o rodapé enquanto não há lista na tela

            self.store = Gio.ListStore(item_type=Row)
            self.filter = Gtk.CustomFilter.new(self._match, None)
            self.filtered = Gtk.FilterListModel(model=self.store, filter=self.filter)
            self.view = Gtk.ColumnView(show_row_separators=True, reorderable=False)
            for title, prop, sort_prop, width in LIST_COLUMNS[kind]:
                self.view.append_column(make_column(title, prop, sort_prop, width, not width))
            self.sorted = Gtk.SortListModel(model=self.filtered, sorter=self.view.get_sorter())
            self.selection = Gtk.MultiSelection(model=self.sorted)
            self.selection.connect("selection-changed", lambda *_: win._update_footer())
            self.view.set_model(self.selection)
            scroller = Gtk.ScrolledWindow(vexpand=True, hexpand=True, child=self.view)

            self.dropdown = Gtk.DropDown.new_from_strings([ALL_APPS])
            self.dropdown.connect("notify::selected", self.on_app_changed)
            self.search = Gtk.SearchEntry(hexpand=True, placeholder_text=self.words["hint"])
            self.search.connect("search-changed", self.on_search)
            bar = Gtk.Box(spacing=8, margin_top=8, margin_bottom=8, margin_start=10, margin_end=10)
            bar.append(self.dropdown)
            bar.append(self.search)
            page_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            page_list.append(bar)
            page_list.append(Gtk.Separator())
            page_list.append(scroller)

            scan_now = Gtk.Button(label=self.words["scan"], halign=Gtk.Align.CENTER)
            scan_now.add_css_class("pill")
            scan_now.add_css_class("suggested-action")
            scan_now.connect("clicked", lambda *_: win.scan(kind))
            page_idle = Adw.StatusPage(icon_name="edit-find-symbolic", title=IDLE_TITLE,
                                       description=self.words["idle"], child=scan_now)
            spinner = Gtk.Spinner(spinning=True, width_request=32, height_request=32,
                                  halign=Gtk.Align.CENTER)
            page_busy = Adw.StatusPage(title="Trabalhando…", child=spinner)
            page_empty = Adw.StatusPage(icon_name="emblem-ok-symbolic",
                                        title=self.words["empty"])
            self.stack = Gtk.Stack()
            for name, page in (("idle", page_idle), ("busy", page_busy),
                               ("empty", page_empty), ("list", page_list)):
                self.stack.add_named(page, name)

        def show(self, name):
            self.stack.set_visible_child_name(name)

        def fill(self, items):
            self.items = items
            self.store.remove_all()
            self.store.splice(0, 0, [Row(item, self.kind) for item in items])
            counts = Counter(item.app for item in items)
            self.app_choices = [None] + sorted(counts)
            labels = [ALL_APPS] + [
                f"{app} ({fmt_num(counts[app])})" for app in self.app_choices[1:]]
            keep = self.app_selected if self.app_selected in counts else None
            self.updating_dropdown = True
            self.dropdown.set_model(Gtk.StringList.new(labels))
            self.dropdown.set_selected(self.app_choices.index(keep))
            self.updating_dropdown = False
            self.app_selected = keep
            self.filter.changed(Gtk.FilterChange.DIFFERENT)
            if items:
                self.show("list")
            else:
                self.show("empty")
                self.status = self.words["empty_note"]

        def footer(self):
            if self.stack.get_visible_child_name() != "list":
                return self.status
            picked = self.selection.get_selection().get_size()
            sess = sum(1 for item in self.items
                       if getattr(item, "store", "") == STORE_SESSION)
            return footer_text(len(self.items), self.shown(), picked, sess, self.kind)

        # ---- filtro
        def _match(self, row, *_):
            if self.app_selected and row.item.app != self.app_selected:
                return False
            return not self.needle or self.needle in row.hay

        def _refilter(self):
            self.filter.changed(Gtk.FilterChange.DIFFERENT)
            self.win._update_footer()

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
        def shown(self):
            return self.sorted.get_n_items()

        def selected_rows(self):
            bits = self.selection.get_selection()
            return [self.selection.get_item(bits.get_nth(i)) for i in range(bits.get_size())]

        def visible_rows(self):
            return [self.sorted.get_item(i) for i in range(self.shown())]

    class Window(Adw.ApplicationWindow):
        def __init__(self, app):
            super().__init__(application=app, title=APP_NAME,
                             default_width=1200, default_height=680)
            self.busy = False
            self.rules = load_rules(home)
            self.settings = load_settings(home)
            sync_autostart(self.settings, home)   # o programa pode ter mudado de pasta

            # os botões do cabeçalho falam da aba Senhas quando ela está aberta e dos
            # cookies no resto do tempo (self.kind)
            self.kind = COOKIES
            self.btn_scan = Gtk.Button(label=KIND_TEXTS[COOKIES]["scan"])
            self.btn_scan.add_css_class("suggested-action")
            self.btn_scan.connect("clicked", lambda *_: self.scan(self.kind))
            self.btn_delete = Gtk.Button(label=KIND_TEXTS[COOKIES]["delete"], sensitive=False)
            self.btn_delete.add_css_class("eliminar")
            self.btn_delete.connect("clicked", self.on_delete)
            btn_rules = Gtk.Button(icon_name="alarm-symbolic",
                                   tooltip_text="Limpeza automática")
            btn_rules.connect("clicked", self.on_rules)
            header = Adw.HeaderBar()
            header.pack_start(self.btn_scan)
            header.pack_start(btn_rules)
            header.pack_end(self.btn_delete)

            self.lists = {kind: ListTab(self, kind) for kind in (COOKIES, PASSWORDS)}
            self.tabs = Adw.ViewStack(vexpand=True)
            pages = {"inicio": (self._start_page(), "go-home-symbolic"),
                     COOKIES: (self.lists[COOKIES].stack, "view-list-symbolic"),
                     PASSWORDS: (self.lists[PASSWORDS].stack, "dialog-password-symbolic"),
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
            name = self.tabs.get_visible_child_name()
            if name == "inicio":
                self._refresh_stats()             # limpezas automáticas contam também
            self.kind = name if name in self.lists else COOKIES
            self.btn_scan.set_label(KIND_TEXTS[self.kind]["scan"])
            self.btn_delete.set_label(KIND_TEXTS[self.kind]["delete"])
            self._update_footer()

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
            text = Gtk.Label(justify=Gtk.Justification.CENTER, label=START_TEXT)
            text.add_css_class("inicio-texto")
            cards = Gtk.Box(spacing=14, homogeneous=True, margin_top=6)
            for index, (icon_name, (title_text, body, state)) in enumerate(zip(
                    ("edit-find-symbolic", "dialog-password-symbolic", "alarm-symbolic"),
                    START_CARDS)):
                handler = (lambda *_: self.scan(COOKIES), lambda *_: self.scan(PASSWORDS),
                           self.on_rules)[index]
                card, status = self._card(icon_name, title_text, body,
                                          state or rules_summary(self.rules), handler,
                                          primary=index == 0)
                cards.append(card)
            self.rules_state = status             # o último cartão é o das regras
            note = Gtk.Label(label=START_NOTE, margin_top=18)
            note.add_css_class("inicio-nota")
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8,
                             valign=Gtk.Align.CENTER, margin_top=24, margin_bottom=24,
                             margin_start=24, margin_end=24)
            for widget in (title, text, self._monitor(), cards, note):
                column.append(widget)
            page = Gtk.Box()
            page.add_css_class("inicio")
            page.append(Adw.Clamp(maximum_size=780, child=column, hexpand=True))
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
            what = Adw.ComboRow(title="O que limpar", model=Gtk.StringList.new(
                [label for _kinds, label in WHAT_LABELS]))
            when = Adw.ComboRow(title="Quando", model=Gtk.StringList.new(
                [label for _key, label in WHEN_LABELS]))
            hour = Adw.EntryRow(title="Horário (HH:MM)", text="08:00", visible=False)
            when.connect("notify::selected", lambda *_: hour.set_visible(
                when_keys[when.get_selected()] == WHEN_TIME))
            add = Gtk.Button(label="Adicionar regra", halign=Gtk.Align.END, margin_top=12)
            add.add_css_class("suggested-action")
            form = Adw.PreferencesGroup(title="Nova regra", description=RULES_TEXT)
            for widget in (sites, what, when, hour, add):
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
                    detail = f"{rule_what_text(rule)} · {rule_when_text(rule)}"
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
                                       hour.get_text(), WHAT_LABELS[what.get_selected()][0])
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

        # ---- rodapé
        def _update_footer(self):
            current = self.lists[self.kind]
            self.footer.set_text(current.footer())
            self.btn_delete.set_sensitive(
                not self.busy and current.stack.get_visible_child_name() == "list"
                and current.shown() > 0)

        # ---- verificar
        def _set_busy(self, busy, kind, text=""):
            self.busy = busy
            self.btn_scan.set_sensitive(not busy)
            self.btn_delete.set_sensitive(False)
            if busy:
                current = self.lists[kind]
                current.status = text
                current.show("busy")
                self.tabs.set_visible_child_name(kind)
                self._update_footer()

        # Os cliques só agendam o trabalho: mexer na tela (trocar de página, abrir diálogo)
        # dentro do próprio "clicked" deixa o GTK com o botão preso como "pressionado".
        def scan(self, kind):
            GLib.idle_add(self._start_scan, kind)

        def on_delete(self, *_):
            GLib.idle_add(self._ask_delete)

        def _start_scan(self, kind):
            if self.busy:
                return False
            self._set_busy(True, kind, KIND_TEXTS[kind]["busy"])

            def work():
                GLib.idle_add(self._scan_done, kind, scan_safely(home, kind))

            threading.Thread(target=work, daemon=True).start()
            return False

        def _scan_done(self, kind, result):
            items, warnings = result
            self._set_busy(False, kind)
            self.lists[kind].fill(items)
            self._update_footer()
            if warnings:
                self._alert("Alguns locais não puderam ser lidos", "\n".join(warnings))
            return False

        # ---- eliminar
        def _ask_delete(self):
            if self.busy:
                return False
            kind, current = self.kind, self.lists[self.kind]
            picked = current.selected_rows()
            rows = picked or current.visible_rows()
            if not rows:
                return False
            targets = [r.item for r in rows]
            self.tabs.set_visible_child_name(kind)    # a lista de que a pergunta fala
            heading, body = delete_question(targets, bool(picked), len(current.items), kind)
            dialog = Adw.AlertDialog(heading=heading, body=body)
            dialog.add_response("cancel", "Cancelar")
            dialog.add_response("delete", "Eliminar")
            dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            dialog.connect("response", self._delete_answer, kind, targets)
            dialog.present(self)
            return False

        def _delete_answer(self, _dialog, response, kind, targets):
            if response == "delete":
                GLib.idle_add(self._start_delete, kind, targets)

        def _start_delete(self, kind, targets):
            if self.busy:
                return False
            self._set_busy(True, kind, "Eliminando…")

            def work():
                outcome = delete_safely(targets, home, kind)
                GLib.idle_add(self._delete_done, kind, outcome, scan_safely(home, kind))

            threading.Thread(target=work, daemon=True).start()
            return False

        def _delete_done(self, kind, outcome, result):
            self._scan_done(kind, result)
            self._refresh_stats()
            self.toasts.add_toast(Adw.Toast(title=deleted_text(outcome["deleted"], kind)))
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


# --------------------------------------------------------------------------- desenho (janela Tk)
# O Tk não tem cantos arredondados, ícones simbólicos nem cores semitransparentes. Para a
# janela Tk ficar igual à GTK, no Windows e no Linux, os cantos, os ícones, o interruptor,
# as barras do gráfico e o brilho da página inicial são desenhados aqui, em PNG com
# transparência, sem bibliotecas de fora.

def _rgb(color: str) -> tuple[int, int, int]:
    return int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)


def mix(color: str, over: str, amount: float) -> str:
    """A cor over pintada sobre color com opacidade amount: o alpha() do CSS sobre um
    fundo liso."""
    return "#%02x%02x%02x" % tuple(round(a + (b - a) * amount)
                                   for a, b in zip(_rgb(color), _rgb(over)))


def png_rgba(width: int, height: int, rows) -> bytes:
    """PNG com transparência. rows: uma sequência de bytes por linha, com r, g, b, a de
    cada pixel."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    raw = b"".join(b"\0" + bytes(row) for row in rows)      # linhas sem filtro
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def _pixels(width: int, height: int, layers) -> list[bytearray]:
    """As linhas de pixels das camadas [(cor, opacidade, forma)], de baixo para cima. A
    forma é uma função (x, y) -> distância em pixels até a borda dela, negativa dentro;
    a borda sai suavizada, meio pixel para cada lado."""
    layers = [(_rgb(color), alpha, shape) for color, alpha, shape in layers]
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            red = green = blue = cover = 0.0  # cor pré-multiplicada pela opacidade
            for (r, g, b), alpha, shape in layers:
                d = shape(x + 0.5, y + 0.5)
                a = alpha * (1.0 if d <= -0.5 else 0.0 if d >= 0.5 else 0.5 - d)
                if a:
                    keep = 1.0 - a
                    red, green, blue = r * a + red * keep, g * a + green * keep, b * a + blue * keep
                    cover = a + cover * keep
            row.extend((min(255, round(red / cover)), min(255, round(green / cover)),
                        min(255, round(blue / cover)), round(cover * 255))
                       if cover else (0, 0, 0, 0))
        rows.append(row)
    return rows


def paint(width: int, height: int, layers) -> bytes:
    """PNG com as camadas [(cor, opacidade, forma)] (ver _pixels)."""
    return png_rgba(width, height, _pixels(width, height, layers))


def round_rect(x0: float, y0: float, x1: float, y1: float, radius: float):
    """Forma: retângulo de cantos arredondados."""
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    hx, hy = (x1 - x0) / 2 - radius, (y1 - y0) / 2 - radius

    def shape(x, y):
        qx, qy = abs(x - cx) - hx, abs(y - cy) - hy
        return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - radius
    return shape


def _line(x1, y1, x2, y2, width):
    """Forma: traço reto de pontas redondas."""
    dx, dy = x2 - x1, y2 - y1
    length = dx * dx + dy * dy or 1e-9

    def shape(x, y):
        t = max(0.0, min(1.0, ((x - x1) * dx + (y - y1) * dy) / length))
        return math.hypot(x - x1 - t * dx, y - y1 - t * dy) - width / 2
    return shape


def _disk(cx, cy, radius):
    return lambda x, y: math.hypot(x - cx, y - cy) - radius


def _ring(cx, cy, radius, width):
    return lambda x, y: abs(math.hypot(x - cx, y - cy) - radius) - width / 2


def _arc(cx, cy, radius, width, start, extent):
    """Forma: pedaço de anel de pontas redondas, do ângulo start (radianos) por extent."""
    middle, half = start + extent / 2, extent / 2

    def shape(x, y):
        off = (math.atan2(y - cy, x - cx) - middle + math.pi) % (2 * math.pi) - math.pi
        if abs(off) <= half:
            return abs(math.hypot(x - cx, y - cy) - radius) - width / 2
        end = middle + math.copysign(half, off)
        return math.hypot(x - cx - radius * math.cos(end),
                          y - cy - radius * math.sin(end)) - width / 2
    return shape


def _union(*shapes):
    return lambda x, y: min(shape(x, y) for shape in shapes)


def _cut(shape, hole):
    return lambda x, y: max(shape(x, y), -hole(x, y))


def _gear():
    teeth = [_line(8 + 4.6 * math.cos(k * math.pi / 4), 8 + 4.6 * math.sin(k * math.pi / 4),
                   8 + 6.5 * math.cos(k * math.pi / 4), 8 + 6.5 * math.sin(k * math.pi / 4),
                   2.6) for k in range(8)]
    return _cut(_union(_disk(8, 8, 5.2), *teeth), _disk(8, 8, 2.2))


# ícones simbólicos de 16 x 16, no desenho dos ícones do GNOME que a janela GTK usa
ICONS = {
    "inicio": lambda: _union(                               # go-home
        _line(1.75, 7.6, 8, 1.9, 1.5), _line(8, 1.9, 14.25, 7.6, 1.5),
        _line(3.6, 6.8, 3.6, 13.9, 1.5), _line(12.4, 6.8, 12.4, 13.9, 1.5),
        _line(3.6, 13.9, 12.4, 13.9, 1.5), round_rect(6.6, 9.2, 9.4, 14.65, 0.7)),
    "lista": lambda: _union(                                # view-list
        *[round_rect(1, y - 1.5, 4, y + 1.5, 0.8) for y in (3.5, 8, 12.5)],
        *[round_rect(5.75, y - 0.75, 15, y + 0.75, 0.75) for y in (3.5, 8, 12.5)]),
    "senha": lambda: _union(                                # dialog-password (chave)
        _cut(_disk(5.5, 5.5, 4.5), _disk(4.6, 4.6, 1.4)), _line(7.5, 7.5, 14, 14, 2.2),
        _line(10.6, 10.6, 12.2, 9.0, 2), _line(12.9, 12.9, 14.5, 11.3, 2)),
    "ajustes": _gear,                                       # emblem-system
    "alarme": lambda: _union(                               # alarm
        _ring(8, 8.8, 5.4, 1.5), _line(8, 8.8, 8, 5.8, 1.4), _line(8, 8.8, 10.2, 10.2, 1.4),
        _line(1.4, 4.4, 4.2, 1.6, 1.8), _line(11.8, 1.6, 14.6, 4.4, 1.8),
        _line(4.3, 13.1, 3.1, 14.5, 1.4), _line(11.7, 13.1, 12.9, 14.5, 1.4)),
    "busca": lambda: _union(                                # edit-find
        _ring(6.6, 6.6, 4.6, 1.8), _line(10.2, 10.2, 14.2, 14.2, 2.2)),
    "ok": lambda: _union(                                   # emblem-ok
        _ring(8, 8, 6.6, 1.4), _line(4.9, 8.3, 7.1, 10.5, 1.6),
        _line(7.1, 10.5, 11.2, 5.9, 1.6)),
    "seta": lambda: _union(                                 # pan-down
        _line(4.25, 6.25, 8, 10, 1.6), _line(8, 10, 11.75, 6.25, 1.6)),
    "lixeira": lambda: _union(                              # user-trash
        _cut(round_rect(3.4, 4.6, 12.6, 15, 1.6), round_rect(4.9, 4.6, 11.1, 13.5, 0.6)),
        _line(1.9, 3.3, 14.1, 3.3, 1.5), round_rect(6, 0.9, 10, 3.3, 0.8),
        _line(6.75, 7, 6.75, 11.5, 1.2), _line(9.25, 7, 9.25, 11.5, 1.2)),
}


def _scaled(shape, size: int, offset: float = 0.0):
    """A forma de um ícone de 16 x 16 no tamanho size, deslocada de offset pixels."""
    k = size / 16
    return lambda x, y: shape((x - offset) / k, (y - offset) / k) * k


def icon_png(name: str, size: int, color: str, alpha: float = 1.0) -> bytes:
    return paint(size, size, [(color, alpha, _scaled(ICONS[name](), size))])


SLICE_MIDDLE = 48


def slice_png(radius: int, fill: str, edge: str | None = None, width: int = 0,
              margin: int = 0, alpha: float = 1.0, wide: bool = True) -> bytes:
    """Retângulo de cantos arredondados para ser esticado pelo meio (o -border, de
    radius + margin, dos elementos de imagem do ttk). edge é o contorno, com width
    pixels; margin, uma folga transparente em volta.

    O ttk estica repetindo o miolo: com um miolo de 1 pixel ele desenharia um quadradinho
    por pixel da janela. Por isso o miolo tem SLICE_MIDDLE pixels (só na altura, se não
    for wide)."""
    corner = radius + margin
    n = 2 * corner + 1
    outer = round_rect(margin, margin, n - margin, n - margin, radius)
    layers = [(fill, alpha, outer)]
    if edge and width:
        inner = round_rect(margin + width, margin + width, n - margin - width,
                           n - margin - width, max(radius - width, 0))
        layers = [(edge, alpha, outer), (fill, alpha, inner)]
    rows = _pixels(n, n, layers)
    across = SLICE_MIDDLE if wide else 1
    left, right = 4 * corner, 4 * corner + 4
    rows = [row[:left] + row[left:right] * across + row[right:] for row in rows]
    rows = rows[:corner] + [rows[corner]] * SLICE_MIDDLE + rows[corner + 1:]
    return png_rgba(2 * corner + across, 2 * corner + SLICE_MIDDLE, rows)


def badge_png(size: int, pad: int, radius: int, color: str, name: str) -> bytes:
    """Ícone dos cartões da página inicial: na cor, sobre um quadrado dela a 16%."""
    full = size + 2 * pad
    return paint(full, full, [(color, 0.16, round_rect(0, 0, full, full, radius)),
                              (color, 1.0, _scaled(ICONS[name](), size, pad))])


def bar_png(width: int, height: int, radius: int, color: str) -> bytes:
    """Barra do gráfico de cookies eliminados: cantos arredondados só em cima."""
    return paint(width, height, [(color, 1.0, round_rect(0, 0, width, height + radius, radius))])


def switch_png(width: int, height: int, on: bool, track: str, knob: str,
               alpha: float = 1.0) -> bytes:
    """Interruptor: trilho de pontas redondas e a bolinha, à direita quando ligado."""
    half = height / 2
    return paint(width, height, [
        (track, alpha, round_rect(0, 0, width, height, half)),
        (knob, alpha, _disk(width - half if on else half, half, half - height * 3 / 26))])


def spinner_png(size: int, color: str, turn: float) -> bytes:
    """Um quadro do indicador de "trabalhando": três quartos de anel, girados de turn
    voltas."""
    arc = _arc(8, 8, 6.5, 2, 2 * math.pi * turn, 1.5 * math.pi)
    return paint(size, size, [(color, 1.0, _scaled(arc, size))])


def glow_png(size: int, radius: float, base: str, color: str, strength: float) -> bytes:
    """Quadrado da cor base com um brilho redondo no meio: color com strength de
    opacidade no centro, sumindo até radius (o radial-gradient da janela GTK)."""
    (br, bg, bb), (cr, cg, cb) = _rgb(base), _rgb(color)
    half = size // 2
    size = 2 * half
    rows = []
    for y in range(half):                       # um quarto; o resto é espelho
        pixels = []
        for x in range(half):
            t = strength * max(0.0, 1.0 - math.hypot(x + 0.5 - half, y + 0.5 - half) / radius)
            pixels.append(bytes((round(br + (cr - br) * t), round(bg + (cg - bg) * t),
                                 round(bb + (cb - bb) * t), 255)))
        rows.append(b"".join(pixels + pixels[::-1]))
    return png_rgba(size, size, rows + rows[::-1])


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


def _win_dark_titlebar(window, color: str = THEME["bg"]) -> None:
    """Windows 10 e 11: barra de título escura; no 11, na cor do fundo (color), para ela
    e o cabeçalho da janela parecerem uma peça só, como na janela GTK."""
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
        red, green, blue = _rgb(color)
        value = ctypes.c_int(red | green << 8 | blue << 16)             # cor da barra: só no 11
        set_attr(hwnd, 35, ctypes.byref(value), ctypes.sizeof(value))
    except (AttributeError, OSError):
        pass


def run_gui_tk(home: str | None, minimized: bool = False) -> int:
    """A janela do Windows (e do Linux sem GTK 4), desenhada igual à janela GTK."""
    try:
        import tkinter as tk
        from tkinter import font as tkfont, ttk
    except ImportError:
        print("Falta a parte gráfica do Python. No Debian/Ubuntu:\n"
              "    sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1\n"
              "ou, para a janela Tk:\n"
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

    FG, BG, BAR, SURFACE = T["fg"], T["bg"], T["bar"], T["surface"]
    # cores que o libadwaita tira do texto e do fundo, como alpha(currentColor, 0.15)
    SEP = mix(BG, FG, 0.15)                     # linhas divisórias
    FIELD = mix(BG, FG, 0.10)                   # campo de busca, lista de aplicativos
    PICKED = mix(BG, T["accent"], 0.25)         # linha selecionada
    SHADE = mix(SURFACE, "#000000", 0.36)       # divisória das listas de ajustes
    KNOB = mix(BG, "#ffffff", 0.8)              # bolinha do interruptor
    TIP = mix(BG, "#000000", 0.6)               # fundo das dicas

    # ---- fontes: as mesmas proporções da janela GTK, que usa 11 pt no texto normal
    families = set(tkfont.families(root))
    if WINDOWS:
        family, ratio = "Segoe UI", 10 / 11     # no Windows, o costume é 10 pt
    else:
        family = next((name for name in ("Adwaita Sans", "Cantarell") if name in families),
                      tkfont.nametofont("TkDefaultFont").cget("family"))
        ratio = 1.0

    def font(points, bold=False):
        return tkfont.Font(root, family=family, weight="bold" if bold else "normal",
                           size=-max(1, round(points * ratio * 96 / 72 * scale)))

    F = {"base": font(11), "bold": font(11, True), "sub": font(9.2), "small": font(9.5),
         "small_bold": font(9.5, True), "tiny": font(8.5), "tiny_bold": font(8.5, True),
         "intro": font(11.5), "hero": font(26, True), "stat": font(21, True),
         "title1": font(20, True), "title2": font(15, True)}
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        tkfont.nametofont(name).configure(family=family, size=F["base"].cget("size"))
    BUTTON_PAD = max(px(4), (px(34) - F["bold"].metrics("linespace")) // 2)  # 34 px de altura
    FIELD_PAD = max(px(4), (px(34) - F["base"].metrics("linespace")) // 2)

    # ---- imagens
    art = {}

    def picture(key, make):
        """PhotoImage do PNG que make() devolve, guardada: o Tk apaga a que ninguém guarda."""
        if key not in art:
            art[key] = tk.PhotoImage(master=root,
                                     data=base64.b64encode(make()).decode("ascii"))
        return art[key]

    def icon(name, size=16, color=FG, alpha=1.0):
        size = px(size)
        return picture(("ícone", name, size, color, alpha),
                       lambda: icon_png(name, size, color, alpha))

    def lined(fill, line):
        """Fundo com uma linha de 1 pixel embaixo: esticada (com -border 0 0 0 1), vira a
        faixa de uma linha da lista com a divisória. Larga, para o ttk repetir pouco."""
        key = ("faixa", fill, line)
        if key not in art:
            width, height = 256, SLICE_MIDDLE + 1
            image = tk.PhotoImage(master=root, width=width, height=height)
            image.put("{%s}" % fill, to=(0, 0, width, height - 1))
            image.put("{%s}" % line, to=(0, height - 1, width, height))
            art[key] = image
        return art[key]

    def separator(parent, color=SEP):
        return tk.Frame(parent, height=1, bg=color, bd=0, highlightthickness=0)

    # ---- estilos
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=FG, font=F["base"], troughcolor=BG,
                    bordercolor=BG, lightcolor=BG, darkcolor=BG, focuscolor=BG,
                    selectbackground=PICKED, selectforeground=FG, insertcolor=FG)
    style.map(".", background=[("disabled", BG), ("active", BG)],
              foreground=[("disabled", mix(BG, FG, 0.5))],
              selectbackground=[("!focus", PICKED)], selectforeground=[("!focus", FG)])

    def plain(name, bg, **options):
        """Estilo de fundo bg em todos os estados (o tema clam clareia o fundo ativo)."""
        style.configure(name, background=bg, **options)
        style.map(name, background=[(state, bg) for state in
                                    ("disabled", "pressed", "active", "hover")])

    def box(name, radius, normal, *states):
        """Elemento de fundo arredondado, esticado pelo meio. normal e cada estado: cor ou
        (cor, contorno, espessura); states: [(estados ttk, aparência)], vale o primeiro
        que bater. radius em pixels."""
        def image(look):
            look = look if isinstance(look, tuple) else (look, None, 0)
            fill, edge, width = look
            width = max(1, px(width)) if width else 0
            return picture(("canto", radius, fill, edge, width),
                           lambda: slice_png(radius, fill, edge, width))
        # padding=0: sem ele, o ttk afasta o conteúdo da borda pelo tamanho do canto;
        # width e height: o tamanho mínimo é o dos cantos, não o da imagem inteira
        style.element_create(name, "image", image(normal),
                             *[(state, image(look)) for state, look in states],
                             border=radius, padding=0, width=2 * radius, height=2 * radius,
                             sticky="nsew")

    def framed(name, under, radius, normal, *states):
        """Estilo de ttk.Frame com o fundo arredondado sobre a cor under."""
        box(name + ".fundo", radius, normal, *states)
        style.layout(name, [(name + ".fundo", {"sticky": "nsew"})])
        plain(name, under)

    def button(name, under, kind="normal", radius=None, padding=None):
        """Botão do libadwaita sobre o fundo under: normal, plano (sem fundo), principal
        (verde-água), eliminar (vermelho discreto) ou destrutivo (vermelho cheio)."""
        danger = T["danger"]
        if kind == "principal":
            fill, text = T["accent_bg"], T["on_accent"]
            hover, press = mix(fill, text, 0.1), mix(fill, text, 0.2)
        elif kind == "destrutivo":
            fill, text = T["danger_bg"], "#ffffff"
            hover, press = mix(fill, text, 0.1), mix(fill, "#000000", 0.2)
        elif kind == "eliminar":
            fill, text = mix(under, danger, 0.14), danger
            hover, press = mix(under, danger, 0.22), mix(under, danger, 0.30)
        elif kind == "plano":
            fill, text = under, FG
            hover, press = mix(under, FG, 0.07), mix(under, FG, 0.16)
        else:
            fill, text = mix(under, FG, 0.10), FG
            hover, press = mix(under, FG, 0.15), mix(under, FG, 0.30)
        off = mix(under, fill, 0.5)                 # desativado: meio transparente
        box(name + ".fundo", radius or px(8), fill, ("disabled", off), ("pressed", press),
            ("active", hover))
        widget = name.rsplit(".", 1)[1][1:]         # Button, Menubutton...
        style.layout(name, [(name + ".fundo", {"sticky": "nsew", "children": [
            (widget + ".padding", {"sticky": "nsew", "children": [
                (widget + ".label", {"sticky": ""})]})]})])
        plain(name, under, foreground=text, font=F["bold"], anchor="center", space=px(6),
              padding=padding or (px(16), BUTTON_PAD), relief="flat", borderwidth=0)
        style.map(name, foreground=[("disabled", mix(off, text, 0.5))])

    button("Principal.TButton", BG, "principal")
    button("Eliminar.TButton", BG, "eliminar")
    button("Plano.TButton", BG, "plano", padding=px(9))
    button("Lista.TMenubutton", BG, padding=(px(12), BUTTON_PAD))
    pill = F["bold"].metrics("linespace") + 2 * px(10)
    button("Pilula.TButton", BG, "principal", radius=pill // 2, padding=(px(32), px(10)))
    button("Dialogo.TButton", SURFACE)
    button("Dialogo.Destrutivo.TButton", SURFACE, "destrutivo")
    button("Linha.Plano.TButton", SURFACE, "plano", padding=px(9))

    # abas do cabeçalho (o Adw.ViewSwitcher)
    box("Aba.fundo", px(8), BG, ("selected active", mix(BG, FG, 0.13)),
        ("selected", mix(BG, FG, 0.10)), ("pressed", mix(BG, FG, 0.16)),
        ("active", mix(BG, FG, 0.07)))
    style.layout("Aba.TRadiobutton", [("Aba.fundo", {"sticky": "nsew", "children": [
        ("Radiobutton.padding", {"sticky": "nsew", "children": [
            ("Radiobutton.label", {"sticky": ""})]})]})])
    plain("Aba.TRadiobutton", BG, foreground=FG, font=F["bold"], space=px(6),
          padding=(px(12), BUTTON_PAD))

    # quadros: painéis e cartões da página inicial, grupos de ajustes, campo de busca
    plain("TFrame", BG)
    plain("Rodape.TFrame", BAR)
    plain("Linha.TFrame", SURFACE)
    plain("Dialogo.TFrame", SURFACE)
    framed("Painel.TFrame", BG, px(16), (SURFACE, T["border"], 1))
    hover = (T["raised"], mix(T["raised"], T["accent"], 0.6), 1)
    framed("Cartao.TFrame", BG, px(16), (SURFACE, T["border"], 1), ("hover", hover))
    framed("Cartao.Principal.TFrame", BG, px(16),
           (SURFACE, mix(SURFACE, T["accent"], 0.6), 1), ("hover", hover))
    # listas de ajustes (a boxed-list): contorno de 1 px um pouco mais escuro que o fundo
    framed("Grupo.TFrame", BG, px(12), (SURFACE, mix(BG, "#000000", 0.1), 1))
    framed("Campo.TFrame", BG, px(8), FIELD,
           ("focus", (FIELD, mix(FIELD, T["accent"], 0.5), 2)))

    # rótulos: fundo, cor e fonte
    for name, (bg, color, typeface) in {
            "TLabel": (BG, FG, F["base"]),
            "Pagina.TLabel": (BG, FG, F["base"]),
            "Pagina.Titulo.TLabel": (BG, FG, F["title1"]),
            "Grupo.TLabel": (BG, FG, F["bold"]),
            "Descricao.TLabel": (BG, T["fg_dim"], F["base"]),
            "Rodape.TLabel": (BAR, T["fg_dim"], F["base"]),
            "Campo.TLabel": (FIELD, FG, F["base"]),
            "Painel.TLabel": (SURFACE, FG, F["bold"]),
            "Painel.Rotulo.TLabel": (SURFACE, T["fg_muted"], F["small_bold"]),
            "Painel.Numero.TLabel": (SURFACE, FG, F["stat"]),
            "Painel.Nota.TLabel": (SURFACE, T["fg_dim"], F["small"]),
            "Linha.TLabel": (SURFACE, FG, F["base"]),
            "LinhaSub.TLabel": (SURFACE, T["fg_dim"], F["sub"]),
            "Dialogo.TLabel": (SURFACE, FG, F["base"]),
            "Dialogo.Titulo.TLabel": (SURFACE, FG, F["title2"])}.items():
        plain(name, bg, foreground=color, font=typeface)
        style.map(name, foreground=[("disabled", mix(bg, color, 0.5))])
    for name, color, typeface in (("Cartao.TLabel", FG, F["bold"]),
                                  ("Cartao.Texto.TLabel", T["fg_dim"], F["base"]),
                                  ("Cartao.Estado.TLabel", T["accent"], F["small_bold"])):
        style.configure(name, background=SURFACE, foreground=color, font=typeface)
        style.map(name, background=[("hover", T["raised"]), ("disabled", SURFACE),
                                    ("active", SURFACE)])

    # aviso que some sozinho (o Adw.Toast)
    box("Aviso.fundo", (F["base"].metrics("linespace") + 2 * px(10)) // 2, mix(BG, FG, 0.15))
    style.layout("Aviso.TLabel", [("Aviso.fundo", {"sticky": "nsew", "children": [
        ("Label.padding", {"sticky": "nsew", "children": [
            ("Label.label", {"sticky": "nsew"})]})]})])
    plain("Aviso.TLabel", BG, foreground=FG, font=F["base"], padding=(px(20), px(10)))

    # campos de texto: o fundo vem do quadro em volta (Campo.TFrame) ou da linha
    for name, fill, pad in (("Campo.TEntry", FIELD, (px(2), FIELD_PAD - px(2))),
                            ("Linha.TEntry", SURFACE, (0, px(2)))):
        style.configure(name, fieldbackground=fill, background=fill, foreground=FG,
                        insertcolor=FG, bordercolor=fill, lightcolor=fill, darkcolor=fill,
                        borderwidth=0, padding=pad, font=F["base"])
        style.map(name, bordercolor=[("focus", fill)], lightcolor=[("focus", fill)],
                  darkcolor=[("focus", fill)], fieldbackground=[("disabled", fill)],
                  background=[("disabled", fill), ("active", fill)])

    # interruptor (o Gtk.Switch): 46 x 26, bolinha de 20
    def switch_image(on, alpha):
        width, height = px(46), px(26)
        track = T["accent_bg"] if on else mix(SURFACE, FG, 0.15)
        return picture(("chave", on, alpha, width, height),
                       lambda: switch_png(width, height, on, track, KNOB, alpha))

    style.element_create("Chave.indicador", "image", switch_image(False, 1.0),
                         ("disabled selected", switch_image(True, 0.5)),
                         ("disabled", switch_image(False, 0.5)),
                         ("selected", switch_image(True, 1.0)), sticky="")
    style.layout("Chave.TCheckbutton", [("Chave.indicador", {"sticky": ""})])
    plain("Chave.TCheckbutton", SURFACE, padding=0)

    # lista: linhas com divisória, cabeçalho em negrito apagado
    style.element_create("Lista.linha", "image", lined(BG, SEP), ("selected", lined(PICKED, SEP)),
                         border=(0, 0, 0, 1), padding=0, width=1, height=1, sticky="nsew")
    style.layout("Lista.Treeview.Row", [("Lista.linha", {"sticky": "nsew"})])
    style.element_create("Lista.cabecalho", "image", lined(BG, SEP), border=(0, 0, 0, 1),
                         padding=0, width=1, height=1, sticky="nsew")
    style.layout("Lista.Treeview.Heading", [("Lista.cabecalho", {"sticky": "nsew", "children": [
        ("Treeheading.padding", {"sticky": "nsew", "children": [
            ("Treeheading.image", {"side": "right", "sticky": ""}),
            ("Treeheading.text", {"sticky": "we"})]})]})])
    plain("Lista.Treeview", BG, fieldbackground=BG, foreground=FG, bordercolor=BG,
          lightcolor=BG, darkcolor=BG, borderwidth=0, font=F["base"],
          rowheight=F["base"].metrics("linespace") + px(16))
    style.map("Lista.Treeview", foreground=[("selected", FG)])
    plain("Lista.Treeview.Heading", BG, foreground=T["fg_muted"], font=F["small_bold"],
          padding=(px(6), px(9)), relief="flat", borderwidth=0)
    style.map("Lista.Treeview.Heading", foreground=[("active", T["fg_dim"])])

    # barra de rolagem fina, de pontas redondas, sem setas
    def thumb(alpha):
        radius, margin = px(3), px(2)
        return picture(("rolagem", radius, margin, alpha), lambda: slice_png(
            radius, FG, margin=margin, alpha=alpha, wide=False))

    corner = px(3) + px(2)
    style.element_create("Rolagem.thumb", "image", thumb(0.25), ("pressed", thumb(0.5)),
                         ("active", thumb(0.4)), border=corner, padding=0,
                         width=2 * corner + 1, height=2 * corner + 1, sticky="nsew")
    style.layout("Rolagem.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
        "sticky": "ns", "children": [("Rolagem.thumb", {"expand": "1", "sticky": "nswe"})]})])
    plain("Rolagem.Vertical.TScrollbar", BG, troughcolor=BG, bordercolor=BG, lightcolor=BG,
          darkcolor=BG, gripcount=0)

    for option, value in (("background", SURFACE), ("foreground", FG),
                          ("activeBackground", mix(SURFACE, FG, 0.1)),
                          ("activeForeground", FG), ("selectColor", T["accent"]),
                          ("relief", "flat"), ("borderWidth", 0), ("activeBorderWidth", 0),
                          ("font", str(F["base"]))):
        root.option_add("*Menu." + option, value)

    # ---- dicas (tooltips)
    tip = {"window": None, "job": None, "text": None}

    def hide_tip(_event=None):
        if tip["job"]:
            root.after_cancel(tip["job"])
        if tip["window"]:
            tip["window"].destroy()
        tip.update(window=None, job=None, text=None)

    def show_tip(text):
        hide_tip()
        if not text:
            return
        top = tip["window"] = tk.Toplevel(root, bg=SEP)
        top.overrideredirect(True)
        top.attributes("-topmost", True)
        tk.Label(top, text=text, bg=TIP, fg=FG, font=F["small"], justify="left",
                 padx=px(10), pady=px(6)).pack(padx=1, pady=1)
        x, y = root.winfo_pointerxy()
        top.geometry(f"+{x + px(12)}+{y + px(18)}")
        tip["text"] = text

    def tooltip(widget, text):
        """Dica que aparece com o ponteiro parado sobre widget."""
        def enter(_event):
            hide_tip()
            tip["job"] = root.after(600, lambda: show_tip(text))
        widget.bind("<Enter>", enter, add="+")
        widget.bind("<Leave>", hide_tip, add="+")
        widget.bind("<ButtonPress>", hide_tip, add="+")

    def toast(parent, text):
        """Aviso embaixo, que some sozinho em 3 segundos."""
        label = ttk.Label(parent, text=text, style="Aviso.TLabel")
        label.place(relx=0.5, rely=1.0, y=-px(12), anchor="s")
        label.lift()
        root.after(3000, label.destroy)

    # ---- peças repetidas
    def status_page(parent, image, title, text="", action=None):
        """Página com ícone grande, título, texto e botão (o Adw.StatusPage).
        Devolve (página, coluna do meio)."""
        page = ttk.Frame(parent)
        column = ttk.Frame(page)
        column.place(relx=0.5, rely=0.5, anchor="center")
        if image:
            ttk.Label(column, image=image).pack(pady=(0, px(30)))
        ttk.Label(column, text=title, style="Pagina.Titulo.TLabel", justify="center").pack()
        if text:
            ttk.Label(column, text=text, style="Pagina.TLabel", justify="center",
                      wraplength=px(560)).pack(pady=(px(12), 0))
        if action:
            action(column).pack(pady=(px(30), 0))
        return page, column

    group_lines = {}

    def fill_group(group, rows):
        """Mostra as linhas rows, nessa ordem, numa lista de cantos arredondados (a
        boxed-list do libadwaita), com divisórias de ponta a ponta entre elas."""
        for line in group_lines.pop(str(group), []):
            line.destroy()
        for child in group.pack_slaves():
            child.pack_forget()
        lines = group_lines[str(group)] = []
        for index, row in enumerate(rows):
            row.pack(fill="x")
            if index:                     # a linha fica recuada dos cantos; a divisória, não
                line = separator(group, SHADE)
                line.place(in_=row, x=-px(12), y=0, relwidth=1, width=2 * px(12), height=1)
                lines.append(line)

    def list_row(group, title, subtitle=None, wrap=480):
        """Linha de lista de ajustes (o Adw.ActionRow): título, subtítulo e, à direita, o
        quadro devolvido para o interruptor ou botões. Devolve (linha, direita, rótulos)."""
        row = ttk.Frame(group, style="Linha.TFrame", padding=(0, px(8 if subtitle else 14)))
        suffix = ttk.Frame(row, style="Linha.TFrame")
        suffix.pack(side="right", padx=(px(12), 0))
        texts = ttk.Frame(row, style="Linha.TFrame")
        texts.pack(side="left", fill="x", expand=True)
        labels = [ttk.Label(texts, text=title, style="Linha.TLabel")]
        if subtitle:
            labels.append(ttk.Label(texts, text=subtitle, style="LinhaSub.TLabel",
                                    justify="left", wraplength=px(wrap)))
        for label in labels:
            label.pack(anchor="w")
        return row, suffix, labels

    def group_box(parent):
        # recuo de 12 px dos lados: as linhas não cobrem os cantos arredondados
        return ttk.Frame(parent, style="Grupo.TFrame", padding=(px(12), 0))

    def place_over(top, parent, width=None, height=None):
        top.update_idletasks()
        width = width or top.winfo_reqwidth()
        height = height or top.winfo_reqheight()
        x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - height) // 3
        top.geometry(f"{width}x{height}+{max(x, 0)}+{max(y, 0)}")

    class ListTab:
        """Uma aba com lista, de cookies ou de senhas: as páginas sem verificação, vazia e
        com a lista (a de "trabalhando" é da janela), o filtro, a ordenação e a seleção."""

        def __init__(self, app, kind, body):
            self.app, self.kind = app, kind
            self.words = KIND_TEXTS[kind]
            self.columns = LIST_COLUMNS[kind]
            self.items: list = []
            self.hay: list[str] = []           # texto de busca de cada item
            self.visible: list[str] = []       # linhas mostradas, em ordem; o id é a posição
            self.app_choices: list[str | None] = [None]
            self.app_selected: str | None = None
            self.needle = ""
            self.sort_col: str | None = None
            self.sort_desc = False
            self.status = "Pronto."            # o rodapé enquanto não há lista na tela
            self.search_job = None
            self.page = "idle"                 # idle, busy, empty ou list

            def scan_button(parent):
                return ttk.Button(parent, text=self.words["scan"], style="Pilula.TButton",
                                  command=lambda: app.start_scan(kind))

            self.pages = {
                "idle": status_page(body, icon("busca", 128, FG, 0.5), IDLE_TITLE,
                                    self.words["idle"], scan_button)[0],
                "empty": status_page(body, icon("ok", 128, FG, 0.5), self.words["empty"])[0],
                "list": ttk.Frame(body)}
            for page in self.pages.values():
                page.grid(row=0, column=0, sticky="nsew")

            page = self.pages["list"]
            bar = ttk.Frame(page, padding=(px(10), px(8)))
            bar.pack(fill="x")
            self.menu = tk.Menu(root, tearoff=False)
            self.app_var = tk.IntVar(value=0)
            self.drop = ttk.Menubutton(bar, text=ALL_APPS, style="Lista.TMenubutton",
                                       image=icon("seta"), compound="right", menu=self.menu,
                                       takefocus=False)
            self.drop.pack(side="left", fill="y")
            field = ttk.Frame(bar, style="Campo.TFrame", padding=(px(9), px(2)))
            field.pack(side="left", fill="both", expand=True, padx=(px(8), 0))
            ttk.Label(field, image=icon("busca", 16, T["fg_dim"]),
                      style="Campo.TLabel").pack(side="left")
            self.search_var = tk.StringVar()
            self.search = ttk.Entry(field, textvariable=self.search_var, style="Campo.TEntry")
            self.search.pack(side="left", fill="both", expand=True, padx=(px(6), 0))
            self.search.bind("<FocusIn>", lambda _event: field.state(["focus"]))
            self.search.bind("<FocusOut>", lambda _event: field.state(["!focus"]))
            # dica dentro do campo, visível enquanto ele está vazio
            self.hint = tk.Label(self.search, text=self.words["hint"], bd=0, bg=FIELD,
                                 fg=mix(FIELD, FG, 0.5), font=F["base"], cursor="xterm")
            self.hint.place(x=px(3), rely=0.5, anchor="w")
            self.hint.bind("<Button-1>", lambda _event: self.search.focus_set())
            self.search_var.trace_add("write", self.on_search)
            separator(page).pack(fill="x")

            table = ttk.Frame(page)
            table.pack(fill="both", expand=True)
            self.tree = ttk.Treeview(table, columns=[col for _t, col, _s, _w in self.columns],
                                     show="headings", selectmode="extended",
                                     style="Lista.Treeview")
            for title, col, _sort, width in self.columns:
                self.tree.heading(col, text=title, anchor="w",
                                  command=lambda c=col: self.sort_by(c))
                self.tree.column(col, width=px(width or 300), minwidth=px(70),
                                 stretch=not width, anchor="w")
            scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview,
                                   style="Rolagem.Vertical.TScrollbar")

            def scrolled(first, last):             # a barra só aparece se há o que rolar
                if float(first) <= 0 and float(last) >= 1:
                    scroll.pack_forget()
                elif not scroll.winfo_ismapped():
                    scroll.pack(side="right", fill="y", before=self.tree)
                scroll.set(first, last)

            self.tree.configure(yscrollcommand=scrolled)
            self.tree.pack(side="left", fill="both", expand=True)
            self.tree.bind("<<TreeviewSelect>>", lambda _event: app.update_footer())
            for key in ("<Control-a>", "<Control-A>"):
                self.tree.bind(key, lambda _event: self.tree.selection_set(self.visible))
            self.tree.bind("<Escape>", lambda _event: self.tree.selection_set(()))

        def frame(self):
            """A página desta aba que deve ficar à mostra."""
            return self.app.pages["busy"] if self.page == "busy" else self.pages[self.page]

        def fill(self, items):
            self.tree.delete(*(str(i) for i in range(len(self.items))))
            self.items = items
            self.hay = [search_text(item) for item in items]
            for i, item in enumerate(items):
                self.tree.insert("", "end", iid=str(i), values=row_values(item, self.kind))
            counts = Counter(item.app for item in items)
            self.app_choices = [None] + sorted(counts)
            if self.app_selected not in counts:
                self.app_selected = None
            labels = [ALL_APPS] + [f"{app} ({fmt_num(counts[app])})"
                                   for app in self.app_choices[1:]]
            self.menu.delete(0, "end")
            for index, label in enumerate(labels):
                self.menu.add_radiobutton(label=label, variable=self.app_var, value=index,
                                          command=self.on_app)
            index = self.app_choices.index(self.app_selected)
            self.app_var.set(index)
            self.drop.configure(text=labels[index])
            self.refilter()
            if items:
                self.page = "list"
            else:
                self.page = "empty"
                self.status = self.words["empty_note"]

        def footer(self):
            if self.page != "list":
                return self.status
            sess = sum(1 for item in self.items
                       if getattr(item, "store", "") == STORE_SESSION)
            return footer_text(len(self.items), len(self.visible), len(self.picked()), sess,
                               self.kind)

        # ---- filtro e ordenação
        def refilter(self):
            app, needle = self.app_selected, self.needle
            rows = [i for i, item in enumerate(self.items)
                    if (not app or item.app == app) and (not needle or needle in self.hay[i])]
            if self.sort_col:
                attr = next(sort for _t, col, sort, _w in self.columns if col == self.sort_col)
                rows.sort(key=lambda i: getattr(self.items[i], attr).casefold(),
                          reverse=self.sort_desc)
            self.visible = [str(i) for i in rows]
            keep = self.picked()
            self.tree.set_children("", *self.visible)
            self.tree.selection_set(keep)
            self.app.update_footer()

        def picked(self):
            shown = set(self.visible)
            return [iid for iid in self.tree.selection() if iid in shown]

        def sort_by(self, col):
            self.sort_desc = self.sort_col == col and not self.sort_desc
            self.sort_col = col
            for title, other, _sort, _width in self.columns:
                arrow = ("  ▼" if self.sort_desc else "  ▲") if other == col else ""
                self.tree.heading(other, text=title + arrow)
            self.refilter()

        def on_search(self, *_):
            if self.search_var.get():
                self.hint.place_forget()
            else:
                self.hint.place(x=px(3), rely=0.5, anchor="w")
            if self.search_job:
                root.after_cancel(self.search_job)
            self.search_job = root.after(150, self.apply_search)

        def apply_search(self):
            self.search_job = None
            self.needle = self.search_var.get().strip().lower()
            self.refilter()

        def on_app(self):
            index = self.app_var.get()
            self.app_selected = self.app_choices[index]
            self.drop.configure(text=self.menu.entrycget(index, "label"))
            self.refilter()

    TAB_ICONS = {"inicio": "inicio", COOKIES: "lista", PASSWORDS: "senha", "config": "ajustes"}

    class App:
        def __init__(self):
            self.busy = False
            self.rules = load_rules(home)
            self.rules_window = None
            self.settings = load_settings(home)
            sync_autostart(self.settings, home)    # o programa pode ter mudado de pasta
            self.tab = "inicio"
            # os botões do cabeçalho falam da aba Senhas quando ela está aberta e dos
            # cookies no resto do tempo
            self.kind = COOKIES
            self.bar_tips: list[str] = []
            self.bar_step = 1
            self.bar_hover = None
            self.start_job = None
            self.glow_size = None
            self.glow_job = None
            self.spin_job = None
            self.results: queue.Queue = queue.Queue()
            self._build()
            self._poll()

        # ---- montagem
        def _build(self):
            # cabeçalho: Verificar e Limpeza automática à esquerda, abas no meio, Eliminar
            # à direita (como o Adw.HeaderBar)
            header = ttk.Frame(root, height=px(52))
            header.pack(fill="x")
            header.pack_propagate(False)
            start = ttk.Frame(header)
            start.pack(side="left", padx=(px(9), 0))
            self.btn_scan = ttk.Button(start, text=KIND_TEXTS[COOKIES]["scan"],
                                       style="Principal.TButton", takefocus=False,
                                       command=lambda: self.start_scan(self.kind))
            self.btn_scan.pack(side="left")
            rules = ttk.Button(start, image=icon("alarme"), style="Plano.TButton",
                               takefocus=False, command=self.show_rules)
            rules.pack(side="left", padx=(px(6), 0))
            tooltip(rules, "Limpeza automática")
            self.btn_delete = ttk.Button(header, text=KIND_TEXTS[COOKIES]["delete"],
                                         style="Eliminar.TButton", takefocus=False,
                                         command=self.ask_delete)
            self.btn_delete.state(["disabled"])
            self.btn_delete.pack(side="right", padx=(0, px(9)))
            tabs = ttk.Frame(header)
            tabs.place(relx=0.5, rely=0.5, anchor="center")
            self.tab_var = tk.StringVar(value=self.tab)
            for index, (key, text) in enumerate(TABS):
                tabs.columnconfigure(index, uniform="aba", minsize=px(120))
                ttk.Radiobutton(tabs, text=text, image=icon(TAB_ICONS[key]), compound="left",
                                value=key, variable=self.tab_var, style="Aba.TRadiobutton",
                                takefocus=False,
                                command=lambda k=key: self.select_tab(k)).grid(
                    row=0, column=index, sticky="nsew", padx=px(2))

            footer = ttk.Frame(root, style="Rodape.TFrame", padding=(px(10), px(6)))
            footer.pack(side="bottom", fill="x")
            self.footer = ttk.Label(footer, text="Pronto.", style="Rodape.TLabel", anchor="w")
            self.footer.pack(fill="x")
            self.footer.bind("<Configure>",
                             lambda event: self.footer.configure(wraplength=event.width))
            separator(root).pack(side="bottom", fill="x")

            body = self.body = ttk.Frame(root)
            body.pack(fill="both", expand=True)
            body.rowconfigure(0, weight=1)
            body.columnconfigure(0, weight=1)
            busy, column = status_page(body, None, "Trabalhando…")
            self.spinner = ttk.Label(column)
            self.spinner.pack(pady=(px(30), 0))
            self.pages = {"start": self.start_page(body), "busy": busy,
                          "config": self.settings_page(body)}
            for page in self.pages.values():
                page.grid(row=0, column=0, sticky="nsew")
            self.lists = {kind: ListTab(self, kind, body) for kind in (COOKIES, PASSWORDS)}
            self.select_tab("inicio")

        # ---- abas
        def select_tab(self, tab):
            self.tab = tab
            self.tab_var.set(tab)
            if tab == "inicio":
                self.refresh_stats()               # limpezas automáticas contam também
            if tab in self.lists:
                self.lists[tab].frame().tkraise()
            else:
                self.pages["start" if tab == "inicio" else "config"].tkraise()
            self.kind = tab if tab in self.lists else COOKIES
            self.btn_scan.configure(text=KIND_TEXTS[self.kind]["scan"])
            self.btn_delete.configure(text=KIND_TEXTS[self.kind]["delete"])
            self.update_footer()

        # ---- página inicial: brilho atrás do título, monitor, cartões e nota
        def start_page(self, parent):
            page = ttk.Frame(parent)
            canvas = self.start_canvas = tk.Canvas(page, bg=BG, highlightthickness=0, bd=0)
            canvas.pack(fill="both", expand=True)
            self.glow_item = canvas.create_image(0, 0, anchor="center")
            self.hero_item = canvas.create_text(0, 0, text=APP_NAME, font=F["hero"], fill=FG,
                                                anchor="n")
            self.intro_item = canvas.create_text(0, 0, text=START_TEXT, font=F["intro"],
                                                 fill=T["fg_dim"], anchor="n",
                                                 justify="center")
            self.monitor_box = self.monitor(canvas)
            self.monitor_item = canvas.create_window(0, 0, window=self.monitor_box,
                                                     anchor="n")
            self.cards_box = ttk.Frame(canvas)
            commands = (lambda: self.start_scan(COOKIES), lambda: self.start_scan(PASSWORDS),
                        self.show_rules)
            for index, (badge, (title, text, state), command) in enumerate(zip(
                    ("busca", "senha", "alarme"), START_CARDS, commands)):
                card, self.rules_state = self.card(self.cards_box, badge, title, text,
                                                   state or rules_summary(self.rules),
                                                   command, primary=index == 0)
                card.grid(row=0, column=index, sticky="nsew",
                          padx=(px(7) if index else 0, px(7) if index < 2 else 0))
                self.cards_box.columnconfigure(index, weight=1, uniform="cartao")
            # self.rules_state ficou com o último cartão, o das regras
            self.cards_item = canvas.create_window(0, 0, window=self.cards_box, anchor="n")
            self.note_item = canvas.create_text(0, 0, text=START_NOTE, font=F["small"],
                                                fill=T["fg_muted"], anchor="n")
            sizes = {}

            def resized(event):
                # mover o painel também gera <Configure>: só o tamanho novo interessa
                size = (event.width, event.height)
                if sizes.get(str(event.widget)) != size:
                    sizes[str(event.widget)] = size
                    self.place_start()

            for widget in (canvas, self.monitor_box, self.cards_box):
                widget.bind("<Configure>", resized, add="+")
            return page

        def place_start(self):
            if not self.start_job:
                self.start_job = root.after_idle(self._place_start)

        def _place_start(self):
            """Centra a coluna (até 780 px) e põe o brilho atrás do título, como o
            radial-gradient(circle at 50% 12%, ..., transparent 38%) da janela GTK."""
            self.start_job = None
            canvas = self.start_canvas
            width, height = canvas.winfo_width(), canvas.winfo_height()
            if width < 2 or height < 2:
                return
            column = min(px(780), width - px(48))
            canvas.itemconfigure(self.monitor_item, width=column)
            canvas.itemconfigure(self.cards_item, width=column)

            def tall(item):
                _x0, top, _x1, bottom = canvas.bbox(item)
                return bottom - top

            parts = [(self.hero_item, px(6), tall(self.hero_item)),
                     (self.intro_item, px(8), tall(self.intro_item)),
                     (self.monitor_item, px(30), self.monitor_box.winfo_reqheight()),
                     (self.cards_item, px(14), self.cards_box.winfo_reqheight()),
                     (self.note_item, px(26), tall(self.note_item))]
            y = max(px(24), (height - sum(gap + size for _item, gap, size in parts)) // 2)
            for item, gap, size in parts:
                y += gap
                if canvas.coords(item) != [float(width // 2), float(y)]:
                    canvas.coords(item, width // 2, y)
                y += size

            radius = 0.38 * math.hypot(width / 2, height * 0.88)
            if self.glow_job:
                root.after_cancel(self.glow_job)
            if self.glow_size is None:
                self.draw_glow(radius)
            else:                                  # redesenha quando parar de redimensionar
                self.glow_job = root.after(200, self.draw_glow, radius)
            canvas.coords(self.glow_item, width / 2, height * 0.12)

        def draw_glow(self, radius):
            self.glow_job = None
            step = 2                               # o brilho é suave: calcula 1/2 e amplia
            size = 2 * (int(radius / step) + 1)
            if size != self.glow_size:
                self.glow_size = size
                self.glow = tk.PhotoImage(master=root, data=base64.b64encode(glow_png(
                    size, radius / step, BG, T["accent"], 0.13)).decode("ascii")).zoom(step)
                self.start_canvas.itemconfigure(self.glow_item, image=self.glow)

        BAR, BAR_GAP, BAR_HEIGHT = 18, 8, 46

        def monitor(self, parent):
            """Painel com os cookies eliminados: última sessão, 7 dias e um gráfico por dia."""
            panel = ttk.Frame(parent, style="Painel.TFrame", padding=(px(18), px(16)))
            ttk.Label(panel, text="Cookies eliminados", style="Painel.TLabel").grid(
                row=0, column=0, columnspan=3, sticky="w", pady=(0, px(12)))
            self.stat_labels = {}
            for column, (key, title) in enumerate((("session", "Última sessão"),
                                                   ("week", "Últimos 7 dias"))):
                tile = ttk.Frame(panel, style="Linha.TFrame")
                tile.grid(row=1, column=column, sticky="sew", padx=(0, px(18)))
                panel.columnconfigure(column, weight=1, uniform="numeros")
                ttk.Label(tile, text=title, style="Painel.Rotulo.TLabel").pack(anchor="w")
                for name, look in ((key, "Painel.Numero.TLabel"),
                                   (key + "_note", "Painel.Nota.TLabel")):
                    self.stat_labels[name] = ttk.Label(tile, style=look)
                    self.stat_labels[name].pack(anchor="w")
            self.chart = tk.Canvas(panel, bg=SURFACE, highlightthickness=0, bd=0)
            self.chart.grid(row=1, column=2, sticky="se")
            self.chart.bind("<Motion>", self.on_chart)
            self.chart.bind("<Leave>", lambda _event: (hide_tip(), setattr(self, "bar_hover", None)))
            return panel

        def on_chart(self, event):
            """Dica com o valor do dia sob o ponteiro, como o tooltip das barras na GTK."""
            index = int(event.x // self.bar_step)
            if index != self.bar_hover and 0 <= index < len(self.bar_tips):
                self.bar_hover = index
                show_tip(self.bar_tips[index])

        def refresh_stats(self):
            view = stats_view(load_stats(home))
            for key in ("session", "session_note", "week", "week_note"):
                self.stat_labels[key].configure(text=view[key])
            bars = view["bars"]
            self.bar_tips = [tip_text for _label, _share, tip_text, _today in bars]
            width = max([px(self.BAR)] + [F["tiny_bold"].measure(label)
                                          for label, *_rest in bars])
            gap, floor = px(self.BAR_GAP), px(self.BAR_HEIGHT)
            self.bar_step = width + gap
            chart = self.chart
            chart.configure(width=len(bars) * width + (len(bars) - 1) * gap,
                            height=floor + px(4) + F["tiny"].metrics("linespace"))
            chart.delete("all")
            for index, (label, share, _tip, today) in enumerate(bars):
                middle = index * self.bar_step + width / 2
                if share:
                    tall, thick = max(px(2), round(floor * share)), px(self.BAR)
                    chart.create_image(middle, floor, anchor="s", image=picture(
                        ("barra", thick, tall),
                        lambda: bar_png(thick, tall, px(4), T["accent"])))
                else:                              # dia sem limpeza: só um traço
                    chart.create_rectangle(middle - px(self.BAR) / 2, floor - px(2),
                                           middle + px(self.BAR) / 2, floor, width=0,
                                           fill=T["border"])
                chart.create_text(middle, floor + px(4), text=label, anchor="n",
                                  font=F["tiny_bold"] if today else F["tiny"],
                                  fill=FG if today else T["fg_muted"])

        def card(self, parent, badge, title, text, state, command, primary=False):
            """Cartão clicável da página inicial. Devolve (cartão, rótulo da linha de estado)."""
            frame = ttk.Frame(parent, padding=px(18), cursor="hand2",
                              style="Cartao.Principal.TFrame" if primary else "Cartao.TFrame")
            image = picture(("selo", badge, px(20)), lambda: badge_png(
                px(20), px(9), px(10), T["accent"], badge))
            parts = [ttk.Label(frame, image=image, style="Cartao.TLabel"),
                     ttk.Label(frame, text=title, style="Cartao.TLabel"),
                     ttk.Label(frame, text=text, style="Cartao.Texto.TLabel", justify="left"),
                     ttk.Label(frame, text=state, style="Cartao.Estado.TLabel")]
            for part, gap in zip(parts, (0, px(12), px(6), px(10))):
                part.pack(anchor="w", pady=(gap, 0))
            def wrap(event):                       # o texto quebra na largura do cartão
                width = max(px(100), event.width - 2 * px(18))
                if str(parts[2].cget("wraplength")) != str(width):
                    parts[2].configure(wraplength=width)

            frame.bind("<Configure>", wrap, add="+")
            everything = [frame] + parts

            def paint(_event=None):
                x, y = root.winfo_pointerxy()
                under = root.winfo_containing(x, y)
                inside = under is not None and str(under).startswith(str(frame))
                for widget in everything:
                    widget.state(["hover" if inside else "!hover"])

            for widget in everything:
                widget.configure(cursor="hand2")
                widget.bind("<Enter>", paint)
                widget.bind("<Leave>", paint)
                widget.bind("<Button-1>", lambda _event: command())
            return frame, parts[3]

        # ---- ajustes (o Adw.PreferencesPage)
        def settings_page(self, parent):
            page = ttk.Frame(parent)
            column = ttk.Frame(page)
            column.place(relx=0.5, y=px(32), anchor="n", width=px(576))
            page.bind("<Configure>", lambda event: column.place_configure(
                width=min(px(576), event.width - px(24))))
            ttk.Label(column, text="Inicialização", style="Grupo.TLabel").pack(
                anchor="w", pady=(0, px(12)))
            startup = group_box(column)
            startup.pack(fill="x")
            self.setting_rows = {}
            rows = []
            for key, (title, text) in SETTING_TEXTS.items():
                row, suffix, labels = list_row(startup, title, text)
                var = tk.BooleanVar(value=self.settings[key])
                switch = ttk.Checkbutton(suffix, style="Chave.TCheckbutton", variable=var,
                                         takefocus=False,
                                         command=lambda k=key: self.on_setting(k))
                switch.pack()
                self.setting_rows[key] = (var, switch, labels)
                rows.append(row)
            fill_group(startup, rows)
            ttk.Label(column, text="Sobre", style="Grupo.TLabel").pack(
                anchor="w", pady=(px(24), px(12)))
            about = group_box(column)
            about.pack(fill="x")
            fill_group(about, [list_row(about, APP_NAME, f"Versão {APP_VERSION}")[0]])
            self.paint_settings()
            return page

        def setting_usable(self, key):
            """Abrir minimizado só vale com o início com o sistema ligado."""
            return key != "iniciar_minimizado" or self.settings["iniciar_com_sistema"]

        def paint_settings(self):
            for key, (var, switch, labels) in self.setting_rows.items():
                var.set(self.settings[key])
                state = ["!disabled" if self.setting_usable(key) else "disabled"]
                for widget in [switch] + labels:
                    widget.state(state)

        def on_setting(self, key):
            self.settings[key] = self.setting_rows[key][0].get()
            self.paint_settings()
            warnings = save_settings(self.settings, home)
            if warnings:
                self.dialog("Configuração não aplicada", "\n".join(warnings),
                            [("ok", "Entendi", "Dialogo.TButton")])

        # ---- limpeza automática (o Adw.Dialog com as regras)
        def show_rules(self):
            if self.rules_window and self.rules_window.winfo_exists():
                self.rules_window.lift()
                self.rules_window.focus_set()
                return
            when_keys = [key for key, _label in WHEN_LABELS]
            top = self.rules_window = tk.Toplevel(root, bg=BG)
            top.withdraw()
            top.title("Limpeza automática")
            top.transient(root)
            canvas = tk.Canvas(top, bg=BG, highlightthickness=0, bd=0)
            scroll = ttk.Scrollbar(top, orient="vertical", command=canvas.yview,
                                   style="Rolagem.Vertical.TScrollbar")
            canvas.configure(yscrollcommand=scroll.set)
            canvas.pack(side="left", fill="both", expand=True)
            column = ttk.Frame(canvas, padding=(px(30), px(24)))
            item = canvas.create_window(0, 0, window=column, anchor="nw")

            def fit(_event=None):
                width, tall = canvas.winfo_width(), column.winfo_reqheight()
                canvas.itemconfigure(item, width=width)
                canvas.configure(scrollregion=(0, 0, width, tall))
                if tall > canvas.winfo_height():
                    if not scroll.winfo_ismapped():
                        scroll.pack(side="right", fill="y", before=canvas)
                elif scroll.winfo_ismapped():
                    scroll.pack_forget()
                    canvas.yview_moveto(0)

            def wheel(event):
                if column.winfo_reqheight() > canvas.winfo_height():
                    up = event.num == 4 or getattr(event, "delta", 0) > 0
                    canvas.yview_scroll(-1 if up else 1, "units")

            canvas.bind("<Configure>", fit)
            column.bind("<Configure>", fit)
            for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                top.bind(sequence, wheel)

            ttk.Label(column, text="Nova regra", style="Grupo.TLabel").pack(anchor="w")
            ttk.Label(column, text=RULES_TEXT, style="Descricao.TLabel",
                      justify="left", wraplength=px(490)).pack(anchor="w", pady=(px(2), px(12)))
            form = group_box(column)
            form.pack(fill="x")

            def entry_row(title, text=""):
                """Linha com campo de texto (o Adw.EntryRow): título pequeno em cima."""
                row = ttk.Frame(form, style="Linha.TFrame", padding=(0, px(7)))
                ttk.Label(row, text=title, style="LinhaSub.TLabel").pack(anchor="w")
                entry = ttk.Entry(row, style="Linha.TEntry")
                entry.insert(0, text)
                entry.pack(fill="x")
                row.bind("<Button-1>", lambda _event: entry.focus_set())
                return row, entry

            def combo_row(title, labels, changed=None):
                """Linha com escolha (o Adw.ComboRow): clique abre a lista de opções."""
                row, suffix, parts = list_row(form, title)
                var = tk.IntVar(value=0)
                value = ttk.Label(suffix, text=labels[0], style="Linha.TLabel")
                value.pack(side="left", padx=(0, px(8)))
                arrow = ttk.Label(suffix, image=icon("seta"), style="Linha.TLabel")
                arrow.pack(side="left")
                menu = tk.Menu(row, tearoff=False)

                def pick():
                    value.configure(text=labels[var.get()])
                    if changed:
                        changed()

                for index, label in enumerate(labels):
                    menu.add_radiobutton(label=label, variable=var, value=index, command=pick)
                for widget in [row, suffix, value, arrow] + parts:
                    widget.configure(cursor="hand2")
                    widget.bind("<Button-1>", lambda _event: menu.tk_popup(
                        value.winfo_rootx(), value.winfo_rooty() + value.winfo_height()))
                return row, var

            sites_row, sites = entry_row("Sites, separados por vírgula (vazio = todos)")
            what_row, what = combo_row("O que limpar", [label for _kinds, label in WHAT_LABELS])
            hour_row, hour = entry_row("Horário (HH:MM)", "08:00")

            def on_when():                         # o horário só aparece quando vale
                rows = [sites_row, what_row, when_row]
                if when_keys[when.get()] == WHEN_TIME:
                    rows.append(hour_row)
                fill_group(form, rows)

            when_row, when = combo_row("Quando", [label for _key, label in WHEN_LABELS],
                                       on_when)
            on_when()
            add = ttk.Button(column, text="Adicionar regra", style="Principal.TButton")
            add.pack(anchor="e", pady=(px(12), 0))
            ttk.Label(column, text="Regras", style="Grupo.TLabel").pack(
                anchor="w", pady=(px(24), px(12)))
            listing = group_box(column)
            listing.pack(fill="x")

            def save():
                warnings = save_rules(self.rules, home)
                self.rules_state.configure(text=rules_summary(self.rules))
                if warnings:
                    self.dialog("Agendamento incompleto", "\n".join(warnings),
                                [("ok", "Entendi", "Dialogo.TButton")], parent=top)

            def refresh():
                for child in listing.winfo_children():
                    child.destroy()
                group_lines.pop(str(listing), None)
                runs = last_runs(home)
                rows = []
                for rule in self.rules:
                    detail = f"{rule_what_text(rule)} · {rule_when_text(rule)}"
                    if rule["id"] in runs:
                        detail += "\nÚltima limpeza em " + runs[rule["id"]]
                    row, suffix, _labels = list_row(listing, rule_sites_text(rule), detail,
                                                    wrap=360)
                    active = tk.BooleanVar(value=rule["ativa"])
                    switch = ttk.Checkbutton(suffix, style="Chave.TCheckbutton",
                                             variable=active, takefocus=False,
                                             command=lambda r=rule, v=active: on_toggle(r, v))
                    switch.pack(side="left")
                    tooltip(switch, "Regra ativa")
                    trash = ttk.Button(suffix, image=icon("lixeira"), takefocus=False,
                                       style="Linha.Plano.TButton",
                                       command=lambda r=rule: on_remove(r))
                    trash.pack(side="left", padx=(px(6), 0))
                    tooltip(trash, "Remover regra")
                    rows.append(row)
                if not self.rules:
                    rows.append(list_row(listing, "Nenhuma regra ainda",
                                         "Crie a primeira acima.")[0])
                fill_group(listing, rows)

            def on_toggle(rule, active):
                rule["ativa"] = active.get()
                save()

            def on_remove(rule):
                hide_tip()
                self.rules.remove(rule)
                save()
                refresh()

            def on_add(_event=None):
                rule, error = new_rule(sites.get(), when_keys[when.get()], hour.get(),
                                       WHAT_LABELS[what.get()][0])
                if rule is None:
                    toast(top, error)
                    return
                self.rules.append(rule)
                sites.delete(0, "end")
                save()
                refresh()

            add.configure(command=on_add)
            sites.bind("<Return>", on_add)
            top.bind("<Escape>", lambda _event: top.destroy())
            refresh()
            place_over(top, root, px(560), px(640))
            if WINDOWS:
                _win_dark_titlebar(top)
            top.deiconify()
            sites.focus_set()

        # ---- diálogos (o Adw.AlertDialog)
        def dialog(self, heading, body, buttons, answer=None, parent=None):
            """Diálogo modal. buttons: [(resposta, texto, estilo)]; a primeira vale para o Esc."""
            parent = parent or root
            top = tk.Toplevel(parent, bg=SURFACE)
            top.withdraw()
            top.title(APP_NAME)
            top.transient(parent)
            top.resizable(False, False)
            box_ = ttk.Frame(top, style="Dialogo.TFrame", padding=px(24))
            box_.pack(fill="both", expand=True)
            text = dict(justify="center", anchor="center", wraplength=px(324))
            ttk.Label(box_, text=heading, style="Dialogo.Titulo.TLabel", **text).pack(fill="x")
            ttk.Label(box_, text=body, style="Dialogo.TLabel", **text).pack(
                fill="x", pady=(px(10), px(24)))
            row = ttk.Frame(box_, style="Dialogo.TFrame")
            row.pack(fill="x")

            def close(response):
                top.destroy()
                if answer:
                    answer(response)

            for index, (response, label, look) in enumerate(buttons):
                row.columnconfigure(index, weight=1, uniform="resposta")
                ttk.Button(row, text=label, style=look, takefocus=False,
                           command=lambda r=response: close(r)).grid(
                    row=0, column=index, sticky="ew", padx=(px(12) if index else 0, 0))
            top.protocol("WM_DELETE_WINDOW", lambda: close(buttons[0][0]))
            top.bind("<Escape>", lambda _event: close(buttons[0][0]))
            top.update_idletasks()
            place_over(top, parent, max(top.winfo_reqwidth(), px(372)))
            if WINDOWS:
                _win_dark_titlebar(top, SURFACE)
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

        SPIN_FRAMES = 12

        def spin(self, step=0):
            """Gira o indicador da página "Trabalhando…" enquanto houver trabalho."""
            if not self.busy:
                self.spin_job = None
                return
            size = px(32)
            turn = step % self.SPIN_FRAMES
            self.spinner.configure(image=picture(("roda", size, turn), lambda: spinner_png(
                size, FG, turn / self.SPIN_FRAMES)))
            self.spin_job = root.after(1000 // self.SPIN_FRAMES, self.spin, step + 1)

        def set_busy(self, busy, kind, text=""):
            self.busy = busy
            self.btn_scan.state(["disabled" if busy else "!disabled"])
            self.btn_delete.state(["disabled"])
            if busy:
                current = self.lists[kind]
                current.status = text
                current.page = "busy"
                if not self.spin_job:
                    self.spin()
                self.select_tab(kind)

        def update_footer(self):
            current = self.lists[self.kind]
            self.footer.configure(text=current.footer())
            self.btn_delete.state(["!disabled" if current.page == "list" and current.visible
                                   and not self.busy else "disabled"])

        # ---- verificar
        def start_scan(self, kind):
            if self.busy:
                return
            self.set_busy(True, kind, KIND_TEXTS[kind]["busy"])
            self.work(lambda: (scan_safely(home, kind),),
                      lambda result: self.scan_done(kind, result))

        def scan_done(self, kind, result):
            items, warnings = result
            self.set_busy(False, kind)
            self.lists[kind].fill(items)
            self.select_tab(kind)
            if warnings:
                self.dialog("Alguns locais não puderam ser lidos", "\n".join(warnings),
                            [("ok", "Entendi", "Dialogo.TButton")])

        # ---- eliminar
        def ask_delete(self):
            if self.busy:
                return
            kind, current = self.kind, self.lists[self.kind]
            picked = current.picked()
            rows = picked or current.visible
            if not rows:
                return
            targets = [current.items[int(iid)] for iid in rows]
            self.select_tab(kind)                  # a lista de que a pergunta fala
            heading, body = delete_question(targets, bool(picked), len(current.items), kind)
            self.dialog(heading, body, [("cancel", "Cancelar", "Dialogo.TButton"),
                                        ("delete", "Eliminar", "Dialogo.Destrutivo.TButton")],
                        lambda response: response == "delete"
                        and self.start_delete(kind, targets))

        def start_delete(self, kind, targets):
            if self.busy:
                return
            self.set_busy(True, kind, "Eliminando…")
            self.work(lambda: (delete_safely(targets, home, kind), scan_safely(home, kind)),
                      lambda outcome, result: self.delete_done(kind, outcome, result))

        def delete_done(self, kind, outcome, result):
            self.scan_done(kind, result)
            self.refresh_stats()
            toast(self.body, deleted_text(outcome["deleted"], kind))
            notes = delete_notes(outcome)
            if notes:
                self.dialog("Nem tudo foi eliminado", notes,
                            [("ok", "Entendi", "Dialogo.TButton")])

    App()
    root.geometry(f"{min(px(1200), root.winfo_screenwidth() - px(80))}"
                  f"x{min(px(680), root.winfo_screenheight() - px(120))}")
    root.minsize(px(960), px(560))
    if WINDOWS:
        icon_file = _resource("icone.ico")
        if icon_file:
            try:
                root.iconbitmap(default=icon_file)
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
