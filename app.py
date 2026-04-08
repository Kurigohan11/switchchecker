#!/usr/bin/env python3

from flask import Flask, request, jsonify, render_template, session
import paramiko
import socket
import time
import logging
import traceback
import re
import threading

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE = "switchpro.log"
_fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
_sh = logging.StreamHandler()
_fmt = logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s", "%Y-%m-%d %H:%M:%S")
_fh.setFormatter(_fmt); _sh.setFormatter(_fmt)

log = logging.getLogger("switchpro")
log.setLevel(logging.DEBUG)
log.addHandler(_fh); log.addHandler(_sh)

pk = logging.getLogger("paramiko")
pk.setLevel(logging.DEBUG); pk.addHandler(_fh); pk.propagate = False

app = Flask(__name__)
app.secret_key = "switchpro_v6"
log.info("=" * 60)
log.info("SwitchPro v6 запущен")

# ─── Switch profiles ──────────────────────────────────────────────────────────
SWITCH_PROFILES = {
    "cisco_sf300": {
        "display_name": "Cisco SF300",
        "detect_patterns": ["SF302","SF300-24","SF300-48","SF300",
                            "Cisco Small Business","Small Business Managed"],
        "prompt_patterns": ["sf300","sf302"],
        "port_types": ["fa","gi","fa1/0/","fa3/0/","gi1/0/","gi3/0/"],
        "default_port_type": "fa",
        "commands": {
            "show_all_ports": "sh int st",
            "mac_table":      "sh mac add int {port}",
            "cable_test":     "test cable-diagnostics tdr int {port}",
            "port_errors":    "sh int cou {port}",
            "clear_errors":   "clear cou {port}",
            "dhcp_bindings":  "sh ip dhcp snooping binding",
        },
    },
    "mes1124mb": {
        "display_name": "Eltex MES1124MB",
        "detect_patterns": ["MES1124MB","MES1124","MES 1124"],
        "prompt_patterns": ["mes1124mb","mes1124"],
        "port_types": ["fa","gi","fa1/0/","fa3/0/","gi1/0/","gi3/0/"],
        "default_port_type": "fa",
        "commands": {
            "show_all_ports": "sh int st",
            "mac_table":      "sh mac add int {port}",
            "cable_test":     "test cable-diagnostics tdr int {port}",
            "port_errors":    "sh int cou {port}",
            "clear_errors":   "clear cou {port}",
            "dhcp_bindings":  "sh ip dhcp snooping binding",
        },
    },
    "mes2324b": {
        "display_name": "Eltex MES2324B",
        "detect_patterns": ["MES2324B","MES2324","MES 2324B","MES 2324"],
        "prompt_patterns": ["mes2324b","mes2324"],
        "port_types": ["fa","gi","fa1/0/","fa3/0/","gi1/0/","gi3/0/"],
        "default_port_type": "fa",
        "commands": {
            "show_all_ports": "sh int st",
            "mac_table":      "sh mac add int {port}",
            "cable_test":     "test cable-diagnostics tdr int {port}",
            "port_errors":    "sh int cou {port}",
            "clear_errors":   "clear cou {port}",
            "dhcp_bindings":  "sh ip dhcp snooping binding",
        },
    },
    "mes2424b_ac": {
        "display_name": "Eltex MES2424B AC",
        "detect_patterns": ["ESF3"],
        "prompt_patterns": [],
        "hw_version": "3v1",
        "port_types": ["gi0/"],
        "default_port_type": "gi0/",
        "commands": {
            "show_all_ports": "show interfaces sta",
            "mac_table":      "sh mac int {port}",
            "cable_test":     "test cable-diagnostics {port}",
            "port_errors":    "show int cou {port}",
            "clear_errors":   "clear cou {port}",
            "dhcp_bindings":  "show ip binding",
        },
    },
    "mes2424b": {
        "display_name": "Eltex MES2424B 28port",
        "detect_patterns": ["MES2424B","MES2424","MES 2424B","MES 2424","ES9E"],
        "prompt_patterns": ["mes2424b","mes2424"],
        "hw_version": "1v3",
        "port_types": ["gi0/"],
        "default_port_type": "gi0/",
        "commands": {
            "show_all_ports": "show interfaces sta",
            "mac_table":      "sh mac int {port}",
            "cable_test":     "test cable-diagnostics {port}",
            "port_errors":    "show int cou {port}",
            "clear_errors":   "clear cou {port}",
            "dhcp_bindings":  "show ip binding",
        },
    },
    "linksys": {
        "display_name": "Linksys",
        "detect_patterns": ["Linksys","SRW224","SRW248","SRW2024",
                            "24-port 10/100 + 4-Port Gigabit",
                            "48-port 10/100 + 4-port Gigabit"],
        # Linksys через Telnet показывает "User Name:" — детектируется по баннеру
        "telnet_banner_marker": "user name:",
        "prompt_patterns": ["linksys","srw"],
        "port_types": ["e","g"],
        "default_port_type": "e",
        "commands": {
            "show_all_ports": "sh int st",
            "mac_table":      "sh mac add eth {port}",
            "cable_test":     "test c t {port}",
            "port_errors":    "sh int cou eth {port}",
            "clear_errors":   "clear cou eth {port}",
            "dhcp_bindings":  "sh ip dhcp snooping binding",
        },
    },
}

DETECT_COMMANDS = ["show version", "show system", "show system information"]

# ─── Persistent session cache ─────────────────────────────────────────────────
# Ключ: (host, username, protocol) → ShellSession или TelnetSession
_session_cache: dict = {}
_session_lock = threading.Lock()

def _cache_key(host, username, protocol):
    return f"{protocol}:{username}@{host}"

def _get_session(host, username, protocol):
    key = _cache_key(host, username, protocol)
    with _session_lock:
        sess = _session_cache.get(key)
        if sess:
            # Проверяем что сессия ещё жива
            try:
                if protocol == "ssh":
                    if sess.tr and sess.tr.is_active():
                        return sess
                else:  # telnet
                    if sess.tn and sess.tn.sock:
                        return sess
            except Exception:
                pass
            # Мёртвая сессия — убираем
            del _session_cache[key]
    return None

def _put_session(host, username, protocol, sess):
    key = _cache_key(host, username, protocol)
    with _session_lock:
        # Закрыть старую если есть
        old = _session_cache.get(key)
        if old and old is not sess:
            try: old.close()
            except Exception: pass
        _session_cache[key] = sess

def _drop_session(host, username, protocol):
    key = _cache_key(host, username, protocol)
    with _session_lock:
        sess = _session_cache.pop(key, None)
    if sess:
        try: sess.close()
        except Exception: pass

# ─── Helpers ──────────────────────────────────────────────────────────────────

def load_password(path="passwords.txt"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        log.error(f"Файл паролей не найден: {path}")
        return None

def check_tcp(host, port, timeout=5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close(); return True, None
    except socket.timeout:
        return False, f"Таймаут TCP {host}:{port}"
    except ConnectionRefusedError:
        return False, f"Порт {port} закрыт на {host}"
    except socket.gaierror as e:
        return False, f"DNS ошибка {host}: {e}"
    except OSError as e:
        return False, f"Сетевая ошибка: {e}"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return ""

def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*[mGKHFJA-Za-z]|\x1b\[?\d*[A-Za-z]|\r', '', text)

def _make_socket(host, port, source_ip, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if source_ip:
        try: s.bind((source_ip, 0))
        except OSError as e: log.warning(f"source_ip bind: {e}")
    s.settimeout(timeout)
    s.connect((host, port))
    return s

def match_model(text, prompt="", serial=""):
    combined = (prompt + "\n" + text + "\n" + serial).upper()
    if serial.upper().startswith("ESF"):
        log.info("Модель по серийнику ESF: mes2424b_ac")
        return "mes2424b_ac"
    for mk, p in SWITCH_PROFILES.items():
        if mk == "cisco_sf300": continue
        for pat in p.get("prompt_patterns", []):
            if pat.upper() in combined:
                log.info(f"Модель по prompt '{pat}': {mk}")
                return mk
    for mk, p in SWITCH_PROFILES.items():
        for pat in p["detect_patterns"]:
            if pat.upper() in combined:
                log.info(f"Модель по паттерну '{pat}': {mk}")
                return mk
    return None

def parse_serial(text):
    m = re.search(r'Hardware Serial Number\s*:\s*(\S+)', text, re.IGNORECASE)
    return m.group(1) if m else ""


# ─── SSH ShellSession ─────────────────────────────────────────────────────────

class ShellSession:
    def __init__(self, host, username, password,
                 enable_password=None, source_ip=None, timeout=20):
        self.host    = host
        self.timeout = timeout
        self.tr      = None
        self.ch      = None
        self.prompt  = ""

        tcp_ok, tcp_err = check_tcp(host, 22, timeout=min(timeout, 8))
        if not tcp_ok:
            raise ConnectionError(tcp_err)

        sock = _make_socket(host, 22, source_ip, timeout)
        self.tr = paramiko.Transport(sock)
        self.tr.set_keepalive(0)

        self.tr._preferred_kex = (
            'curve25519-sha256','curve25519-sha256@libssh.org',
            'ecdh-sha2-nistp256','ecdh-sha2-nistp384','ecdh-sha2-nistp521',
            'diffie-hellman-group14-sha256','diffie-hellman-group14-sha1',
            'diffie-hellman-group-exchange-sha256','diffie-hellman-group-exchange-sha1',
            'diffie-hellman-group1-sha1',
        )
        self.tr._preferred_ciphers = (
            'aes128-ctr','aes192-ctr','aes256-ctr',
            'aes128-cbc','aes192-cbc','aes256-cbc','3des-cbc',
        )
        self.tr._preferred_macs = ('hmac-sha2-256','hmac-sha2-512','hmac-sha1','hmac-md5',)
        self.tr._preferred_keys = (
            'ssh-rsa','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521',
            'ssh-ed25519','rsa-sha2-256','rsa-sha2-512','ssh-dss',
        )

        # Патч: разрешить ssh-dss (убран в paramiko 4.x, но нужен для старых свитчей)
        try:
            from paramiko.dsskey import DSSKey
            if 'ssh-dss' not in self.tr._key_info:
                self.tr._key_info['ssh-dss'] = DSSKey
                log.debug("DSS key support patched")
        except Exception as _dss_e:
            log.debug(f"DSS patch skipped: {_dss_e}")

        self.tr.start_client(timeout=timeout)

        try:
            self.tr.auth_password(username, password)
        except paramiko.AuthenticationException as e:
            err = str(e)
            # Проверяем если сервер требует только publickey
            if "publickey" in err.lower() or not self.tr.is_authenticated():
                # Попробуем получить список методов
                methods = []
                try:
                    self.tr.auth_none(username)
                except paramiko.BadAuthenticationType as bae:
                    methods = bae.allowed_types
                except Exception:
                    pass
                if methods and "password" not in methods:
                    raise paramiko.AuthenticationException(
                        f"SSH: сервер принимает только {methods}. "
                        f"Используй Telnet для этого свитча.")
            raise

        if not self.tr.is_authenticated():
            raise paramiko.AuthenticationException("Аутентификация не прошла")

        self.ch = self.tr.open_session()
        self.ch.settimeout(timeout)
        self.ch.get_pty(term='vt100', width=220, height=50)
        self.ch.invoke_shell()

        # Шлём Enter сразу, потом ждём баннер/промпт.
        time.sleep(0.5)
        self.ch.send("\n")
        banner = self._read(timeout=15, stop_on_patterns=["#",">","yes/no","password","assword","login:","username:","user name:"])
        log.debug(f"Banner [{host}]: {repr(strip_ansi(banner)[-150:])}")

        # Fingerprint
        if "yes/no" in banner.lower() or "authenticity" in banner.lower():
            log.info(f"Fingerprint [{host}] → yes")
            self.ch.send("yes\n"); time.sleep(0.3)
            banner += self._read(timeout=10, stop_on_patterns=["#",">","password","assword"])

        # Повторный запрос пароля
        if "password" in banner.lower() or "assword" in banner.lower():
            self.ch.send(password + "\n")
            banner += self._read(timeout=10, stop_on_patterns=["#",">"])

        self.prompt = self._extract_prompt(banner)
        # Если промпт пуст — ещё один Enter (на случай если свитч ждал второго)
        if not self.prompt:
            self.ch.send("\n")
            extra = self._read(timeout=8, stop_on_patterns=["#",">"])
            banner += extra
            self.prompt = self._extract_prompt(extra)
        log.info(f"Shell [{host}], промпт: '{self.prompt}'")

        if enable_password is not None:
            self._do_enable(enable_password)

        # Отключить пагинацию
        for cmd in ["terminal length 0", "terminal datadump"]:
            self.ch.send(cmd + "\n"); time.sleep(0.2)
            self._drain()

    def _extract_prompt(self, text):
        clean = strip_ansi(text)
        for line in reversed(clean.splitlines()):
            s = line.strip()
            # Промпт: "hostname#", "hostname> ", "hostname#  " и т.п.
            m = re.search(r'^(.*?)[#>]\s*$', s)
            if m and m.group(1).strip():
                return m.group(1).strip()
        return ""

    def _do_enable(self, pw):
        self.ch.send("enable\n"); time.sleep(0.3)
        buf = self._read(timeout=5, stop_on_patterns=["password","assword","#",">"])
        if "password" in buf.lower() or "assword" in buf.lower():
            self.ch.send(pw + "\n"); time.sleep(0.3)
            self._read(timeout=5, stop_on_patterns=["#",">"])
            log.info(f"Enable OK [{self.host}]")

    def _read(self, timeout=15, stop_on_prompt=True, stop_on_patterns=None,
              auto_more=False):
        """
        Читать данные с SSH-канала до промпта (#/>) или timeout.
        auto_more=True: автоматически нажимать пробел при появлении --More--.
        """
        patterns = stop_on_patterns or []
        buf = ""
        deadline = time.time() + timeout

        # Пробуем получить event из paramiko для быстрого ожидания данных
        _event = None
        try:
            _event = self.ch.in_buffer._event
        except Exception:
            pass

        while time.time() < deadline:
            if self.ch.recv_ready():
                try:
                    chunk = self.ch.recv(65536)
                    if not chunk:
                        break
                    buf += chunk.decode("utf-8", errors="replace")
                except Exception:
                    break

                clean = strip_ansi(buf).rstrip()

                # Обрабатываем --More-- / --more-- / -- More --
                if auto_more and re.search(r"-+\s*[Mm]ore\s*-+", clean):
                    self.ch.send(" ")   # пробел = следующая страница
                    # Убираем строку --More-- из буфера
                    buf = re.sub(r"\r?\n?\s*-+\s*[Mm]ore\s*-+\s*\r?", "", buf)
                    continue

                if stop_on_prompt and re.search(r"[#>]\s*$", clean):
                    break
                if patterns:
                    cl = clean.lower()
                    if any(p.lower() in cl for p in patterns):
                        break
            else:
                # Ждём данные: через event (мгновенно) или sleep
                if _event is not None:
                    _event.wait(timeout=min(0.5, deadline - time.time()))
                    _event.clear()
                else:
                    time.sleep(0.02)
        return buf

    def _drain(self, t=1.5):
        """Слить все данные из буфера канала (очистка после команды)."""
        dead = time.time() + t
        while time.time() < dead:
            remaining = dead - time.time()
            if remaining <= 0:
                break
            try:
                r, _, _ = select.select([self.ch], [], [], min(0.15, remaining))
            except Exception:
                break
            if r:
                try:
                    self.ch.recv(65536)
                except Exception:
                    break
            else:
                break

    def is_alive(self):
        try:
            return self.tr and self.tr.is_active() and not self.ch.closed
        except Exception:
            return False

    def run(self, command, extra_wait=0, auto_more=True):
        log.debug(f"run [{self.host}]: {command}")
        # Очищаем буфер от остатков предыдущей команды
        self._drain(t=0.3)
        self.ch.send(command + "\n")
        time.sleep(0.3 + extra_wait)
        raw = self._read(timeout=self.timeout, auto_more=auto_more)
        output = strip_ansi(raw)
        lines = []
        for line in output.splitlines():
            s = line.strip()
            if not s: continue
            if s.endswith('#') or s.endswith('>'): continue
            if command.strip() in s: continue
            lines.append(line)
        result = "\n".join(lines).strip() or "(нет вывода)"
        log.debug(f"[{command[:40]}]: {result[:200]}")
        return result

    def close(self):
        try:
            if self.ch and not self.ch.closed:
                self.ch.send("exit\n"); time.sleep(0.1)
        except Exception: pass
        try: self.ch.close()
        except Exception: pass
        try: self.tr.close()
        except Exception: pass


# ─── Telnet ───────────────────────────────────────────────────────────────────

class _Telnet:
    IAC=255; DONT=254; DO=253; WONT=252; WILL=251; SB=250; SE=240

    def __init__(self, host, port, timeout, source_ip=None):
        self.sock = _make_socket(host, port, source_ip, timeout)
        self._buf = b""

    def _negotiate(self, data):
        out = b""; i = 0
        while i < len(data):
            b = data[i]
            if b == self.IAC:
                if i+1 >= len(data): break
                cmd = data[i+1]
                if cmd in (self.DO, self.WILL, self.DONT, self.WONT):
                    if i+2 < len(data):
                        opt = data[i+2]
                        if cmd == self.DO:   r = self.WILL if opt==1 else self.WONT
                        elif cmd == self.WILL: r = self.DO if opt==1 else self.DONT
                        else: r = self.WONT if cmd==self.DONT else self.DONT
                        try: self.sock.sendall(bytes([self.IAC, r, opt]))
                        except Exception: pass
                        i += 3
                    else: i += 2
                elif cmd == self.SB:
                    end = data.find(bytes([self.IAC, self.SE]), i+2)
                    i = end+2 if end!=-1 else len(data)
                elif cmd == self.IAC:
                    out += bytes([self.IAC]); i += 2
                else: i += 2
            else:
                out += bytes([b]); i += 1
        return out

    def read_until_any(self, patterns, timeout=6, auto_more=False):
        """
        Читать до появления одного из паттернов или истечения timeout.
        auto_more=True: нажимает пробел при --More--.
        """
        deadline = time.time() + timeout

        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                self.sock.settimeout(min(0.3, max(0.05, remaining)))
                chunk = self.sock.recv(8192)
                if not chunk:
                    break
                self._buf += self._negotiate(chunk)
                text = self._buf.decode("utf-8", errors="replace")

                # Обрабатываем --More--
                if auto_more and re.search(r"-+\s*[Mm]ore\s*-+", text):
                    self.sock.sendall(b" ")
                    self._buf = re.sub(
                        rb"\r?\n?\s*-+\s*[Mm]ore\s*-+\s*\r?", b"",
                        self._buf)
                    continue

                dec = text.lower()
                for p in patterns:
                    if p.lower() in dec:
                        r = text
                        self._buf = b""
                        return r
            except socket.timeout:
                pass
            except OSError:
                break

        r = self._buf.decode("utf-8", errors="replace")
        self._buf = b""
        return r

    def writeln(self, text: str):
        self.sock.sendall(text.encode("utf-8", errors="replace") + b"\r\n")

    def close(self):
        try: self.sock.close()
        except Exception: pass


class TelnetSession:

    _LOGIN_P  = ["user name:", "login:", "username:", "user:"]
    _PASSWD_P = ["password:", "pass:", "assword:", "secret:"]
    _PROMPT_P = ["#", ">"]
    _ALL_P    = _LOGIN_P + _PASSWD_P + _PROMPT_P

    def __init__(self, host, username, password,
                 enable_password=None, source_ip=None, timeout=20):
        self.host    = host
        self.timeout = timeout
        self.prompt  = ""
        self._is_linksys = False

        tcp_ok, tcp_err = check_tcp(host, 23, timeout=min(timeout, 8))
        if not tcp_ok:
            raise ConnectionError(tcp_err)

        self.tn = _Telnet(host, 23, timeout=timeout, source_ip=source_ip)
        self._login(username, password, enable_password)

    def _has(self, text, pats):
        t = text.lower()
        return any(p in t for p in pats)

    def _login(self, username, password, enable_pw):
        # Ожидаем первый баннер
        banner = self.tn.read_until_any(["yes/no"] + self._ALL_P, timeout=12)
        log.debug(f"TelnetSession banner [{self.host}]: {repr(banner[-120:])}")

        # Fingerprint
        if "yes/no" in banner.lower():
            self.tn.writeln("yes"); time.sleep(0.3)
            banner = self.tn.read_until_any(self._ALL_P, timeout=8)

        # Linksys определяем по "User Name:" в баннере
        if "user name:" in banner.lower():
            self._is_linksys = True
            log.info(f"TelnetSession: Linksys обнаружен по 'User Name:' [{self.host}]")

        # Ввод логина
        if self._has(banner, self._LOGIN_P):
            log.debug(f"TelnetSession: логин [{self.host}]")
            self.tn.writeln(username); time.sleep(0.8)
            # После логина ждём только пароль
            banner = self.tn.read_until_any(self._PASSWD_P + self._PROMPT_P, timeout=10)
            log.debug(f"TelnetSession after-login [{self.host}]: {repr(banner[-80:])}")

        # Ввод пароля
        if self._has(banner, self._PASSWD_P):
            log.debug(f"TelnetSession: пароль [{self.host}]")
            self.tn.writeln(password); time.sleep(1.2)
            # После пароля ждём ТОЛЬКО промпт (#/>)
            banner = self.tn.read_until_any(self._PROMPT_P, timeout=15)
            log.debug(f"TelnetSession after-pass [{self.host}]: {repr(banner[-120:])}")

            # Если промпт не появился — проверяем если снова логин (неверный пароль)
            if not self._has(banner, self._PROMPT_P):
                if self._has(banner, self._LOGIN_P):
                    raise paramiko.AuthenticationException(
                        f"Telnet: неверный логин или пароль [{self.host}]")
                # Попробуем подождать ещё
                banner += self.tn.read_until_any(self._PROMPT_P + self._LOGIN_P, timeout=8)
                if self._has(banner, self._LOGIN_P) and not self._has(banner, self._PROMPT_P):
                    raise paramiko.AuthenticationException(
                        f"Telnet: вход не выполнен [{self.host}]")

        # Извлечь промпт
        for line in reversed(strip_ansi(banner).splitlines()):
            s = line.strip()
            if s and (s.endswith('#') or s.endswith('>')):
                self.prompt = re.sub(r'[#>].*$', '', s).strip(); break

        log.info(f"TelnetSession: вошли [{self.host}], промпт='{self.prompt}', linksys={self._is_linksys}")

        # Enable
        if enable_pw is not None:
            self.tn.writeln("enable"); time.sleep(0.3)
            en = self.tn.read_until_any(self._PASSWD_P + self._PROMPT_P, timeout=5)
            if self._has(en, self._PASSWD_P):
                self.tn.writeln(enable_pw); time.sleep(0.5)
                self.tn.read_until_any(self._PROMPT_P, timeout=5)

        # Пагинация
        self.tn.writeln("terminal length 0"); time.sleep(0.3)
        self.tn.read_until_any(self._PROMPT_P, timeout=3)

    def is_alive(self):
        try:
            self.tn.sock.settimeout(0.1)
            self.tn.sock.recv(0)
            return True
        except socket.timeout:
            return True
        except Exception:
            return False

    def _drain_buf(self, t=0.3):
        """Слить все данные из буфера сокета (остатки предыдущей команды)."""
        self.tn._buf = b""  # сначала очищаем внутренний буфер
        dead = time.time() + t
        while time.time() < dead:
            remaining = dead - time.time()
            try:
                self.tn.sock.settimeout(min(0.1, max(0.01, remaining)))
                chunk = self.tn.sock.recv(8192)
                if not chunk:
                    break
                # Обрабатываем IAC чтобы не сломать negotiation
                self.tn._negotiate(chunk)
            except socket.timeout:
                break
            except OSError:
                break

    def run(self, command, auto_more=True):
        log.debug(f"TelnetSession.run [{self.host}]: {command}")
        # Очищаем буфер от остатков предыдущей команды
        self._drain_buf()
        self.tn.writeln(command)
        raw = self.tn.read_until_any(self._PROMPT_P, timeout=self.timeout,
                                     auto_more=auto_more)
        output = strip_ansi(raw)
        lines = [l for l in output.splitlines()
                 if l.strip()
                 and command.strip() not in l
                 and not l.strip().endswith('#')
                 and not l.strip().endswith('>')]
        result = "\n".join(lines).strip()
        log.info(f"TelnetSession result [{self.host}]: {len(result)} байт")
        return result or "(нет вывода)"

    def close(self):
        try: self.tn.writeln("exit"); time.sleep(0.1)
        except Exception: pass
        self.tn.close()


# ─── Session factory (с кешем) ───────────────────────────────────────────────

def _open_session(host, username, password, protocol,
                  enable_password=None, source_ip=None, timeout=20):
    """Открыть или вернуть кешированную сессию."""
    # Пробуем кеш
    sess = _get_session(host, username, protocol)
    if sess:
        log.debug(f"Reusing cached session [{host}] proto={protocol}")
        return sess

    log.debug(f"Opening new session [{host}] proto={protocol}")
    if protocol == "telnet":
        sess = TelnetSession(host, username, password,
                             enable_password=enable_password,
                             source_ip=source_ip, timeout=timeout)
    else:
        sess = ShellSession(host, username, password,
                            enable_password=enable_password,
                            source_ip=source_ip, timeout=timeout)
    _put_session(host, username, protocol, sess)
    return sess


def _run_on_session(host, username, password, command, protocol,
                    enable_password=None, source_ip=None, timeout=20):
    """Выполнить команду используя кешированную или новую сессию."""
    try:
        sess = _open_session(host, username, password, protocol,
                             enable_password, source_ip, timeout)
        result = sess.run(command)
        return {"success": True, "output": result}
    except (ConnectionError, paramiko.AuthenticationException, paramiko.SSHException) as e:
        # При ошибке сессии — удаляем из кеша
        _drop_session(host, username, protocol)
        return {"success": False, "error": str(e)}
    except Exception as e:
        _drop_session(host, username, protocol)
        log.error(traceback.format_exc())
        return {"success": False, "error": f"{type(e).__name__}: {e}"}


# ─── Model detection ─────────────────────────────────────────────────────────

def detect_model(host, username, password, protocol="ssh",
                 enable_password=None, source_ip=None):
    log.info(f"Определение модели [{host}] proto={protocol}")

    if protocol == "telnet":
        # Шаг 1: прочитать баннер без входа — Linksys показывает "User Name:"
        try:
            tcp_ok, tcp_err = check_tcp(host, 23, timeout=6)
            if not tcp_ok:
                return None, tcp_err
            probe = _Telnet(host, 23, timeout=8, source_ip=source_ip)
            probe_banner = probe.read_until_any(
                ["user name:", "login:", "username:", "#", ">"], timeout=8)
            probe.close()
            log.debug(f"Probe banner [{host}]: {repr(probe_banner[-80:])}")
            if "user name:" in probe_banner.lower():
                log.info(f"Модель по telnet баннеру 'User Name:': linksys")
                return "linksys", None
        except Exception as e:
            log.debug(f"Telnet probe [{host}]: {e}")

        # Шаг 2: войти и выполнить команды определения
        sess = None
        try:
            sess = TelnetSession(host, username, password,
                                 enable_password=enable_password,
                                 source_ip=source_ip, timeout=20)
            # Если TelnetSession сама обнаружила Linksys — возвращаем сразу
            if sess._is_linksys:
                _put_session(host, username, protocol, sess)
                return "linksys", None

            prompt_hint = sess.prompt
            all_out = ""; serial = ""

            m = match_model("", prompt_hint, serial)
            if m:
                _put_session(host, username, protocol, sess)
                return m, None

            for cmd in DETECT_COMMANDS:
                out = sess.run(cmd)
                log.debug(f"[{cmd}] telnet: {out[:200]}")
                all_out += "\n" + out
                if not serial: serial = parse_serial(out)
                m = match_model(out, prompt_hint, serial)
                if m: break

            if m:
                _put_session(host, username, protocol, sess)
                return m, None

            m = match_model(all_out, prompt_hint, serial)
            if m:
                _put_session(host, username, protocol, sess)
                return m, None

            sess.close()
            return "unknown", f"Промпт: {prompt_hint}\n{all_out[:400]}"

        except paramiko.AuthenticationException as e:
            return None, str(e)
        except ConnectionError as e:
            return None, str(e)
        except Exception as e:
            log.error(traceback.format_exc())
            if sess:
                try: sess.close()
                except Exception: pass
            return None, f"Telnet ошибка: {e}"

    # SSH
    tcp_ok, tcp_err = check_tcp(host, 22, timeout=8)
    if not tcp_ok:
        return None, tcp_err

    try:
        sess = ShellSession(host, username, password,
                            enable_password=enable_password,
                            source_ip=source_ip, timeout=20)
        prompt_hint = sess.prompt
        all_out = ""; serial = ""

        m = match_model("", prompt_hint, serial)
        if m:
            _put_session(host, username, "ssh", sess)
            return m, None

        for cmd in DETECT_COMMANDS:
            out = sess.run(cmd)
            log.debug(f"[{cmd}]: {out[:250]}")
            all_out += "\n" + out
            if not serial: serial = parse_serial(out)
            m = match_model(out, prompt_hint, serial)
            if m: break

        if m:
            _put_session(host, username, "ssh", sess)
            return m, None

        m = match_model(all_out, prompt_hint, serial)
        if m:
            _put_session(host, username, "ssh", sess)
            return m, None

        sess.close()
        log.warning(f"Модель не определена [{host}]")
        return "unknown", f"Промпт: {prompt_hint}\nСерийник: {serial}\n{all_out[:600]}"

    except ConnectionError as e:
        return None, str(e)
    except paramiko.AuthenticationException as e:
        return None, str(e)
    except paramiko.SSHException as e:
        err = str(e)
        hint = ""
        if any(w in err.lower() for w in ("kex","no acceptable","host key","dss","publickey")):
            hint = (f"\n\nДобавь в ~/.ssh/config:\n  Host {host}\n"
                    f"    KexAlgorithms +diffie-hellman-group1-sha1\n"
                    f"    HostKeyAlgorithms +ssh-dss,ssh-rsa\n    Ciphers +aes128-cbc,3des-cbc\n"
                    f"Или попробуй подключение через Telnet.")
        return None, f"SSH ошибка: {err}{hint}"
    except Exception as e:
        log.error(traceback.format_exc())
        return None, f"{type(e).__name__}: {e}"


# ─── Flask routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/local_ip")
def local_ip():
    return jsonify({"ip": get_local_ip()})

@app.route("/api/log")
def get_log():
    n = int(request.args.get("lines", 150))
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return jsonify({"success": True, "log": "".join(lines[-n:])})
    except FileNotFoundError:
        return jsonify({"success": True, "log": "(пусто)"})


@app.route("/api/connect", methods=["POST"])
def connect():
    d = request.json
    host        = d.get("host","").strip()
    username    = d.get("username","").strip()
    pw_file     = d.get("password_file","passwords.txt").strip()
    protocol    = d.get("protocol","ssh")
    source_ip   = d.get("source_ip","").strip() or None
    use_enable  = d.get("use_enable", False)
    enable_same = d.get("enable_same", True)
    en_pw_file  = d.get("enable_pw_file","").strip()

    log.info(f"=== CONNECT host={host} user={username} proto={protocol} src={source_ip} enable={use_enable}")

    if not host or not username:
        return jsonify({"success": False, "error": "Укажите хост и логин"})

    password = load_password(pw_file)
    if password is None:
        return jsonify({"success": False, "error": f"Файл паролей не найден: {pw_file}"})

    enable_pw = None
    if use_enable:
        if enable_same:
            enable_pw = password
        elif en_pw_file:
            enable_pw = load_password(en_pw_file)
            if enable_pw is None:
                return jsonify({"success": False, "error": f"Файл enable-пароля не найден: {en_pw_file}"})
        else:
            enable_pw = password

    # Сбросить старую сессию для этого хоста если была
    _drop_session(host, username, protocol)

    model_key, error = detect_model(host, username, password,
                                    protocol=protocol, enable_password=enable_pw,
                                    source_ip=source_ip)
    if model_key is None:
        return jsonify({"success": False, "error": error})

    profile = SWITCH_PROFILES.get(model_key, {})
    model_name = profile.get("display_name", "Неизвестная модель")
    port_types = profile.get("port_types", ["fa"])
    default_pt = profile.get("default_port_type", port_types[0] if port_types else "fa")

    log.info(f"Подключено: {host} → {model_key} ({model_name})")

    return jsonify({
        "success":           True,
        "model_key":         model_key,
        "model_name":        model_name,
        "host":              host,
        "username":          username,
        "protocol":          protocol,
        "source_ip":         source_ip,
        "enable_password":   enable_pw,
        "port_types":        port_types,
        "default_port_type": default_pt,
        "raw_version":       error if model_key == "unknown" else None,
    })


@app.route("/api/run", methods=["POST"])
def run_action():
    d         = request.json
    host      = d.get("host")
    username  = d.get("username")
    pw_file   = d.get("password_file","passwords.txt")
    model_key = d.get("model_key","unknown")
    action    = d.get("action")
    port_num  = d.get("port_num","1")
    port_type = d.get("port_type","fa")
    protocol  = d.get("protocol","ssh")
    source_ip = d.get("source_ip") or None
    enable_pw = d.get("enable_password") or None

    password = load_password(pw_file)
    if password is None:
        return jsonify({"success": False, "error": "Файл паролей не найден"})

    profile = SWITCH_PROFILES.get(model_key)
    if not profile:
        return jsonify({"success": False, "error": f"Нет профиля: {model_key}"})

    tpl = profile["commands"].get(action)
    if not tpl:
        return jsonify({"success": False, "error": f"Действие '{action}' не поддерживается"})

    port = f"{port_type}{port_num}"
    command = tpl.format(port=port)
    log.info(f"RUN [{host}] action={action} port={port} cmd='{command}'")

    result = _run_on_session(host, username, password, command,
                             protocol=protocol, enable_password=enable_pw,
                             source_ip=source_ip)
    result["command"] = command
    return jsonify(result)


@app.route("/api/custom", methods=["POST"])
def custom():
    d         = request.json
    host      = d.get("host")
    username  = d.get("username")
    pw_file   = d.get("password_file","passwords.txt")
    command   = d.get("command","").strip()
    model_key = d.get("model_key","unknown")
    protocol  = d.get("protocol","ssh")
    source_ip = d.get("source_ip") or None
    enable_pw = d.get("enable_password") or None

    if not command:
        return jsonify({"success": False, "error": "Введите команду"})

    password = load_password(pw_file)
    if password is None:
        return jsonify({"success": False, "error": "Файл паролей не найден"})

    result = _run_on_session(host, username, password, command,
                             protocol=protocol, enable_password=enable_pw,
                             source_ip=source_ip)
    result["command"] = command
    return jsonify(result)


@app.route("/api/disconnect", methods=["POST"])
def disconnect():
    d        = request.json
    host     = d.get("host","")
    username = d.get("username","")
    protocol = d.get("protocol","ssh")

    log.info(f"DISCONNECT [{host}] proto={protocol}")
    _drop_session(host, username, protocol)
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
