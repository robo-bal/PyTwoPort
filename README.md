#!/usr/bin/env python3
"""
netscan_gui.py - LAN device scanner with Tkinter GUI
Windows only, Python 3.8+, standard library only (no pip installs).

Discovery pipeline, per target IP:
  1. On-link targets (inside any local adapter's subnet):
       Win32 SendARP() -> resolves the MAC at layer 2.
       This finds hosts even when their firewall drops ICMP (the default
       Windows firewall does). If ARP fails, nothing is there: ICMP can't
       reach an on-link host without ARP either. So ICMP is skipped for
       those addresses, which roughly halves sweep time.
     Off-link (routed) targets: ICMP only, and no MAC is available.
  2. Win32 IcmpSendEcho() -> round-trip time and reply TTL.
     The TTL gives a rough OS family guess. No ping.exe processes are
     spawned and no locale-dependent text is parsed.
  3. For live hosts only:
       - socket.gethostbyaddr(): Windows resolver (DNS, LLMNR, NetBIOS).
       - Raw NetBIOS NBSTAT query (UDP/137): NetBIOS name, workgroup, and
         adapter MAC (useful for routed hosts, where ARP isn't possible).
       - Optional TCP connect() probe of common ports, run in parallel per host.
  4. Vendor lookup from the MAC OUI:
       - A small built-in table.
       - The full IEEE MA-L registry, downloaded with the "Update OUI DB"
         button and cached as oui.csv next to this script.
       - Locally administered MACs (randomized phone/laptop MACs, VMs)
         are flagged as such.

Threading model:
  - One worker thread runs a ThreadPoolExecutor over the targets.
  - All Tk calls stay on the main thread. Workers post results to a
    queue.Queue, and the GUI drains it every 100 ms via after().

Run:  python netscan_gui.py
"""

import csv
import ctypes
import ipaddress
import os
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

if sys.platform != "win32":
    sys.exit("This tool binds to iphlpapi.dll and runs on Windows only.")

# ============================================================================
# Win32 bindings (iphlpapi.dll)
# ============================================================================
_iphlpapi = ctypes.WinDLL("iphlpapi.dll")


class IP_OPTION_INFORMATION(ctypes.Structure):
    """Mirrors IP_OPTION_INFORMATION from ipexport.h.
    ctypes applies native alignment, so the layout is correct on both
    32-bit and 64-bit Python (OptionsData is a pointer)."""
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),          # TTL of the *reply* packet
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    """Mirrors ICMP_ECHO_REPLY (the native layout, not the WOW64 *_32 variant)."""
    _fields_ = [
        ("Address", ctypes.c_ulong),        # replying address, network byte order
        ("Status", ctypes.c_ulong),         # IP_SUCCESS == 0
        ("RoundTripTime", ctypes.c_ulong),  # milliseconds
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


# HANDLE IcmpCreateFile(void)
_IcmpCreateFile = _iphlpapi.IcmpCreateFile
_IcmpCreateFile.argtypes = []
_IcmpCreateFile.restype = wintypes.HANDLE

# BOOL IcmpCloseHandle(HANDLE)
_IcmpCloseHandle = _iphlpapi.IcmpCloseHandle
_IcmpCloseHandle.argtypes = [wintypes.HANDLE]
_IcmpCloseHandle.restype = wintypes.BOOL

# DWORD IcmpSendEcho(HANDLE, IPAddr, LPVOID req, WORD reqSize,
#                    PIP_OPTION_INFORMATION, LPVOID reply, DWORD replySize, DWORD timeout)
_IcmpSendEcho = _iphlpapi.IcmpSendEcho
_IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, wintypes.WORD,
                          ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
_IcmpSendEcho.restype = wintypes.DWORD

# DWORD SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen)
_SendARP = _iphlpapi.SendARP
_SendARP.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                     ctypes.POINTER(ctypes.c_ulong)]
_SendARP.restype = wintypes.DWORD

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ICMP_PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"   # the same 32-byte pattern ping.exe sends
CREATE_NO_WINDOW = 0x08000000                        # hide the console flash for ipconfig


def _ip_to_ipaddr(ip: str) -> int:
    """Convert a dotted quad to a Win32 IPAddr: a ULONG holding the address
    bytes in network order. Native-endian unpack preserves the byte layout."""
    return struct.unpack("=I", socket.inet_aton(ip))[0]


def icmp_ping(ip: str, timeout_ms: int):
    """Send one ICMP echo request. Returns (ttl, rtt_ms), or None if there was
    no valid echo reply (timeout, unreachable, TTL expired, and so on)."""
    h = _IcmpCreateFile()
    if not h or h == INVALID_HANDLE_VALUE:
        return None
    try:
        req = ctypes.create_string_buffer(ICMP_PAYLOAD, len(ICMP_PAYLOAD))
        # MSDN: the reply buffer must hold 1 reply, the payload, and 8 bytes
        # for an ICMP error. Extra slack is added for safety.
        reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(ICMP_PAYLOAD) + 64
        reply_buf = ctypes.create_string_buffer(reply_size)
        n = _IcmpSendEcho(h, _ip_to_ipaddr(ip), req, len(ICMP_PAYLOAD),
                          None, reply_buf, reply_size, timeout_ms)
        if n == 0:
            return None
        reply = ICMP_ECHO_REPLY.from_buffer(reply_buf)
        if reply.Status != 0:              # anything but IP_SUCCESS is not an echo reply
            return None
        return reply.Options.Ttl, reply.RoundTripTime
    finally:
        _IcmpCloseHandle(h)


def arp_resolve(ip: str) -> str:
    """Resolve a MAC via SendARP. The ARP cache is checked first; otherwise a
    real ARP request goes out. It blocks about 3 s on no answer (OS retry
    policy), which is why the sweep uses a large thread pool.
    Returns 'AA:BB:CC:DD:EE:FF', or '' on failure."""
    mac = (ctypes.c_ubyte * 8)()
    ln = ctypes.c_ulong(8)
    if _SendARP(_ip_to_ipaddr(ip), 0, mac, ctypes.byref(ln)) != 0 or ln.value < 6:
        return ""
    return ":".join(f"{b:02X}" for b in mac[:6])


# ============================================================================
# Local adapter discovery
# ============================================================================
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}")


def normalize_mac(mac: str) -> str:
    return mac.upper().replace("-", ":")


def run_cmd(args, timeout=10) -> str:
    """Run a console tool hidden and return stdout. Output is decoded with the
    OEM codepage, which is what console tools emit on Windows."""
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW)
        return r.stdout.decode("oem", errors="ignore")
    except Exception:
        return ""


def get_local_interfaces():
    """Parse 'ipconfig /all' into [{'iface': IPv4Interface, 'mac': str}, ...].

    Adapter blocks start with a header line at column 0; property lines are
    indented. Matching relies on the 'IPv4' token, 255.x masks, and a MAC
    regex, so it works across most Windows display languages."""
    out = run_cmd(["ipconfig", "/all"])
    blocks, cur = [], []
    for line in out.splitlines():
        if line.strip() and not line[0].isspace():     # new adapter header
            if cur:
                blocks.append("\n".join(cur))
            cur = [line]
        else:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur))

    result = []
    for b in blocks:
        ips = re.findall(r"IPv4[^:\n]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", b)
        masks = re.findall(r":\s*(255\.\d{1,3}\.\d{1,3}\.\d{1,3})", b)
        m = MAC_RE.search(b)                            # 'Physical Address' precedes the DUID
        mac = normalize_mac(m.group(0)) if m else ""
        for i, ip in enumerate(ips):
            mask = masks[i] if i < len(masks) else "255.255.255.0"
            try:
                result.append({"iface": ipaddress.IPv4Interface(f"{ip}/{mask}"), "mac": mac})
            except ValueError:
                pass
    return result


def get_primary_ip() -> str:
    """IP of the adapter holding the default route. A UDP connect() only does
    a route lookup; no packet is sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# ============================================================================
# Per-host enrichment
# ============================================================================
def reverse_lookup(ip: str) -> str:
    """Windows resolver: DNS PTR, then LLMNR / NetBIOS depending on configuration."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def netbios_query(ip: str, timeout: float = 0.6):
    """Raw NBSTAT (node status) query to UDP/137, per RFC 1002.
    Returns (netbios_name, workgroup, mac); empty strings where unavailable."""
    tid = os.urandom(2)
    # Header: TID, flags=0, QDCOUNT=1, AN/NS/AR=0
    # QNAME: '*' padded with NULs to 16 bytes, first-level encoded
    #   ('*'=0x2A -> 'CK', 0x00 -> 'AA'), giving 32 chars with a 0x20 length prefix.
    # QTYPE=NBSTAT(0x21), QCLASS=IN(1)
    pkt = (tid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           + b"\x20" + b"CK" + b"A" * 30 + b"\x00" + b"\x00\x21\x00\x01")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (ip, 137))
            data, _ = s.recvfrom(2048)
    except OSError:
        return "", "", ""

    # Answer layout: 12 header + 34 name + 2 type + 2 class + 4 TTL + 2 RDLENGTH = 56.
    # Byte 56 is NUM_NAMES; then 18-byte entries (15 name, 1 suffix, 2 flags),
    # then the 6-byte unit ID (the adapter MAC).
    if len(data) < 57 or data[:2] != tid:
        return "", "", ""
    num = data[56]
    off = 57
    name = group = ""
    for _ in range(num):
        if off + 18 > len(data):
            break
        n = data[off:off + 15].decode("ascii", "ignore").strip()
        suffix = data[off + 15]
        flags = struct.unpack(">H", data[off + 16:off + 18])[0]
        off += 18
        if suffix == 0x00:                       # workstation service
            if flags & 0x8000:                   # G bit set: group name, i.e. the workgroup/domain
                group = group or n
            else:
                name = name or n
    mac = ""
    if off + 6 <= len(data):
        raw = data[off:off + 6]
        if any(raw):                             # Samba reports all zeros
            mac = ":".join(f"{b:02X}" for b in raw)
    return name, group, mac


# Ports chosen for mixed IT and embedded/industrial LANs
PROBE_PORTS = [(21, "ftp"), (22, "ssh"), (23, "telnet"), (53, "dns"), (80, "http"),
               (135, "msrpc"), (139, "netbios"), (443, "https"), (445, "smb"),
               (502, "modbus"), (554, "rtsp"), (1883, "mqtt"), (3389, "rdp"),
               (5900, "vnc"), (8080, "http-alt"), (8883, "mqtts"), (9100, "jetdirect")]


def _tcp_open(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_ports(ip: str, timeout: float = 0.4):
    """TCP connect() probe run in parallel per host. Worst case, when the host
    silently drops SYNs, is about 'timeout' seconds rather than N x timeout."""
    with ThreadPoolExecutor(max_workers=len(PROBE_PORTS)) as ex:
        res = list(ex.map(lambda p: (p, _tcp_open(ip, p[0], timeout)), PROBE_PORTS))
    return [f"{p}/{svc}" for (p, svc), ok in res if ok]


def ttl_guess(ttl) -> str:
    """Rough OS family from the reply TTL, assuming few hops on a LAN.
    Initial TTLs: 64 = Linux/Unix/macOS and many embedded stacks,
    128 = Windows, 255 = network gear and some RTOS/IP stacks."""
    if ttl in ("", None):
        return ""
    if ttl <= 64:
        return "Linux/Unix/embedded"
    if ttl <= 128:
        return "Windows"
    return "Net gear / RTOS"


def scan_host(ip: str, on_link: bool, opts: dict, stop: threading.Event):
    """Full probe of one IP. Returns a record dict, or None if nothing is there."""
    if stop.is_set():
        return None

    mac = ""
    if on_link:
        mac = arp_resolve(ip)
        if not mac:
            return None                           # no L2 presence, so skip ICMP

    ping = icmp_ping(ip, opts["timeout"])
    if not mac and ping is None:
        return None

    ttl, rtt = ping if ping else ("", "")
    if mac and ping:
        via = "ARP + ICMP"
    elif mac:
        via = "ARP only (ICMP filtered)"
    else:
        via = "ICMP (routed)"

    hostname = reverse_lookup(ip) if opts["dns"] else ""
    nb_name = nb_group = ""
    if opts["nbns"]:
        nb_name, nb_group, nb_mac = netbios_query(ip)
        if not mac and nb_mac:                    # routed host: NBSTAT is the only MAC source
            mac = nb_mac
            via += " + NBSTAT MAC"
    ports = probe_ports(ip) if opts["ports"] else []

    return {
        "ip": ip, "mac": mac, "hostname": hostname,
        "netbios": nb_name, "workgroup": nb_group,
        "ttl": ttl, "os": ttl_guess(ttl),
        "rtt": ("<1" if rtt == 0 else rtt) if rtt != "" else "",
        "ports": ", ".join(ports), "via": via,
    }


# ============================================================================
# OUI vendor database
# ============================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUI_FILE = os.path.join(SCRIPT_DIR, "oui.csv")
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"   # IEEE MA-L registry

# Minimal fallback table. Use "Update OUI DB" for full coverage.
BUILTIN_OUI = {
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "240AC4": "Espressif", "30AEA4": "Espressif", "246F28": "Espressif",
    "A4CF12": "Espressif", "5CCF7F": "Espressif", "18FE34": "Espressif",
    "000C29": "VMware", "005056": "VMware", "080027": "VirtualBox (PCS)",
    "00155D": "Microsoft Hyper-V",
}


def load_oui() -> dict:
    """Built-in table, overlaid with the IEEE CSV if it has been downloaded.
    CSV columns: Registry, Assignment (6 hex), Organization Name, Address."""
    db = dict(BUILTIN_OUI)
    if os.path.isfile(OUI_FILE):
        try:
            with open(OUI_FILE, newline="", encoding="utf-8", errors="ignore") as f:
                for row in csv.reader(f):
                    if len(row) >= 3 and len(row[1]) == 6:
                        db[row[1].upper()] = row[2].strip()
        except OSError:
            pass
    return db


def lookup_vendor(db: dict, mac: str) -> str:
    if not mac:
        return ""
    hexmac = mac.replace(":", "")
    vendor = db.get(hexmac[:6], "")
    if not vendor and int(hexmac[:2], 16) & 0x02:    # U/L bit set: locally administered
        return "(locally administered / random MAC)"
    return vendor


# ============================================================================
# GUI
# ============================================================================
class ScannerApp(tk.Tk):
    # (column id, heading, width px)
    COLUMNS = [
        ("ip", "IP Address", 110), ("mac", "MAC Address", 125),
        ("vendor", "Vendor (OUI)", 190), ("hostname", "Hostname", 170),
        ("netbios", "NetBIOS", 110), ("workgroup", "Workgroup", 100),
        ("ttl", "TTL", 45), ("os", "OS guess", 130), ("rtt", "RTT ms", 60),
        ("ports", "Open TCP ports", 200), ("via", "Detected via", 170),
    ]

    def __init__(self):
        super().__init__()
        self.title("LAN Device Scanner")
        self.geometry("1450x650")

        self.q = queue.Queue()                # worker -> GUI messages
        self.stop_evt = threading.Event()
        self.worker = None
        self.records = {}                     # ip -> record dict (used for export and relabel)
        self.oui = load_oui()

        # Local adapters, used for the default subnet, on-link test, and "this PC" rows
        self.ifaces = get_local_interfaces()
        primary_ip = get_primary_ip()
        prim = next((i for i in self.ifaces if str(i["iface"].ip) == primary_ip), None)
        default_net = str(prim["iface"].network) if prim else f"{primary_ip}/24"

        self._build_ui(default_net)
        self._set_status(f"Ready. Local IP {primary_ip}. OUI entries loaded: {len(self.oui)}")
        self.after(100, self._poll_queue)

    # ---------------------------------------------------------------- UI build
    def _build_ui(self, default_net):
        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")

        ttk.Label(top, text="Subnet (CIDR):").pack(side="left")
        self.subnet_var = tk.StringVar(value=default_net)
        ttk.Entry(top, textvariable=self.subnet_var, width=20).pack(side="left", padx=(2, 10))

        ttk.Label(top, text="ICMP timeout ms:").pack(side="left")
        self.timeout_var = tk.StringVar(value="600")
        ttk.Entry(top, textvariable=self.timeout_var, width=6).pack(side="left", padx=(2, 10))

        ttk.Label(top, text="Threads:").pack(side="left")
        self.threads_var = tk.StringVar(value="128")
        ttk.Entry(top, textvariable=self.threads_var, width=5).pack(side="left", padx=(2, 10))

        self.dns_var = tk.BooleanVar(value=True)
        self.nbns_var = tk.BooleanVar(value=True)
        self.ports_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Hostname", variable=self.dns_var).pack(side="left")
        ttk.Checkbutton(top, text="NetBIOS", variable=self.nbns_var).pack(side="left")
        ttk.Checkbutton(top, text="Port probe", variable=self.ports_var).pack(side="left", padx=(0, 10))

        self.scan_btn = ttk.Button(top, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Button(top, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)
        ttk.Button(top, text="Update OUI DB", command=self.update_oui).pack(side="left", padx=4)

        # Results table with scrollbars
        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, padx=6)
        cols = [c[0] for c in self.COLUMNS]
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", selectmode="extended")
        for cid, head, w in self.COLUMNS:
            self.tree.heading(cid, text=head, command=lambda c=cid: self._sort_by(c, False))
            self.tree.column(cid, width=w, anchor="w", stretch=(cid in ("vendor", "hostname", "ports")))
        vsb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(mid, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1)

        # Right-click menu and double-click to open the web UI
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copy IP", command=lambda: self._copy("ip"))
        self.menu.add_command(label="Copy MAC", command=lambda: self._copy("mac"))
        self.menu.add_command(label="Copy row", command=lambda: self._copy(None))
        self.menu.add_separator()
        self.menu.add_command(label="Open http://", command=lambda: self._open_web("http"))
        self.menu.add_command(label="Open https://", command=lambda: self._open_web("https"))
        self.tree.bind("<Button-3>", self._popup)
        self.tree.bind("<Double-1>", lambda e: self._open_web(None))

        # Status bar
        bot = ttk.Frame(self, padding=6)
        bot.pack(fill="x")
        self.progress = ttk.Progressbar(bot, length=300, mode="determinate")
        self.progress.pack(side="left")
        self.status_var = tk.StringVar()
        ttk.Label(bot, textvariable=self.status_var).pack(side="left", padx=10)

    def _set_status(self, text):
        self.status_var.set(text)

    # ---------------------------------------------------------------- scanning
    def start_scan(self):
        try:
            net = ipaddress.IPv4Network(self.subnet_var.get().strip(), strict=False)
            timeout = max(50, int(self.timeout_var.get()))
            threads = max(1, min(512, int(self.threads_var.get())))
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))
            return

        hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
        if len(hosts) > 4096 and not messagebox.askyesno(
                "Large range", f"{len(hosts)} addresses. This may take a while. Continue?"):
            return

        self.tree.delete(*self.tree.get_children())
        self.records.clear()
        self.progress.configure(value=0, maximum=len(hosts))
        self.stop_evt.clear()
        opts = {"timeout": timeout, "threads": threads, "dns": self.dns_var.get(),
                "nbns": self.nbns_var.get(), "ports": self.ports_var.get()}
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._set_status(f"Scanning {net} ({len(hosts)} addresses)...")
        self.worker = threading.Thread(target=self._scan_worker, args=(hosts, opts), daemon=True)
        self.worker.start()

    def stop_scan(self):
        # Queued futures see stop_evt and return immediately; in-flight probes finish normally
        self.stop_evt.set()
        self._set_status("Stopping...")

    def _scan_worker(self, hosts, opts):
        """Runs off the GUI thread. Communicates only through self.q."""
        t0 = time.time()
        local_nets = [i["iface"].network for i in self.ifaces]
        local_ips = {str(i["iface"].ip): i["mac"] for i in self.ifaces}

        # This PC can't ARP itself, so it is reported directly from the ipconfig data
        for ip in hosts:
            if ip in local_ips:
                self.q.put(("host", {"ip": ip, "mac": local_ips[ip],
                                     "hostname": socket.gethostname(), "netbios": "",
                                     "workgroup": "", "ttl": "", "os": "Windows (this PC)",
                                     "rtt": "", "ports": "", "via": "local adapter"}))
        targets = [h for h in hosts if h not in local_ips]

        done = 0
        with ThreadPoolExecutor(max_workers=opts["threads"]) as ex:
            futs = []
            for ip in targets:
                addr = ipaddress.IPv4Address(ip)
                on_link = any(addr in n for n in local_nets)
                futs.append(ex.submit(scan_host, ip, on_link, opts, self.stop_evt))
            for f in as_completed(futs):
                done += 1
                try:
                    rec = f.result()
                except Exception:
                    rec = None
                if rec:
                    self.q.put(("host", rec))
                if done % 4 == 0 or done == len(targets):
                    self.q.put(("progress", done + (len(hosts) - len(targets))))
        self.q.put(("done", time.time() - t0, self.stop_evt.is_set()))

    def _poll_queue(self):
        """Drain worker messages on the GUI thread; re-arms itself every 100 ms."""
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "host":
                    self._add_row(msg[1])
                elif kind == "progress":
                    self.progress.configure(value=msg[1])
                elif kind == "done":
                    self.progress.configure(value=self.progress["maximum"])
                    self.scan_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self._sort_by("ip", False)
                    state = "Stopped" if msg[2] else "Done"
                    self._set_status(f"{state}: {len(self.records)} devices in {msg[1]:.1f} s")
                elif kind == "oui_ok":
                    self.oui = load_oui()
                    self._relabel_vendors()
                    self._set_status(f"OUI DB updated: {len(self.oui)} entries")
                elif kind == "oui_err":
                    messagebox.showerror("OUI download failed", msg[1])
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _row_values(self, rec):
        rec = dict(rec, vendor=lookup_vendor(self.oui, rec["mac"]))
        return [rec.get(c[0], "") for c in self.COLUMNS]

    def _add_row(self, rec):
        self.records[rec["ip"]] = rec
        self.tree.insert("", "end", iid=rec["ip"], values=self._row_values(rec))
        self._set_status(f"Scanning... {len(self.records)} found")

    def _relabel_vendors(self):
        for ip, rec in self.records.items():
            if self.tree.exists(ip):
                self.tree.item(ip, values=self._row_values(rec))

    # ---------------------------------------------------------------- table helpers
    def _sort_by(self, col, reverse):
        """IP column sorts numerically; numeric-looking columns sort as numbers,
        with text and blanks after them."""
        rows = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]

        def key(item):
            v = item[0]
            if col == "ip":
                return (0, int(ipaddress.IPv4Address(v)))
            try:
                return (0, float(str(v).lstrip("<")))
            except ValueError:
                return (1, str(v).lower())

        rows.sort(key=key, reverse=reverse)
        for i, (_, k) in enumerate(rows):
            self.tree.move(k, "", i)
        self.tree.heading(col, command=lambda: self._sort_by(col, not reverse))

    def _popup(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            if row not in self.tree.selection():
                self.tree.selection_set(row)
            self.menu.tk_popup(event.x_root, event.y_root)

    def _copy(self, field):
        sel = self.tree.selection()
        if not sel:
            return
        if field is None:
            lines = ["\t".join(str(v) for v in self.tree.item(i, "values")) for i in sel]
        else:
            lines = [str(self.tree.set(i, field)) for i in sel]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))

    def _open_web(self, scheme):
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        if scheme is None:   # double-click: pick based on detected ports
            ports = self.records.get(ip, {}).get("ports", "")
            scheme = "https" if ("443/" in ports and "80/" not in ports) else "http"
        webbrowser.open(f"{scheme}://{ip}/")

    # ---------------------------------------------------------------- export / OUI
    def export_csv(self):
        if not self.records:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")],
                                            initialfile="netscan.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([c[1] for c in self.COLUMNS])
            for k in self.tree.get_children(""):       # export in current sort order
                w.writerow(self.tree.item(k, "values"))
        self._set_status(f"Exported {len(self.records)} rows to {path}")

    def update_oui(self):
        """Download the IEEE MA-L CSV (~4 MB) on a background thread.
        Writes to a temp file first, then swaps it in atomically."""
        def work():
            try:
                req = urllib.request.Request(OUI_URL, headers={"User-Agent": "Mozilla/5.0 netscan_gui"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = r.read()
                tmp = OUI_FILE + ".tmp"
                with open(tmp, "wb") as f:
                    f.write(data)
                os.replace(tmp, OUI_FILE)
                self.q.put(("oui_ok",))
            except Exception as e:
                self.q.put(("oui_err", str(e)))
        self._set_status("Downloading IEEE OUI registry...")
        threading.Thread(target=work, daemon=True).start()


if __name__ == "__main__":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)   # sharp rendering on high-DPI displays
    except Exception:
        pass
    ScannerApp().mainloop()