#!/usr/bin/env python3
"""
libpcap-watch - Network-level intrusion prevention system (IPS).
Captures inbound TCP SYN packets using Scapy/BPF, evaluates IDS rules,
and dynamically bans offending IPs using nftables sets.
"""

import os
import sys
import json
import time
import socket
import sqlite3
import signal
import queue
import argparse
import subprocess
import threading
from datetime import datetime, timezone
from dataclasses import dataclass
from scapy.all import sniff, IP, IPv6, TCP
from collections import defaultdict, deque
import ipaddress


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class CaptureConfig:
    interfaces: list[str]
    destination_ips: list[str]
    filter_all_destinations: bool = False


def get_default_interface() -> str:
    """Find the network interface associated with the default IPv4 route."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, check=True
        )
        parts = result.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception as e:
        print(f"[{timestamp()}] ERROR determining default interface: {e}", file=sys.stderr)
    raise RuntimeError("Could not determine default interface")


def get_interface_ip(interface: str) -> str:
    """Return the primary IPv4 address assigned to an interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", interface],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception as e:
        print(f"[{timestamp()}] ERROR determining IP for {interface}: {e}", file=sys.stderr)
    raise RuntimeError(f"No IPv4 address found on interface {interface}")


def build_bpf_filter(config: CaptureConfig) -> str:
    """
    Construct a kernel-level BPF filter using exact integer constants
    to ensure 100% compatibility across all libpcap versions, explicitly
    supporting both IPv4 and IPv6 protocol families.
    """
    # 1. Standard Half-Open SYN (SYN set, ACK not set)
    syn_scan = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"

    # 2. NULL Scan (-sN: Zero flags set)
    null_scan = "tcp[tcpflags] == 0"

    # 3. FIN Scan (-sF: Only FIN set without ACK) -> FIN is 1
    fin_scan = "tcp[tcpflags] == 1"

    # 4. XMAS Scan (-sX: FIN + PSH + URG set) -> 1 + 8 + 32 = 41
    xmas_scan = "tcp[tcpflags] == 41"

    # 5. SYN-FIN Anomaly -> SYN (2) + FIN (1) = 3. Both must be set.
    syn_fin = "tcp[tcpflags] & 3 == 3"

    # Combine all attack vectors into a single logic block
    tcp_logic = f"({syn_scan}) or ({null_scan}) or ({fin_scan}) or ({xmas_scan}) or ({syn_fin})"

    # Wrap with explicit IPv4 and IPv6 protocol qualifiers to ensure full compatibility
    attack_vectors = f"(ip and ({tcp_logic})) or (ip6 and ({tcp_logic}))"

    if config.filter_all_destinations or not config.destination_ips:
        return attack_vectors

    destinations = " or ".join(f"dst host {ip}" for ip in config.destination_ips)
    return f"({attack_vectors}) and ({destinations})"


def load_config(config_path: str) -> dict:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_config = {
        "poll_interval": 1,
        "unban_check_interval": 60,
        "memory_prune_interval": 900,
        "interfaces": [],
        "destination_ips": [],
        "filter_all_destinations": False,
        "history_db_enable": True,
        "whitelist_ips": [
            "127.0.0.0/8",    # Localhost IPv4
            "::1/128",        # Localhost IPv6
            "10.0.0.0/8",     # Private Class A
            "172.16.0.0/12",  # Private Class B
            "192.168.0.0/16", # Private Class C
            "fe80::/10"       # Link-local IPv6
        ],
        "rules_file": os.path.join(script_dir, "rules.json"),
        "db_path": os.path.join(script_dir, "libpcap-watch.db"),
        "history_db_path": os.path.join(script_dir, "libpcap-watch-history.db"),
    }

    if not os.path.isfile(config_path):
        print(f"[{timestamp()}] Config file '{config_path}' not found, using defaults.")
        return default_config

    try:
        with open(config_path, "r") as f:
            user_config = json.load(f)
        return {**default_config, **user_config}
    except Exception as e:
        print(f"[{timestamp()}] ERROR reading config: {e}, using defaults.", file=sys.stderr)
        return default_config


def start_ping_listener(socket_path: str, stop_event: threading.Event):
    """Starts a non-blocking background thread to reply to libpcap-manage ping requests."""
    if os.path.exists(socket_path):
        try:
            os.unlink(socket_path)
        except OSError:
            pass

    def listener():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)  # Allow timeout to check stop_event
            s.bind(socket_path)
            s.listen(5)
            os.chmod(socket_path, 0o666)
            while not stop_event.is_set():
                try:
                    conn, _ = s.accept()
                    with conn:
                        data = conn.recv(1024)
                        if data == b"ping":
                            conn.sendall(b"pong!")
                except socket.timeout:
                    continue
                except Exception:
                    break
        # Clean up socket file on thread exit
        if os.path.exists(socket_path):
            try:
                os.unlink(socket_path)
            except OSError:
                pass

    t = threading.Thread(target=listener, name="IPC-Listener", daemon=True)
    t.start()
    return t


class NoopDecisionLogger:
    def log_ban(self, ip, rule_desc, duration, timestamp): pass

    def log_unban(self, ip, timestamp): pass

    def shutdown(self): pass


class DecisionLogger:
    """Thread-safe async logger that writes ban/unban events to a separate history DB."""

    def __init__(self, db_path: str, dry_run: bool = False):
        self.db_path = db_path
        self.dry_run = dry_run
        self.queue: queue.Queue = queue.Queue()
        self._stop = False
        self._worker = threading.Thread(target=self._writer_loop, daemon=True)
        self._worker.start()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                action TEXT CHECK(action IN ('ban', 'unban')) NOT NULL,
                rule_desc TEXT NOT NULL,
                duration INTEGER NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        conn.commit()
        return conn

    def _writer_loop(self):
        if not self.dry_run:
            conn = self._init_db()
        while not self._stop:
            try:
                event = self.queue.get(timeout=1)
                if event is None:
                    break
                action, ip, rule_desc, duration, ts = event
                if self.dry_run:
                    dt_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                    print(f"[SIMULATE History] {action.upper()} {ip} - {rule_desc} ({duration}s) at {dt_str}")
                else:
                    try:
                        conn.execute(
                            "INSERT INTO decisions (ip, action, rule_desc, duration, timestamp) VALUES (?, ?, ?, ?, ?)",
                            (ip, action, rule_desc, duration, ts)
                        )
                        conn.commit()
                    except Exception as e:
                        print(f"[{timestamp()}] ERROR writing decision log: {e}", file=sys.stderr)
            except queue.Empty:
                continue
        if not self.dry_run:
            conn.close()

    def log_ban(self, ip: str, rule_desc: str, duration: int, timestamp: float):
        self.queue.put(("ban", ip, rule_desc, duration, timestamp))

    def log_unban(self, ip: str, timestamp: float):
        self.queue.put(("unban", ip, "ban expired", 0, timestamp))

    def shutdown(self):
        self.queue.put(None)
        self._worker.join(timeout=5)


class NftablesManager:
    """
    Manages an isolated, negative-priority 'inet' table in nftables.
    Hooks at priority -10 (before UFW at priority 0) to guarantee instant packet drops.
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def init_ban_chain(self):
        """Atomically initialize the negative-priority inet table, sets, and drop chains."""
        if self.dry_run:
            print("[SIMULATE] Initializing zero-trust inet table 'pcap_watch' at priority -10")
            return

        # Atomic nftables ruleset definition
        ruleset = """
        add table inet pcap_watch
        add set inet pcap_watch pcap_banned_v4 { type ipv4_addr; flags timeout; }
        add set inet pcap_watch pcap_banned_v6 { type ipv6_addr; flags timeout; }

        add chain inet pcap_watch input_guard { type filter hook input priority -10; policy accept; }
        add chain inet pcap_watch forward_guard { type filter hook forward priority -10; policy accept; }

        flush chain inet pcap_watch input_guard
        flush chain inet pcap_watch forward_guard

        add rule inet pcap_watch input_guard ip saddr @pcap_banned_v4 counter drop
        add rule inet pcap_watch input_guard ip6 saddr @pcap_banned_v6 counter drop
        add rule inet pcap_watch forward_guard ip saddr @pcap_banned_v4 counter drop
        add rule inet pcap_watch forward_guard ip6 saddr @pcap_banned_v6 counter drop
        """

        result = subprocess.run(["nft", "-f", "-"], input=ruleset, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[{timestamp()}] CRITICAL: Failed to initialize nftables: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"[{timestamp()}] Nftables zero-trust inet table 'pcap_watch' initialized at priority -10.")

    def ban_ip(self, ip: str, duration: int = 0):
        family_type = "ip6" if ":" in ip else "ip"
        set_name = "pcap_banned_v6" if family_type == "ip6" else "pcap_banned_v4"

        if self.dry_run:
            timeout_str = f" timeout {duration}s" if duration > 0 else ""
            print(f"[SIMULATE] nft add element inet pcap_watch {set_name} {{ {ip}{timeout_str} }}")
            return

        print(
            f"[{timestamp()}] BANNING IP: {ip} -> inet pcap_watch set '{set_name}' for {duration if duration > 0 else 'permanent'}s")
        cmd = ["nft", "add", "element", "inet", "pcap_watch", set_name, "{", ip]
        if duration > 0:
            cmd.extend(["timeout", f"{duration}s"])
        cmd.append("}")

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 and "File exists" not in result.stderr:
            print(f"[{timestamp()}] ERROR: nft ban failed: {result.stderr.strip()}", file=sys.stderr)

    def unban_ip(self, ip: str):
        family_type = "ip6" if ":" in ip else "ip"
        set_name = "pcap_banned_v6" if family_type == "ip6" else "pcap_banned_v4"

        if self.dry_run:
            print(f"[SIMULATE] nft delete element inet pcap_watch {set_name} {{ {ip} }}")
            return

        print(f"[{timestamp()}] UNBANNING IP: {ip} from inet pcap_watch set '{set_name}'")
        result = subprocess.run(["nft", "delete", "element", "inet", "pcap_watch", set_name, "{", ip, "}"],
                                capture_output=True, text=True)
        if result.returncode != 0 and "does not exist" not in result.stderr and "No such file" not in result.stderr:
            print(f"[{timestamp()}] ERROR: nft unban failed: {result.stderr.strip()}", file=sys.stderr)


class InMemoryHitTracker:
    """
    High-performance in-memory packet hit tracking engine.
    Uses lazy left-popping on deques to achieve O(1) appends and rapid expiration pruning.
    """

    def __init__(self):
        # Key: (ip, rule_id) -> Value: deque of (timestamp, port) tuples
        self.hits = defaultdict(deque)

    def add_hit(self, ip: str, rule_id: int, port: int, ts: float):
        """Append a packet hit timestamp and target port to the IP/Rule queue."""
        self.hits[(ip, rule_id)].append((ts, port))

    def _prune_queue(self, q: deque, cutoff: float):
        """Helper method: lazily left-pop expired timestamps from a queue."""
        while q and q[0][0] <= cutoff:
            q.popleft()

    def count_recent_hits(self, ip: str, rule_id: int, window: float) -> int:
        """Prune expired hits and return the count of recent hits for rate-flood rules."""
        key = (ip, rule_id)
        if key not in self.hits:
            return 0

        q = self.hits[key]
        self._prune_queue(q, time.time() - window)
        return len(q)

    def count_distinct_ports(self, ip: str, rule_id: int, window: float) -> int:
        """Prune expired hits and return the count of unique ports for port-scan rules."""
        key = (ip, rule_id)
        if key not in self.hits:
            return 0

        q = self.hits[key]
        self._prune_queue(q, time.time() - window)
        return len(set(port for _, port in q))

    def prune_expired(self, max_window: float):
        """
        Background maintenance task: prunes old timestamps across all tracked keys
        and deletes empty dictionary keys to prevent memory leaks over long uptimes.
        """
        cutoff = time.time() - max_window
        # Convert keys to a static list to safely mutate the dictionary during iteration
        for key in list(self.hits.keys()):
            q = self.hits[key]
            self._prune_queue(q, cutoff)
            if not q:
                del self.hits[key]


class Database:
    """SQLite backend for tracking active bans. Hit tracking has been moved to memory."""

    def __init__(self, db_path: str, dry_run: bool = False):
        self.dry_run = dry_run
        if dry_run:
            self.conn = sqlite3.connect(":memory:")
        else:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            self.conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self):
        # Optimize SQLite to run almost entirely in RAM while retaining disk durability
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")  # Safe in WAL mode, massive I/O boost
        self.conn.execute("PRAGMA temp_store=MEMORY")   # Keep temporary indices/tables in RAM
        self.conn.execute("PRAGMA cache_size=-32000")   # Allocate ~32MB of RAM for database cache

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS bans (
                ip TEXT PRIMARY KEY,
                unban_time REAL,
                rule_desc TEXT
            )
        """)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def get_ban(self, ip: str):
        cur = self.conn.execute("SELECT unban_time, rule_desc FROM bans WHERE ip = ?", (ip,))
        return cur.fetchone()

    def add_ban(self, ip: str, unban_time: float, rule_desc: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO bans (ip, unban_time, rule_desc) VALUES (?, ?, ?)",
            (ip, unban_time, rule_desc),
        )
        self.conn.commit()

    def try_remove_expired_ban(self, ip: str, expired_unban_time: float) -> bool:
        cur = self.conn.execute("DELETE FROM bans WHERE ip = ? AND unban_time = ?", (ip, expired_unban_time))
        self.conn.commit()
        return cur.rowcount > 0

    def get_expired_bans(self, now: float):
        cur = self.conn.execute("SELECT ip, unban_time FROM bans WHERE unban_time <= ?", (now,))
        return cur.fetchall()

    def get_active_bans(self):
        now = time.time()
        cur = self.conn.execute("SELECT ip, unban_time FROM bans WHERE unban_time > ?", (now,))
        return cur.fetchall()


class NetworkRuleEngine:
    """Evaluates network packet metadata against IDS rules."""

    def __init__(self, rules_file: str):
        self.rules_file = rules_file
        self.rules = []

    def load(self):
        if not os.path.isfile(self.rules_file):
            print(f"[{timestamp()}] rules file not found - using built-in default IDS rules.")
            self.rules = [
                {
                    "type": "stealth_anomaly",
                    "threshold": 1,
                    "window": 60,
                    "ban_duration": 86400,
                    "description": "Nmap Stealth Scan / Flag Anomaly (NULL, FIN, XMAS, SYN-FIN)",
                },
                {
                    "type": "port_scan",
                    "threshold": 10,
                    "window": 10,
                    "ban_duration": 3600,
                    "description": "Horizontal Port Scan Detected (>10 ports in 10s)",
                },
                {
                    "type": "honeypot_port",
                    "ports": [23, 2323, 445, 3389],
                    "threshold": 1,
                    "window": 60,
                    "ban_duration": 86400,
                    "description": "Honeypot Port Trap (Instant Ban)",
                }
            ]
        else:
            with open(self.rules_file, "r") as f:
                self.rules = json.load(f)

        return len(self.rules)

    def evaluate(self, dport: int, scan_type: str) -> list[tuple[int, dict]]:
        """Return (rule_index, rule_dict) for every rule matching this packet's profile."""
        matches = []
        for idx, rule in enumerate(self.rules):
            rtype = rule.get("type")

            if rtype == "stealth_anomaly" and scan_type == "stealth_anomaly":
                matches.append((idx, rule))

            elif rtype == "port_scan" and scan_type == "syn_scan":
                matches.append((idx, rule))

            elif rtype == "port_rate" and dport in rule.get("ports", []):
                matches.append((idx, rule))

            elif rtype == "honeypot_port" and dport in rule.get("ports", []):
                matches.append((idx, rule))

        return matches

    def max_window(self) -> int:
        if not self.rules:
            return 3600
        return max(r.get("window", 3600) for r in self.rules)


class PacketSniffer(threading.Thread):
    """Background thread running Scapy capture. Pushes events to a Queue to prevent blocking."""

    def __init__(self, config: CaptureConfig, packet_queue: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.config = config
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.bpf_filter = build_bpf_filter(config)

    def _packet_callback(self, packet):
        if self.stop_event.is_set():
            return

        src_ip = None
        if IP in packet:
            src_ip = packet[IP].src
        elif IPv6 in packet:
            src_ip = packet[IPv6].src

        if src_ip and TCP in packet:
            tcp_layer = packet[TCP]
            dport = tcp_layer.dport

            # PERFORMANCE HACK: Because the BPF filter ONLY lets through clean SYNs
            # or illegal stealth scan flag combinations, we can classify instantly:
            # In Scapy, integer flag value 0x02 (2) represents a pure SYN packet.
            # Anything else that passed the kernel is by definition a stealth anomaly!

            # Apply bitwise mask (~0xC0) to filter out TCP ECN flags (0x40 ECE, 0x80 CWR)
            clean_flags = int(tcp_layer.flags) & ~0xC0
            scan_type = "syn_scan" if clean_flags == 0x02 else "stealth_anomaly"

            # Push non-blocking tuple: (source_ip, destination_port, scan_type, timestamp)
            self.packet_queue.put((src_ip, dport, scan_type, time.time()))

    def run(self):
        print(f"[{timestamp()}] Starting Scapy capture on interfaces: {self.config.interfaces}")
        print(f"[{timestamp()}] BPF Filter: {self.bpf_filter}")

        # stop_filter evaluates on every packet; when True, sniff() exits cleanly
        sniff(
            iface=self.config.interfaces,
            filter=self.bpf_filter,
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda _: self.stop_event.is_set()
        )


class NetWatch:
    def __init__(self, args: argparse.Namespace):
        self.dry_run = args.dry_run
        self.silent = args.silent
        self._shutdown_event = threading.Event()
        self.packet_queue: queue.Queue = queue.Queue(maxsize=10000)

        config = load_config(args.config)
        self.poll_interval = config.get("poll_interval", 1)
        self.unban_check_interval = config.get("unban_check_interval", 60)
        self.memory_prune_interval = config.get("memory_prune_interval", 900)

        # Parse whitelist networks
        self.whitelist_networks = []
        for net_str in config.get("whitelist_ips", []):
            try:
                # strict=False allows parsing "192.168.1.5/24" seamlessly into "192.168.1.0/24"
                self.whitelist_networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError as e:
                print(f"[{timestamp()}] WARNING: Invalid whitelist IP/subnet '{net_str}': {e}", file=sys.stderr)

        # Setup Capture Interfaces
        if args.interface:
            interfaces = args.interface
        elif config.get("interfaces"):
            interfaces = config["interfaces"]
        else:
            interfaces = [get_default_interface()]

        # Setup Destination IPs
        if args.all_destinations or config.get("filter_all_destinations"):
            dest_ips = []
            filter_all = True
        elif args.dest_ip:
            dest_ips = args.dest_ip
            filter_all = False
        elif config.get("destination_ips"):
            dest_ips = config["destination_ips"]
            filter_all = False
        else:
            dest_ips = [get_interface_ip(interfaces[0])]
            filter_all = False

        self.capture_config = CaptureConfig(
            interfaces=interfaces,
            destination_ips=dest_ips,
            filter_all_destinations=filter_all
        )

        # Initialize engines
        self.nft = NftablesManager(dry_run=self.dry_run)
        self.db_path = config["db_path"]
        self.db = Database(self.db_path, dry_run=self.dry_run)
        self.hit_tracker = InMemoryHitTracker()

        self.rules_engine = NetworkRuleEngine(config["rules_file"])

        if config["history_db_enable"] and not self.dry_run:
            self.decision_log = DecisionLogger(config["history_db_path"], dry_run=False)
        else:
            self.decision_log = NoopDecisionLogger()

    def _log(self, msg: str, force: bool = False):
        if not self.silent or force:
            print(f"[{timestamp()}] {msg}")

    def _is_whitelisted(self, ip_str: str) -> bool:
        """Evaluate if an IP exists inside any of the configured whitelist subnets."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for network in self.whitelist_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        return False

    def _handle_matches(self, ip: str, dport: int, matched: list[tuple[int, dict]], event_time: float):
        # Abort immediately if the IP matches a trusted subnet
        if self._is_whitelisted(ip):
            return

        for rule_idx, rule in matched:
            self.hit_tracker.add_hit(ip, rule_idx, dport, event_time)

            rtype = rule.get("type")
            if rtype == "port_scan":
                count = self.hit_tracker.count_distinct_ports(ip, rule_idx, rule["window"])
            else:
                count = self.hit_tracker.count_recent_hits(ip, rule_idx, rule["window"])

            if count >= rule["threshold"]:
                existing = self.db.get_ban(ip)
                if existing:
                    continue  # Already banned

                ban_duration = rule["ban_duration"]
                unban_time = event_time + ban_duration if ban_duration > 0 else float("inf")

                self._log(f"ALERT: IP {ip} triggered rule '{rule['description']}' (Hits: {count}/{rule['threshold']})",
                          force=True)
                self.db.add_ban(ip, unban_time, rule["description"])
                self.nft.ban_ip(ip, ban_duration)
                self.decision_log.log_ban(ip, rule["description"], ban_duration, event_time)

    def _unban_loop(self):
        unban_db = Database(self.db_path, dry_run=self.dry_run)
        try:
            while not self._shutdown_event.is_set():
                self._shutdown_event.wait(self.unban_check_interval)
                if self._shutdown_event.is_set():
                    break
                if self.dry_run:
                    continue
                now = time.time()
                for ip, expired_time in unban_db.get_expired_bans(now):
                    if unban_db.try_remove_expired_ban(ip, expired_time):
                        self.nft.unban_ip(ip)
                        self.decision_log.log_unban(ip, time.time())
        finally:
            unban_db.close()

    def run(self):
        if not self.dry_run and os.geteuid() != 0:
            print("libpcap-watch must be run as root to capture packets and manage nftables. Use --dry-run to test.",
                  file=sys.stderr)
            sys.exit(1)

        num_rules = self.rules_engine.load()
        self._log(f"Loaded {num_rules} intrusion detection rules.", force=True)

        if not self.dry_run:
            self.nft.init_ban_chain()
            for ip, _ in self.db.get_active_bans():
                self.nft.ban_ip(ip, duration=0)

        # Start unban thread
        unban_thread = threading.Thread(target=self._unban_loop, daemon=True)
        unban_thread.start()

        # Start IPC Ping Listener (NEW)
        socket_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libpcap-watch.sock")
        ipc_thread = start_ping_listener(socket_path, self._shutdown_event)

        # Start Scapy capture thread
        sniffer = PacketSniffer(self.capture_config, self.packet_queue, self._shutdown_event)
        sniffer.start()

        def handle_shutdown(signum, frame):
            self._log("Shutdown signal received. Stopping gracefully.", force=True)
            self._shutdown_event.set()

        signal.signal(signal.SIGTERM, handle_shutdown)
        signal.signal(signal.SIGINT, handle_shutdown)

        self._log("libpcap-watch engine active and processing packet queue...", force=True)

        last_cleanup = time.time()
        max_window = self.rules_engine.max_window()

        try:
            while not self._shutdown_event.is_set():
                try:
                    # Pull packet event from queue: NOW EXPECTING 4 VALUES!
                    src_ip, dport, scan_type, ts = self.packet_queue.get(timeout=1.0)

                    matched = self.rules_engine.evaluate(dport, scan_type)
                    if matched:
                        self._handle_matches(src_ip, dport, matched, ts)

                except queue.Empty:
                    pass
                except Exception as e:
                    print(f"[{timestamp()}] ERROR in packet processing loop: {e}", file=sys.stderr)

                # Periodically prune expired hit histories from memory to prevent RAM bloat
                if time.time() - last_cleanup > self.memory_prune_interval:
                    self.hit_tracker.prune_expired(max_window)
                    last_cleanup = time.time()

        finally:
            self._log("Shutting down workers...", force=True)
            self._shutdown_event.set()
            sniffer.join(timeout=5)
            unban_thread.join(timeout=5)
            self.db.close()
            self.decision_log.shutdown()
            self._log("Shutdown complete.", force=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="libpcap-watch - Network-level IPS")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without touching nftables or SQLite")
    parser.add_argument("--silent", action="store_true", help="Suppress output except for alerts and errors")
    parser.add_argument("--config", default="libpcap-config.json", help="Path to JSON configuration file")
    parser.add_argument("--interface", action="append", help="Interface to monitor (can be repeated)")
    parser.add_argument("--dest-ip", action="append", help="Destination IP to monitor (can be repeated)")
    parser.add_argument("--all-destinations", action="store_true", help="Do not restrict destination IP")
    args = parser.parse_args()

    watcher = NetWatch(args)
    watcher.run()
