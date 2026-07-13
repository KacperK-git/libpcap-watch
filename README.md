# libpcap-watch

A real-time Network Intrusion Prevention System (IPS) for Linux. libpcap-watch captures ingress network traffic using exact kernel-level BPF filters via Scapy, evaluates packet headers against dynamic intrusion detection rules, and shunts malicious attackers at Layer 4 using hardware-efficient nftables sets.

---

## Key Features

* **Zero-Overhead BPF Filtering:** Constructs precise Berkeley Packet Filters (BPF) so the kernel only passes half-open SYNs and illegal TCP flag combinations (NULL, FIN, XMAS) to user space. Clean, established traffic is never processed by Python.
* **Dynamic Kernel Netfilter Engine:** Automatically builds and manages dedicated nftables tables, chains, and sets (pcap_banned_ipv4 and pcap_banned_ipv6) with native hardware timeout flags.
* **Multi-Vector Threat Detection:**
    * **Stealth & Evasion Scans:** Instant detection of Nmap NULL, FIN, XMAS, and SYN-FIN anomalies.
    * **Horizontal Port Scans:** Catches aggressive and slow sweeps across distinct ports.
    * **Brute-Force & Floods:** Mitigates SSH brute-force attempts and Web SYN floods.
    * **Honeypot Traps:** Instant permanent or long-term bans for touching legacy, admin, or IoT ports (Telnet, SMB, RDP, VNC, ADB, Mirai vectors).
* **High-Performance In-Memory SQLite:** Utilizes WAL (Write-Ahead Logging) mode and memory caching (PRAGMA temp_store=MEMORY) for zero-latency hit tracking and history logging.
* **Dedicated Management CLI:** Includes libpcap-manage.py for live auditing, kernel-to-database synchronization, telemetry extraction, and unbanning.

---

## Architecture & Workflow

```text
[ Ingress Traffic ]
        │
        ▼
┌──────────────────────────────────────────┐
│ Kernel BPF Filter (Raw Socket Layer)     │
│ Only passes SYN or Flag Anomaly packets  │
└────────────────────┬─────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────┐
│ Scapy / Python Engine (libpcap-watch.py) │
│ Evaluates packet vs. rules.json          │
└────────────────────┬─────────────────────┘
                     │
          Match Threshold Exceeded?
                     │
         ┌───────────┴───────────┐
         ▼ (Yes)                 ▼ (No)
┌──────────────────────┐  ┌──────────────┐
│ Add to nftables Set  │  │ Log Hit To   │
│ & SQLite Cache DB    │  │ Memory Cache │
└──────────────────────┘  └──────────────┘
```

---

## Prerequisites & Installation

### System Requirements
* **Linux OS** with a modern kernel supporting nftables.
* **Python 3.9+**
* **Root / Sudo Privileges** (Required for raw packet capture and firewall manipulation).

### 1. Download and Locate
Download or clone this repository to your preferred system directory (for permanent deployment, `/usr/local/libpcap-watch` is recommended).

### 2. Install Dependencies
The engine requires scapy in your Python environment and the userland nftables package installed on your host system.

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y nftables python3-pip
pip install scapy

# RHEL / Fedora / Rocky Linux
sudo dnf install -y nftables python3-pip
pip install scapy
```

### 3. Make Scripts Executable
Navigate to your deployment directory and apply execution permissions to the core scripts:

```bash
chmod +x libpcap-watch.py libpcap-manage.py
```

---

## Systemd Service Deployment

For production environments, libpcap-watch should be managed as a background system service to ensure continuous monitoring and automatic restart on failure.

### 1. Create the Service File
Create a new systemd unit file at `/etc/systemd/system/libpcap-watch.service`:

```ini
[Unit]
Description=Libpcap Watch - L4 Network Sniffer
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/libpcap-watch
ExecStart=/usr/bin/python3 /usr/local/libpcap-watch/libpcap-watch.py
Restart=always
RestartSec=15

# Elevated privileges are mandatory for libpcap raw socket sniffing & netfilter controls
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
```

*Note: Update WorkingDirectory and ExecStart if you installed the repository in a location other than /usr/local/libpcap-watch.*

### 2. Enable and Start the Daemon
Reload the systemd manager configuration, enable the service to start on boot, and initiate the daemon:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now libpcap-watch
```

### 3. Verify Service Status
Check the logs to confirm the packet sniffer is actively capturing traffic:

```bash
sudo systemctl status libpcap-watch
sudo journalctl -u libpcap-watch -f
```

---

## Configuration (rules.json)

The engine is driven by rules.json. You can modify detection thresholds, time windows, and ban durations without touching the core code.

### Example Rule Structure
```json
[
  {
    "type": "stealth_anomaly",
    "threshold": 1,
    "window": 60,
    "ban_duration": 7776000,
    "description": "Nmap Stealth/Evasion Scan (NULL, FIN, XMAS, SYN-FIN) - Instant Ban"
  },
  {
    "type": "port_scan",
    "threshold": 5,
    "window": 15,
    "ban_duration": 7776000,
    "description": "Aggressive Horizontal Port Scan (>5 distinct ports hit within 15s)"
  },
  {
    "type": "port_rate",
    "ports": [22, 2222],
    "threshold": 10,
    "window": 60,
    "ban_duration": 7776000,
    "description": "SSH Brute Force Attempt (>10 connection attempts in 60s)"
  },
  {
    "type": "honeypot_port",
    "ports": [23, 2323, 445, 139, 3389, 5900, 21],
    "threshold": 1,
    "window": 60,
    "ban_duration": 7776000,
    "description": "Honeypot Trap: Legacy/Admin Protocols (Telnet, SMB, RDP, VNC, FTP)"
  }
]
```

### Rule Types
* `stealth_anomaly`: Triggers on TCP flag manipulations (e.g., zero flags set, FIN only, XMAS tree).
* `port_scan`: Tracks unique destination ports accessed by a single IP within the defined time window.
* `port_rate`: Tracks the total volume of connection attempts to specific target ports (useful for brute-force mitigation).
* `honeypot_port`: Immediate trap ports. A single packet to these ports initiates an immediate ban.

---

## Usage

### Command-Line Arguments
If running the script directly from the terminal instead of via systemd, you can use the following arguments:

* `--dry-run`: Simulate packet detection and rule matching without writing to nftables or disk databases. Perfect for testing.
* `--silent`: Suppress standard stdout logs; only print critical alerts and errors.
* `--interface <iface>`: Explicitly define which network interface(s) to sniff (can be repeated for multi-homed systems).
* `--dest-ip <ip>`: Define specific target IP addresses to filter (can be repeated).
* `--all-destinations`: Remove destination IP restrictions and analyze all passing ingress traffic.
* `--config <path>`: Point to a custom JSON configuration file (defaults to libpcap-config.json).

---

## Management CLI (libpcap-manage.py)

The suite includes a management tool to inspect kernel firewall states, view shunted bandwidth, and manage banned IPs.

### List Active Bans
Display all currently active bans, remaining timeout durations, and net growth metrics over the last 24 hours:
```bash
sudo ./libpcap-manage.py list
```

### Show Attack Telemetry & Statistics
View total dropped packets, saved hardware bandwidth, and top attack vectors:
```bash
sudo ./libpcap-manage.py stats --top 10
```

### Test / Query an IP Address
Check if an IP is currently tracked in the working cache or actively dropped inside the kernel netfilter engine:
```bash
sudo ./libpcap-manage.py test 192.0.2.45
```

### Unban an IP Address
Force-remove an IP from both the working SQLite cache and the live kernel nftables set:
```bash
sudo ./libpcap-manage.py unban 192.0.2.45
```

### Check Firewall Synchronization
Verify consistency between the in-memory SQLite database and kernel nftables sets. If discrepancies exist, repair them automatically:
```bash
# Audit state
sudo ./libpcap-manage.py sync

# Auto-repair orphan rules or missing netfilter elements
sudo ./libpcap-manage.py sync --repair
```

### View Attack History
Extract raw telemetry logs from the historical database for a specified time window:
```bash
sudo ./libpcap-manage.py history --hours 6
```

### Ping the Daemon
Verify that the core packet-sniffing process is alive and responsive via IPC socket communication:
```bash
./libpcap-manage.py ping
```

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.
