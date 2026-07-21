#!/usr/bin/env python3
"""
libpcap-manage - advanced management for libpcap-watch bans.
Commands:
  list             List active network bans (oldest first)
  sync             Compare database vs nftables sets, optionally repair
  stats            Show total network bans and dropped traffic statistics
  test <IP>        Check if an IP is currently banned at Layer 4
  unban <IP>       Remove a ban from the working DB and kernel sets
  history          Show network rule hits from the last N hours (default 3)
  ping             Verify the core libpcap-watch process is alive
"""

import os
import re
import sys
import socket
import sqlite3
import subprocess
import time
import argparse
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "libpcap-watch.db")
HISTORY_DB_PATH = os.path.join(SCRIPT_DIR, "libpcap-watch-history.db")
SOCKET_PATH = os.path.join(SCRIPT_DIR, "libpcap-watch.sock")


def format_duration(seconds):
    if seconds < 0:
        return "expired"
    if seconds == float("inf") or seconds == 0:
        return "permanent"
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def get_ban_set_ips(family):
    """Return set of IP addresses currently in the unified inet pcap_watch sets."""
    # Map 'ip' -> 'pcap_banned_v4', 'ip6' -> 'pcap_banned_v6'
    set_name = "pcap_banned_v4" if family == "ip" else "pcap_banned_v6"
    try:
        # Target the unified 'inet' family and 'pcap_watch' table
        output = subprocess.run(
            ["nft", "list", "set", "inet", "pcap_watch", set_name],
            capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        return set()

    ips = set()
    match = re.search(r'elements\s*=\s*\{([^}]+)\}', output)
    if not match:
        return ips

    for item in match.group(1).split(","):
        tokens = item.strip().split()
        if tokens:
            ip = tokens[0]
            if "." in ip or ":" in ip:
                ips.add(ip)
    return ips


def get_ban_set_counters(family):
    """Return dict IP -> (packets, bytes) from the pcap ban set elements."""
    counters = {}
    set_name = "pcap_banned_v4" if family == "ip" else "pcap_banned_v6"
    try:
        output = subprocess.run(
            ["nft", "list", "set", "inet", "pcap_watch", set_name],
            capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        return counters

    match = re.search(r'elements\s*=\s*\{([^}]+)\}', output)
    if not match:
        return counters

    for item in match.group(1).split(","):
        tokens = item.strip().split()
        if tokens:
            ip = tokens[0]
            if "." in ip or ":" in ip:
                pkt_match = re.search(r'packets\s+(\d+)', item)
                bytes_match = re.search(r'bytes\s+(\d+)', item)
                packets = int(pkt_match.group(1)) if pkt_match else 0
                byt = int(bytes_match.group(1)) if bytes_match else 0
                counters[ip] = (packets, byt)
    return counters


def unban_ip(ip: str):
    """Remove the IP from the unified inet pcap_watch ban set."""
    family_type = "ip6" if ":" in ip else "ip"
    set_name = "pcap_banned_v6" if family_type == "ip6" else "pcap_banned_v4"
    try:
        subprocess.run(
            ["nft", "delete", "element", "inet", "pcap_watch", set_name, f"{{ {ip} }}"],
            check=True, capture_output=True, text=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_active_bans(conn):
    """Return list of (ip, unban_time, rule_desc) for active network bans."""
    now = time.time()
    cur = conn.execute(
        "SELECT ip, unban_time, rule_desc FROM bans WHERE unban_time > ? ORDER BY unban_time ASC",
        (now,)
    )
    return cur.fetchall()


def remove_ban(conn, ip):
    conn.execute("DELETE FROM bans WHERE ip = ?", (ip,))
    conn.commit()


def cmd_list(conn):
    bans = get_active_bans(conn)
    line_width = 50

    if bans:
        ip_col = 20
        reason_col = 50
        remaining_col = 20
        header = f"{'IP':<{ip_col}} {'Remaining':<{remaining_col}} {'Network Detection Rule':<{reason_col}}"
        line_width = len(header)
        print(header)
        print("-" * line_width)

        now = time.time()
        for ip, unban_time, rule_desc in bans:
            remaining = unban_time - now if unban_time != float("inf") else float("inf")
            remaining_str = format_duration(remaining)
            if len(rule_desc) > reason_col - 2:
                rule_desc = rule_desc[:reason_col - 5] + "..."
            print(f"{ip:<{ip_col}} {remaining_str:<{remaining_col}} {rule_desc:<{reason_col}}")
    else:
        print("No active network bans currently in the working database.")

    ipv4_count = sum(1 for row in bans if ":" not in row[0])
    ipv6_count = sum(1 for row in bans if ":" in row[0])
    perm_count = sum(1 for row in bans if row[1] == float("inf"))

    bans_per_hour_24h = 0.0
    unbans_per_hour_24h = 0.0
    total_historical_bans = 0

    if os.path.exists(HISTORY_DB_PATH):
        try:
            with sqlite3.connect(HISTORY_DB_PATH) as h_conn:
                now_ts = time.time()
                day_ago = now_ts - 86400

                cur = h_conn.execute(
                    "SELECT COUNT(*) FROM decisions WHERE action = 'ban' AND timestamp >= ?",
                    (day_ago,)
                )
                bans_per_hour_24h = cur.fetchone()[0] / 24.0

                cur = h_conn.execute(
                    "SELECT COUNT(*) FROM decisions WHERE action = 'unban' AND timestamp >= ?",
                    (day_ago,)
                )
                unbans_per_hour_24h = cur.fetchone()[0] / 24.0

                cur = h_conn.execute("SELECT COUNT(*) FROM decisions WHERE action = 'ban'")
                total_historical_bans = cur.fetchone()[0]
        except Exception:
            pass

    growth_rate = bans_per_hour_24h - unbans_per_hour_24h
    if growth_rate >= 20.0: trend_str = "▲▲▲"
    elif growth_rate >= 10.0: trend_str = "▴▴▴"
    elif growth_rate <= -10.0: trend_str = "▽▽▽"
    elif growth_rate <= -20.00: trend_str = "▾▾▾"
    else: trend_str = "---"

    print("-" * line_width)
    print("\n📊 Metrics:")
    print(f"  • All active bans:        {len(bans)}")
    print(f"  • IPv4 bans:              {ipv4_count}")
    print(f"  • IPv6 bans:              {ipv6_count}")
    print(f"  • Persistent bans:        {perm_count}")
    print(f"  • Ban Rate:               {bans_per_hour_24h:.2f}  /h (last 24 h)")
    print(f"  • Unban Rate:             {unbans_per_hour_24h:.2f}  /h (last 24 h)")
    print(f"  • Net Growth Rate:        {growth_rate:+.2f} /h (   {trend_str}   )")
    print(f"  • All bans ever issued:   {total_historical_bans}\n")
    print("-" * line_width)
    print()


def cmd_sync(conn, repair=False):
    """Check consistency between working memory cache DB and kernel nftables sets."""
    now = time.time()

    # Query mappings of IP -> unban_time instead of just a set of IPs
    cur = conn.execute("SELECT ip, unban_time FROM bans WHERE unban_time > ?", (now,))
    db_bans = {row[0]: row[1] for row in cur.fetchall()}
    db_ips = set(db_bans.keys())

    nft_v4 = get_ban_set_ips("ip")
    nft_v6 = get_ban_set_ips("ip6")
    all_nft = nft_v4 | nft_v6

    missing_in_nft = db_ips - all_nft
    orphan_in_nft = all_nft - db_ips

    if not missing_in_nft and not orphan_in_nft:
        print("✅ Cache Database and kernel nftables sets are completely synchronized.")
        return

    if missing_in_nft:
        print(f"⚠️  IPs tracked in database cache but dropped out of kernel firewall ({len(missing_in_nft)}):")
        for ip in sorted(missing_in_nft):
            print(f"   {ip}")
        if repair:
            print("Injecting missing rules into kernel routing tree...")
            for ip in sorted(missing_in_nft):
                family_type = "ip6" if ":" in ip else "ip"
                set_name = "pcap_banned_v6" if family_type == "ip6" else "pcap_banned_v4"

                # Calculate exact remaining duration
                unban_time = db_bans[ip]
                remaining = int(unban_time - time.time())

                cmd = ["nft", "add", "element", "inet", "pcap_watch", set_name, "{", ip]
                if unban_time != float("inf") and remaining > 0:
                    cmd.extend(["timeout", f"{remaining}s"])
                cmd.append("}")

                subprocess.run(cmd, capture_output=True, text=True)
                print(
                    f"   ➕ Remounted {ip} (Remaining: {format_duration(remaining) if unban_time != float('inf') else 'permanent'})")
        else:
            print("   Execute with --repair to automatically fix.")

    if orphan_in_nft:
        print(f"⚠️  Orphan blocks inside kernel sets missing from tracking database ({len(orphan_in_nft)}):")
        for ip in sorted(orphan_in_nft):
            print(f"   {ip}")
        if repair:
            print("Flushing orphan definitions out of firewall tables...")
            for ip in sorted(orphan_in_nft):
                if unban_ip(ip):
                    print(f"   🗑️  Evicted {ip}")
        else:
            print("   Execute with --repair to clear kernel storage structures.")


def cmd_stats(conn, top_n=10):
    bans = get_active_bans(conn)
    print(f"Active tracking elements in database cache: {len(bans)}")

    v4_counters = get_ban_set_counters("ip")
    v6_counters = get_ban_set_counters("ip6")
    all_counters = {**v4_counters, **v6_counters}
    total_packets = sum(pkt for pkt, _ in all_counters.values())
    total_bytes = sum(byt for _, byt in all_counters.values())
    print(f"Total dropped attack packets caught by BPF pipeline: {total_packets}")
    print(f"Total hardware network bandwidth saved: {total_bytes} bytes")

    if all_counters:
        print(f"\nTop {top_n} Attack Vectors by Bandwidth Footprint:")
        print(f"   {'Target IP':<20} {'Packets Dropped':<18} {'Bytes Shunted':<15}")
        print("   " + "-" * 55)
        sorted_by_bytes = sorted(all_counters.items(), key=lambda x: x[1][1], reverse=True)[:top_n]
        for ip, (pkt, byt) in sorted_by_bytes:
            print(f"   {ip:<20} {pkt:<18} {byt:<15}")

        print(f"\nTop {top_n} Attack Vectors by Packet Flood Intensity:")
        print(f"   {'Target IP':<20} {'Packets Dropped':<18} {'Bytes Shunted':<15}")
        print("   " + "-" * 55)
        sorted_by_packets = sorted(all_counters.items(), key=lambda x: x[1][0], reverse=True)[:top_n]
        for ip, (pkt, byt) in sorted_by_packets:
            print(f"   {ip:<20} {pkt:<18} {byt:<15}")


def cmd_test(conn, ip):
    now = time.time()
    cur = conn.execute("SELECT unban_time, rule_desc FROM bans WHERE ip = ? AND unban_time > ?",
                       (ip, now))
    row = cur.fetchone()
    if row:
        unban_time, reason = row
        remaining = unban_time - now if unban_time != float("inf") else float("inf")
        print(f"📋 Cache Tracking State: BANNED")
        print(f"   IDS Signature Trigger: {reason}")
        print(f"   Time Remaining:        {format_duration(remaining)}")
    else:
        print("📋 Cache Tracking State: Neutral (Clean or Expired)")

    family = "ip6" if ":" in ip else "ip"
    nft_ips = get_ban_set_ips(family)
    if ip in nft_ips:
        counters = get_ban_set_counters(family)
        pkt, byt = counters.get(ip, (0, 0))
        print(f"🔒 Kernel Set Engine:   BLOCKED ({pkt} packets, {byt} bytes dropped at ingress)")
    else:
        print(f"🔓 Kernel Set Engine:   PASSING TRAFFIC")


def cmd_unban(conn, ip):
    cur = conn.execute("SELECT ip FROM bans WHERE ip = ?", (ip,))
    if not cur.fetchone():
        print(f"❌ Target IP {ip} is not marked as banned inside the working engine.")
        return
    success = unban_ip(ip)
    remove_ban(conn, ip)
    if success:
        print(f"✅ IP {ip} unblocked successfully (kernel structure entry evicted).")
    else:
        print(f"⚠️  Evicted IP from local engine cache, but no active kernel netfilter handle was found.")


def cmd_history(hours=3.0):
    if not os.path.exists(HISTORY_DB_PATH):
        print(f"❌ Historical log repository database not found at {HISTORY_DB_PATH}.")
        return

    conn = sqlite3.connect(HISTORY_DB_PATH)
    now = time.time()
    cutoff_timestamp = now - (hours * 3600)

    try:
        cur = conn.execute(
            "SELECT ip, action, rule_desc, duration, timestamp FROM decisions WHERE timestamp >= ? ORDER BY timestamp DESC",
            (cutoff_timestamp,)
        )
        rows = cur.fetchall()
    except sqlite3.OperationalError as e:
        print(f"❌ Error extracting telemetry from historical table structures: {e}")
        return
    finally:
        conn.close()

    if not rows:
        print(f"No firewall telemetry logs recorded within the last {hours} hour analysis window.")
        return

    print(f"Network Telemetry Logs (Last {hours} Hours, Newest First. Count: {len(rows)}):")
    print(f"{'Event Timestamp':<22} {'Target Source IP':<20} {'Action':<8} {'Assigned Dur':<14} {'IDS Signature'}")
    print("-" * 95)
    for ip, action, rule_desc, duration, ts in rows:
        time_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        dur_str = format_duration(duration) if action == "ban" else "-"
        desc = rule_desc
        if len(desc) > 30:
            desc = desc[:27] + "..."
        print(f"{time_str:<22} {ip:<20} {action.upper():<8} {dur_str:<14} {desc}")


def cmd_ping():
    if not os.path.exists(SOCKET_PATH):
        print("❌ IPC communication socket missing. Is the core libpcap-watch process running?")
        return
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(SOCKET_PATH)
            client.sendall(b"ping")
            response = client.recv(1024).decode("utf-8").strip()
            if response == "pong!":
                print("🏓 pong! (Core sniffing engine is active and processing packets via BPF loop)")
            else:
                print(f"⚠️ Unexpected IPC loop validation returned: {response}")
    except socket.timeout:
        print("❌ Interface communication timeout. The packet handler loop may be starved or blocked.")
    except Exception as e:
        print(f"❌ Failed to reach socket handle payload context: {e}")


def main():
    parser = argparse.ArgumentParser(description="Manage libpcap-watch network engine states")
    sub = parser.add_subparsers(dest="command", help="Command execution vector")

    sub.add_parser("list", help="List active network engine bans (oldest first)")

    sync_parser = sub.add_parser("sync", help="Check memory cache DB vs engine netfilter consistency")
    sync_parser.add_argument("--repair", action="store_true", help="Repair any localized sync breaks")

    stats_parser = sub.add_parser("stats", help="Show system wide shunted traffic telemetry metrics")
    stats_parser.add_argument("--top", type=int, default=10, help="Analysis truncation threshold (default: 10)")

    test_parser = sub.add_parser("test", help="Check tracking attributes for a target IP")
    test_parser.add_argument("ip", help="Target string representation IP")

    unban_parser = sub.add_parser("unban", help="Force clear an engine block restriction")
    unban_parser.add_argument("ip", help="Target string representation IP")

    hist_parser = sub.add_parser("history", help="Extract raw telemetry from historical log engines")
    hist_parser.add_argument("--hours", type=float, default=3.0, help="Telemetry time parsing constraint (default: 3)")

    sub.add_parser("ping", help="Validate process loop runtime status")

    args = parser.parse_args()

    if args.command == "ping":
        cmd_ping()
        sys.exit(0)

    if not os.path.exists(DB_PATH):
        print(f"Working database cache file missing at {DB_PATH}. Ensure the core daemon is deployed.")
        sys.exit(1)

    if args.command in ("sync", "unban", "test", "stats") and os.geteuid() != 0:
        print("Elevated network access required for kernel netfilter operations. Execute via sudo.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)

    if args.command == "list" or args.command is None:
        cmd_list(conn)
    elif args.command == "sync":
        cmd_sync(conn, repair=args.repair)
    elif args.command == "stats":
        cmd_stats(conn, top_n=args.top)
    elif args.command == "test":
        cmd_test(conn, args.ip)
    elif args.command == "unban":
        cmd_unban(conn, args.ip)
    elif args.command == "history":
        cmd_history(hours=args.hours)
    else:
        parser.print_help()

    conn.close()


if __name__ == "__main__":
    main()
