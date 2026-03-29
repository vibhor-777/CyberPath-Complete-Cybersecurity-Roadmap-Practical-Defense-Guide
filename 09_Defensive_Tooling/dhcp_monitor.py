#!/usr/bin/env python3
"""
dhcp_monitor.py — Rogue DHCP Server Detector

Monitors the network segment for unauthorized DHCPOFFER packets originating
from IP addresses not in the AUTHORIZED_SERVERS allowlist.

Alerts are generated when an offer is seen from an unlisted source.

Usage:
    # Monitor on eth0 with authorized DHCP servers defined inline
    sudo python3 dhcp_monitor.py --interface eth0 --authorized 192.168.1.1 192.168.1.2

    # Custom authorized list and log file
    sudo python3 dhcp_monitor.py --interface eth0 --authorized 10.0.0.1 --log /var/log/dhcp_monitor.log

Requirements:
    pip install scapy

    Root/sudo is required for raw packet capture.

Author: CyberPath Defense Toolkit

⚠️  AUTHORIZED USE ONLY: Only monitor networks you own or have explicit
    written permission to monitor.
"""

import argparse
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Set

try:
    from scapy.all import BOOTP, DHCP, UDP, IP, Ether, sniff, conf
except ImportError:
    print("[ERROR] scapy is required: pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(log_file: str) -> logging.Logger:
    """Configure logging to console and file."""
    logger = logging.getLogger("dhcp_monitor")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    try:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError as e:
        logger.warning("Could not open log file %s: %s", log_file, e)

    return logger


# ---------------------------------------------------------------------------
# Packet Analysis
# ---------------------------------------------------------------------------

def get_dhcp_message_type(packet) -> str:
    """Extract the DHCP message type from a packet."""
    if not packet.haslayer(DHCP):
        return "UNKNOWN"

    dhcp_options = packet[DHCP].options
    for option in dhcp_options:
        if isinstance(option, tuple) and option[0] == "message-type":
            msg_type = option[1]
            type_map = {
                1: "DISCOVER",
                2: "OFFER",
                3: "REQUEST",
                4: "DECLINE",
                5: "ACK",
                6: "NAK",
                7: "RELEASE",
                8: "INFORM",
            }
            return type_map.get(msg_type, f"TYPE_{msg_type}")
    return "UNKNOWN"


def extract_offered_ip(packet) -> str:
    """Extract the IP address being offered in a DHCPOFFER."""
    if packet.haslayer(BOOTP):
        return packet[BOOTP].yiaddr
    return "0.0.0.0"


def extract_dhcp_options(packet) -> dict:
    """Extract useful DHCP options from a packet as a dict."""
    result = {}
    if not packet.haslayer(DHCP):
        return result

    for option in packet[DHCP].options:
        if not isinstance(option, tuple):
            continue
        name, value = option[0], option[1] if len(option) > 1 else None
        if name in ("router", "subnet_mask", "name_server", "domain", "lease_time"):
            result[name] = str(value) if value is not None else ""

    return result


class RogueDHCPMonitor:
    """
    Monitors DHCP traffic and alerts on offers from unauthorized servers.
    """

    def __init__(
        self,
        interface: str,
        authorized_servers: Set[str],
        logger: logging.Logger,
    ):
        self.interface = interface
        self.authorized_servers = authorized_servers
        self.logger = logger
        self.packets_seen = 0
        self.alerts_fired = 0
        self.seen_rogue_ips: Set[str] = set()

    def process_packet(self, packet) -> None:
        """Callback invoked by scapy for each captured packet."""
        # We only care about DHCP packets
        if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP) and packet.haslayer(UDP)):
            return

        self.packets_seen += 1
        msg_type = get_dhcp_message_type(packet)

        # Only alert on DHCPOFFER packets — these are the ones that assign configuration
        if msg_type != "OFFER":
            return

        # Extract source IP
        src_ip = "0.0.0.0"
        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(Ether):
            # Fall back to source MAC if no IP header (DHCP is broadcast)
            src_ip = packet[Ether].src

        offered_ip   = extract_offered_ip(packet)
        dhcp_options = extract_dhcp_options(packet)
        src_mac = packet[Ether].src if packet.haslayer(Ether) else "unknown"

        # Check if source is authorized
        if src_ip not in self.authorized_servers:
            self.alerts_fired += 1
            is_first = src_ip not in self.seen_rogue_ips
            self.seen_rogue_ips.add(src_ip)

            alert_msg = (
                f"ROGUE DHCP OFFER DETECTED | "
                f"src_ip={src_ip} | src_mac={src_mac} | "
                f"offered_ip={offered_ip} | "
                f"router={dhcp_options.get('router', 'N/A')} | "
                f"dns={dhcp_options.get('name_server', 'N/A')}"
            )
            self.logger.warning(alert_msg)

            # Print prominent alert to console
            print("\n" + "!" * 70)
            print(f"  🚨 ALERT: ROGUE DHCP SERVER DETECTED")
            print(f"  Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Source IP  : {src_ip}")
            print(f"  Source MAC : {src_mac}")
            print(f"  Offered IP : {offered_ip}")
            print(f"  Router     : {dhcp_options.get('router', 'N/A')}")
            print(f"  DNS        : {dhcp_options.get('name_server', 'N/A')}")
            print(f"  Subnet     : {dhcp_options.get('subnet_mask', 'N/A')}")
            if is_first:
                print(f"\n  ⚠️  ACTION REQUIRED:")
                print(f"     1. Locate and isolate the device at MAC {src_mac}")
                print(f"     2. Block IP {src_ip} at the switch (port security or DHCP Snooping)")
                print(f"     3. Investigate whether clients received rogue gateway {dhcp_options.get('router','N/A')}")
            print("!" * 70 + "\n")
        else:
            self.logger.debug(
                "Authorized DHCPOFFER from %s offering %s", src_ip, offered_ip
            )

    def start(self, count: int = 0, timeout: int = 0) -> None:
        """
        Start packet capture.

        Args:
            count:   Number of packets to capture (0 = unlimited)
            timeout: Timeout in seconds (0 = no timeout)
        """
        self.logger.info(
            "Starting DHCP monitor on interface '%s'", self.interface
        )
        self.logger.info(
            "Authorized DHCP servers: %s",
            ", ".join(sorted(self.authorized_servers)) or "NONE",
        )
        self.logger.info("Filtering for DHCPOFFER packets (UDP port 67)...")

        # BPF filter: Only capture UDP traffic on DHCP port 67 (server-side)
        bpf_filter = "udp and (port 67 or port 68)"

        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.process_packet,
                store=False,
                count=count if count > 0 else 0,
                timeout=timeout if timeout > 0 else None,
            )
        except PermissionError:
            self.logger.error(
                "Permission denied. Raw packet capture requires root/sudo privileges."
            )
            sys.exit(1)
        except OSError as e:
            self.logger.error("Capture error on interface '%s': %s", self.interface, e)
            sys.exit(1)


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

_monitor_instance = None


def _handle_sigint(signum, frame):
    """Graceful shutdown on Ctrl+C."""
    print("\n\n[INFO] Shutting down DHCP monitor...")
    if _monitor_instance:
        print(
            f"[INFO] Stats: {_monitor_instance.packets_seen} DHCP packets seen, "
            f"{_monitor_instance.alerts_fired} rogue DHCP alerts fired."
        )
    sys.exit(0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "CyberPath Rogue DHCP Monitor — Detects unauthorized DHCP servers on your network segment.\n"
            "Requires root/sudo for raw packet capture."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 dhcp_monitor.py --interface eth0 --authorized 192.168.1.1
  sudo python3 dhcp_monitor.py --interface ens33 --authorized 10.0.0.1 10.0.0.2 --log /var/log/dhcp.log

⚠️  Only use on networks you own or have explicit written authorization to monitor.
        """,
    )
    parser.add_argument(
        "--interface", "-i", required=True,
        help="Network interface to capture on (e.g., eth0, ens33, wlan0)"
    )
    parser.add_argument(
        "--authorized", nargs="*", default=[],
        help="Space-separated list of authorized DHCP server IP addresses"
    )
    parser.add_argument(
        "--log", default="dhcp_monitor.log",
        help="Alert log file path (default: dhcp_monitor.log)"
    )
    parser.add_argument(
        "--timeout", type=int, default=0,
        help="Stop capturing after N seconds (0 = run indefinitely)"
    )
    parser.add_argument(
        "--count", type=int, default=0,
        help="Stop after N DHCP packets captured (0 = unlimited)"
    )
    args = parser.parse_args()

    logger = setup_logging(args.log)
    authorized = set(args.authorized)

    if not authorized:
        logger.warning(
            "No authorized DHCP servers specified. ALL DHCPOFFER packets will trigger alerts."
        )

    global _monitor_instance
    _monitor_instance = RogueDHCPMonitor(
        interface=args.interface,
        authorized_servers=authorized,
        logger=logger,
    )

    signal.signal(signal.SIGINT, _handle_sigint)

    print("\n" + "=" * 70)
    print("  CyberPath Rogue DHCP Monitor")
    print(f"  Interface  : {args.interface}")
    print(f"  Authorized : {', '.join(sorted(authorized)) or 'none (all offers will alert)'}")
    print(f"  Log file   : {args.log}")
    print("  Press Ctrl+C to stop.")
    print("=" * 70 + "\n")

    _monitor_instance.start(count=args.count, timeout=args.timeout)


if __name__ == "__main__":
    main()
