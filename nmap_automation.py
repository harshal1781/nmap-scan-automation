#!/usr/bin/env python3
"""
nmap_automation.py - improved

Usage:
    sudo python3 nmap_automation.py <target> [--udp]

Example:
    sudo python3 nmap_automation.py 192.168.0.110
    sudo python3 nmap_automation.py 192.168.0.110 --udp
"""

import sys
import nmap
from datetime import datetime

def run_nmap_scan(target_ip, use_udp=False):
    nm = nmap.PortScanner()
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[*] Starting Nmap scan on {target_ip} (udp={use_udp}) ...")

    args = '-sS -sV'
    if use_udp:
        # include UDP - note this will slow the scan and may require sudo
        args = '-sS -sV -sU'

    try:
        nm.scan(target_ip, arguments=args)
    except nmap.PortScannerError as e:
        print("[!] Scan Error:", e)
        print("[*] Ensure nmap is installed and you have appropriate privileges.")
        return None

    report_lines = []
    report_lines.append("Nmap Scan Report")
    report_lines.append("-" * 60)
    report_lines.append(f"Scan initiated at: {scan_time}")
    report_lines.append(f"Target: {target_ip}")
    report_lines.append("")

    if not nm.all_hosts():
        report_lines.append("No hosts found or host is blocking probes.")
        return "\n".join(report_lines)

    for host in nm.all_hosts():
        hostinfo = nm[host]
        hostname = hostinfo.hostname() or ""
        state = hostinfo.state() or ""
        report_lines.append(f"Host: {host} {('(' + hostname + ')') if hostname else ''}")
        report_lines.append(f"State: {state}")
        report_lines.append("Open Ports:")
        report_lines.append("{:<8} {:<10} {:<20} {}".format("PORT", "STATE", "SERVICE", "VERSION"))
        report_lines.append("-" * 60)

        for proto in hostinfo.all_protocols():
            ports = sorted(hostinfo[proto].keys())
            for port in ports:
                port_info = hostinfo[proto][port]
                state = port_info.get('state', '')
                service = port_info.get('name', '')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                # Report open and possibly open|filtered entries depending on proto
                if state in ('open', 'open|filtered'):
                    report_lines.append("{:<8} {:<10} {:<20} {}".format(f"{port}/{proto}", state, service, f"{product} {version}".strip()))
        report_lines.append("")

    report_lines.append("-" * 30)
    report_lines.append("[*] Scan Complete.")
    return "\n".join(report_lines)

def save_report(report_content, filename="scan_report.txt"):
    try:
        with open(filename, 'w') as f:
            f.write(report_content)
        print(f"[+] Report saved to {filename}")
    except IOError as e:
        print(f"[!] Error saving report: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 nmap_automation.py <target> [--udp]")
        sys.exit(1)

    target = sys.argv[1]
    use_udp = ('--udp' in sys.argv)
    result = run_nmap_scan(target, use_udp=use_udp)
    if result:
        save_report(result)
