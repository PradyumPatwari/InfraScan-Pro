#!/usr/bin/python3
import os
import sys
import nmap
import ipaddress
import socket
import datetime
import scapy.all as scapy

# ============================================
# ROOT PRIVILEGE CHECK (IMPORTANT FOR SNIFFING)
# ============================================
if os.geteuid() != 0:
    print("❌ ERROR: This tool must be run as ROOT for packet sniffing & network access.")
    print("➡ Use: sudo python3 script.py")
    sys.exit(1)

# ============================================
# UTILITY FUNCTIONS
# ============================================

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False


def grab_banner(ip, port):
    """Simple banner grabbing."""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        return banner.strip()
    except:
        return None


def save_report(ip, text):
    filename = f"scan_report_{ip}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(text)
    print(f"\n📄 Report saved as: {filename}")


# ============================================
# OFFLINE CVE DATABASE (SAFE)
# ============================================

cve_db = {
    "vsftpd": ["Possible misconfigurations; no known exploits after 2.3.4"],
    "openssh": ["CVE-2018-15473 - User enumeration"],
    "apache": ["CVE-2021-41773 - Path traversal"],
    "nginx": ["Moderate CVEs depending on version"]
}

def lookup_cve(service):
    service = service.lower()
    for key in cve_db:
        if key in service:
            return cve_db[key]
    return ["No CVEs in offline DB"]

# ============================================
# INTERFACE DETECTION (FIXES wlan0 ERROR)
# ============================================

def list_interfaces():
    print("\n🔍 Available Network Interfaces:")
    interfaces = scapy.get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    return interfaces


# ============================================
# FULL NMAP SCAN (ADVANCED)
# ============================================

def full_nmap_scan(ip):
    scanner = nmap.PortScanner()

    print("\nChoose scan type:")
    print("1. SYN Scan (-sS)")
    print("2. UDP Scan (-sU)")
    print("3. OS Detection (-O)")
    print("4. Aggressive Scan (-A)")
    print("5. Vulnerability Scan (--script vuln)")

    choice = input("Select: ")

    scan_args = {
        "1": "-sS -sV -T4",
        "2": "-sU -sV -T4",
        "3": "-O -sV",
        "4": "-A -T4",
        "5": "--script vuln -sV"
    }

    if choice not in scan_args:
        return "❌ Invalid scan type."

    print("\n[+] Running Nmap scan... please wait...\n")
    scanner.scan(ip, "1-1000", arguments=scan_args[choice])

    output = ""
    output += f"Scan Report for {ip}\n"
    output += "=" * 40 + "\n"
    output += f"Host State: {scanner[ip].state()}\n"

    # OS Detection
    if "osmatch" in scanner[ip]:
        output += "\n[OS Detection]\n"
        for osinfo in scanner[ip]["osmatch"]:
            output += f"- {osinfo['name']} (Accuracy: {osinfo['accuracy']}%)\n"

    # Ports
    output += "\n[Ports]\n"
    for proto in scanner[ip].all_protocols():
        output += f"\nProtocol: {proto}\n"
        for port in scanner[ip][proto]:
            info = scanner[ip][proto][port]
            service = info.get("name", "")
            version = info.get("version", "")

            output += f"\nPort: {port}\n"
            output += f"Service: {service}\n"
            output += f"Version: {version}\n"
            output += f"State: {info['state']}\n"

            # Banner
            banner = grab_banner(ip, port)
            if banner:
                output += f"Banner: {banner}\n"

            # Possible CVEs
            output += "Possible CVEs:\n"
            for cve in lookup_cve(service):
                output += f"- {cve}\n"

    return output


# ============================================
# PACKET SNIFFING (FIXED)
# ============================================

def packet_sniff():
    interfaces = list_interfaces()

    choice = input("\nSelect interface number: ")

    try:
        iface = interfaces[int(choice) - 1]
    except:
        print("❌ Invalid selection!")
        return

    duration = int(input("Enter capture duration (seconds): "))

    print(f"\n[+] Sniffing packets on {iface} for {duration} seconds...")
    packets = scapy.sniff(iface=iface, timeout=duration)

    filename = f"capture_{datetime.datetime.now().strftime('%H%M%S')}.pcap"
    scapy.wrpcap(filename, packets)

    print(f"[+] Capture saved as: {filename}")
    print("➡ You can open it in Wireshark.")


# ============================================
# HOST DISCOVERY
# ============================================

def network_sweep():
    network = input("Enter network range (e.g., 192.168.1.0/24): ")
    print("\n[+] Scanning for live hosts...\n")

    ans, _ = scapy.arping(network, timeout=2, verbose=False)
    for _, rcv in ans:
        print(f"IP: {rcv.psrc} | MAC: {rcv.hwsrc}")


# ============================================
# BANNER GRABBING
# ============================================

def banner_grabbing():
    ip = input("Enter IP: ")
    port = int(input("Enter Port: "))

    banner = grab_banner(ip, port)
    if banner:
        print("\nBanner Detected:")
        print(banner)
    else:
        print("No banner received.")


# ============================================
# MAIN PROGRAM LOOP
# ============================================

print("====================================")
print("🔥 MULTI-FEATURE NETWORK TOOL v3.6")
print("====================================")

ip = input("\nEnter target IP: ")

if not is_valid_ip(ip):
    print("❌ Invalid IP.")
    sys.exit()

last_report = ""

while True:
    print("\n===== Main Menu =====")
    print("1. Full Nmap Scan")
    print("2. Packet Sniffing (like Wireshark)")
    print("3. Host Discovery (Network Sweep)")
    print("4. Banner Grabbing")
    print("5. Save Last Report")
    print("6. Change IP")
    print("7. Exit")

    choice = input("Select: ")

    if choice == "1":
        last_report = full_nmap_scan(ip)
        print("\n===== SCAN OUTPUT =====\n")
        print(last_report)

    elif choice == "2":
        packet_sniff()

    elif choice == "3":
        network_sweep()

    elif choice == "4":
        banner_grabbing()

    elif choice == "5":
        if last_report:
            save_report(ip, last_report)
        else:
            print("❌ No report available to save.")

    elif choice == "6":
        new_ip = input("Enter new IP: ")
        if is_valid_ip(new_ip):
            ip = new_ip
        else:
            print("❌ Invalid IP.")

    elif choice == "7":
        print("Exiting...")
        break

    else:
        print("❌ Invalid option, try again.")
