#!/usr/bin/env python3
"""
scanner.py - Passive Wi-Fi capability scanner (defensive use only).

Usage:
  sudo python3 scanner.py            # auto-detect wireless iface
  sudo python3 scanner.py wlp1s0    # specify iface

Notes:
 - Only run on networks you own or have explicit permission to scan.
 - Requires 'iw' or 'iwlist' installed.
"""

import subprocess
import sys
import re
from collections import defaultdict
import shutil

def cmd_exists(name):
    return shutil.which(name) is not None

def run_cmd(cmd, timeout=15):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    except subprocess.CalledProcessError as e:
        return None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None

def detect_wireless_interfaces():
    # Prefer 'iw dev' if available
    if cmd_exists("iw"):
        out = run_cmd(["iw", "dev"])
        if out:
            # find lines like: "Interface wlp1s0"
            ifaces = re.findall(r"Interface\s+([^\s]+)", out)
            return ifaces
    # fallback to listing interfaces and filtering common wireless name patterns
    out = run_cmd(["ip", "link", "show"])
    if out:
        ifaces = re.findall(r"^\d+:\s+([^:]+):", out, flags=re.M)
        # heuristics for likely wireless interfaces
        candidates = [i for i in ifaces if re.search(r"wl|wlan|wifi|ath|wlp", i)]
        return candidates
    return []

def scan_with_iw(iface):
    out = run_cmd(["iw", "dev", iface, "scan"])
    return out

def scan_with_iwlist(iface):
    out = run_cmd(["iwlist", iface, "scanning"])
    return out

def parse_iw_output(iw_text):
    if not iw_text:
        return []
    entries = []
    current = {}
    for line in iw_text.splitlines():
        line = line.rstrip()
        if not line:
            if current:
                entries.append(current)
                current = {}
            continue
        m_bss = re.match(r"^BSS\s+([0-9a-f:]+)", line)
        if m_bss:
            if current:
                entries.append(current)
            current = {"bssid": m_bss.group(1), "raw": []}
            continue
        if current is not None:
            current.setdefault("raw", []).append(line)
    if current:
        entries.append(current)
    return entries

def parse_iwlist_output(iwlist_text):
    # Simpler parser for iwlist output
    if not iwlist_text:
        return []
    entries = []
    current = {"raw": []}
    bssid = None
    for line in iwlist_text.splitlines():
        line = line.strip()
        if not line:
            continue
        m_bss = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", line)
        if m_bss:
            if current.get("raw"):
                current["bssid"] = bssid or "unknown"
                entries.append(current)
                current = {"raw": []}
            bssid = m_bss.group(1)
            continue
        current["raw"].append(line)
    if current.get("raw"):
        current["bssid"] = bssid or "unknown"
        entries.append(current)
    return entries

def extract_fields_from_raw(entry):
    ssid = None
    akm_suites = set()
    for line in entry.get("raw", []):
        # common SSID markers (varies)
        m = re.search(r"SSID:\s*(.*)$", line)
        if m:
            ssid = m.group(1).strip()
            continue
        # iwlist style: ESSID:"MyNet"
        m2 = re.search(r'ESSID:"(.*)"', line)
        if m2:
            ssid = m2.group(1)
            continue
        if "SAE" in line.upper():
            akm_suites.add("SAE")
        if "PSK" in line.upper() or "WPA2-PSK" in line.upper() or "WPA-PSK" in line.upper():
            akm_suites.add("PSK")
        if "AKM suite" in line or "AKM Suites" in line or re.search(r"00-0f-ac:\d+", line, flags=re.I):
            if "00-0f-ac:8" in line or re.search(r"00-0f-ac:8", line, flags=re.I):
                akm_suites.add("SAE")
            if "00-0f-ac:2" in line or "00-0f-ac:1" in line:
                akm_suites.add("PSK")
    return ssid or "<hidden>", akm_suites

def main():
    if len(sys.argv) > 1:
        iface = sys.argv[1]
    else:
        ifaces = detect_wireless_interfaces()
        if not ifaces:
            print("No wireless interfaces detected. Make sure the device has a Wi-Fi adapter and drivers are loaded.")
            print("Try: 'iw dev' or 'ip link show' to inspect interfaces.")
            sys.exit(2)
        iface = ifaces[0]
        print(f"Auto-detected wireless interface: {iface}")

    print("**ONLY scan networks you own or have explicit permission to test.**\n")

    if cmd_exists("iw"):
        print(f"Trying 'iw dev {iface} scan' ...")
        raw = scan_with_iw(iface)
        if raw is None:
            print("`iw` scan failed or returned no output. Possible reasons:")
            print(" - interface name is wrong")
            print(" - the interface is managed by NetworkManager and cannot do scan in this mode")
            print(" - driver does not support scanning from userspace in this environment (e.g., inside some VMs)")
            print("Trying fallback: 'iwlist' if available...\n")
        else:
            entries = parse_iw_output(raw)
            results = defaultdict(set)
            for e in entries:
                ssid, akm = extract_fields_from_raw(e)
                bssid = e.get("bssid", "unknown")
                results[(ssid, bssid)] |= akm
            if results:
                print(f"{'SSID':40} {'BSSID':20} {'AKM(s)':20} {'Flag'}")
                print("-"*100)
                for (ssid, bssid), akm in sorted(results.items(), key=lambda x: x[0][0].lower()):
                    akm_str = ",".join(sorted(akm)) if akm else "UNKNOWN"
                    flag = "TRANSITION/MIXED (may allow downgrade)" if "SAE" in akm and "PSK" in akm else ""
                    print(f"{ssid:40} {bssid:20} {akm_str:20} {flag}")
                return
            else:
                # continue to fallback
                pass

    if cmd_exists("iwlist"):
        print(f"Trying fallback 'iwlist {iface} scanning' ...")
        raw2 = scan_with_iwlist(iface)
        if raw2 is None:
            print("`iwlist` also failed. See diagnostic tips below.")
        else:
            entries = parse_iwlist_output(raw2)
            results = defaultdict(set)
            for e in entries:
                ssid, akm = extract_fields_from_raw(e)
                bssid = e.get("bssid", "unknown")
                results[(ssid, bssid)] |= akm
            if results:
                print(f"{'SSID':40} {'BSSID':20} {'AKM(s)':20} {'Flag'}")
                print("-"*100)
                for (ssid, bssid), akm in sorted(results.items(), key=lambda x: x[0][0].lower()):
                    akm_str = ",".join(sorted(akm)) if akm else "UNKNOWN"
                    flag = "TRANSITION/MIXED (may allow downgrade)" if "SAE" in akm and "PSK" in akm else ""
                    print(f"{ssid:40} {bssid:20} {akm_str:20} {flag}")
                return
            else:
                print("No results parsed from iwlist output.")

    # If we reach here, scanning failed
    print("\nScanning failed. Diagnostic checklist:")
    print(" - Are you running as root? (use sudo)")
    print(" - Is the interface correct? e.g. run 'iw dev' or 'ip link show' to inspect available interfaces.")
    print(" - Is 'iw' or 'iwlist' installed? Install with: sudo apt install iw wireless-tools")
    print(" - If running inside a VM, does the VM expose the Wi-Fi adapter in passthrough mode? Many VMs present the adapter as ethernet; without a real Wi-Fi device inside the VM scanning won't work.")
    print(" - For more detailed debugging, try: sudo iw dev <iface> scan  and examine the error output.")
    sys.exit(2)

if __name__ == "__main__":
    main()

