# WPA3 Transition Mode Downgrade Attack Toolkit

> **Educational / Research Use Only**  
> This project is intended for academic study of WPA3 transition mode weaknesses and **must only be used on networks you own or have explicit written permission to test.**

---

## 1. Overview

This project demonstrates a **WPA3-Personal transition mode downgrade attack**:

- It identifies **WPA3-SAE + WPA2-PSK mixed / transition networks**.
- It lures clients away from the legitimate WPA3 AP to a **rogue WPA2 AP** with the same SSID.
- It captures the **WPA2 4-way handshake** so that a traditional offline password cracking attack can be attempted.
- Optionally, it can **stress the SAE/Dragonfly handshake** using a clogging (anti-clogging token) attack at the frame level.

The toolkit automates most of the workflow around scanning, detection, and rogue AP setup; deauthentication and password cracking are left to existing tools (e.g. `aireplay-ng`, `hashcat`).

---

## 2. Components

### 2.1 `attack.py` – Automated Transition Downgrade Orchestrator

Main features:

- Checks for required tools (`ip`, `iw`, `airodump-ng`, `airmon-ng`, `hostapd-mana`).
- Runs `airodump-ng` to capture nearby APs in PCAP format.
- Parses RSN/WPA IEs (via Scapy) to identify:
  - WPA3 networks (SAE)
  - WPA3 transition networks (SAE + PSK)
  - Weak / optional MFP settings
- Lets you **interactively select vulnerable APs** to target.
- Captures client stations connected to each selected AP via `airodump-ng` CSV.
- Generates **`hostapd-mana` config files** for a rogue WPA2-PSK AP (same SSID, chosen channel).
- Launches the rogue AP and **watches output** for a captured WPA(2) handshake (`*.hccapx`) ready for `hashcat`.

### 2.2 `sae_clogging_attack.c` – SAE Commit Flood / Clogging PoC

C program that:

- Opens a **raw AF_PACKET socket** on a wireless interface.
- Crafts many **fake SAE commit frames** with random spoofed source MAC addresses.
- Sends them to a target AP MAC, potentially triggering the **anti-clogging token mechanism** and stressing AP resources.
- Spawns a receiver thread to listen for SAE commit responses containing anti-clogging tokens (for demonstration/logging).

### 2.3 `scanner.py` – Passive WPA3 Transition Scanner

Helper script that:

- Uses `iw dev <iface> scan` (or `iwlist <iface> scanning` as fallback).
- Parses output to recover:
  - SSID
  - BSSID
  - AKM (Authentication and Key Management) suites
- Flags networks that advertise **both SAE and PSK AKM** as:

> `TRANSITION/MIXED (may allow downgrade)`

This is useful to quickly check if an environment even has WPA3 transition mode networks before running the full attack.

---

## 3. Repository Structure

Suggested layout:

```text
.
├── attack.py               # Main WPA3 transition-mode downgrade automation script
├── sae_clogging_attack.c   # SAE commit clogging / anti-clogging token PoC
└── scanner.py              # Passive scanner to locate SAE+PSK transition networks
```

---

## 4. Requirements

### 4.1 Hardware

- Linux machine (laptop/PC) with:
  - **At least one** Wi-Fi interface supporting monitor mode.
  - **Ideally two** Wi-Fi interfaces:
    - One in **monitor mode** for scanning/deauth.
    - One in **managed mode** for running the rogue AP.

### 4.2 Software / Tools

- Linux (Kali, Ubuntu, etc.) with:
  - `ip`, `iw`
  - `airodump-ng`, `airmon-ng` (from `aircrack-ng` suite)
  - `hostapd-mana`
  - `iwlist` (optional fallback for `scanner.py`)
- Python 3 with modules:
  - `scapy`
  - `colorama`
- C toolchain for SAE clogging PoC:
  - `gcc`
  - POSIX threads (`-lpthread`)
  - Raw socket support (requires root)

Install Python dependencies (example):

```bash
sudo pip3 install scapy colorama
```

---

## 5. Setup

1. Clone or copy this project to your machine.
2. Ensure your user has sudo/root access.
3. Enable monitor mode on one Wi-Fi interface, e.g.:

   ```bash
   sudo airmon-ng start wlan0
   # -> gives wlan0mon
   ```

4. Keep another interface in managed mode (e.g. `wlan1`) for the rogue AP if available.

---

## 6. Usage

### 6.1 Discover WPA3 Transition Networks (`scanner.py`)

Quick check using passive scan:

```bash
sudo python3 scanner.py            # auto-detect interface
# or
sudo python3 scanner.py wlan0
```

Example output (simplified):

```text
SSID                                     BSSID               AKM(s)            Flag
--------------------------------------------------------------------------------------------
MyHomeWiFi                               aa:bb:cc:dd:ee:ff   SAE,PSK           TRANSITION/MIXED (may allow downgrade)
```

Use this to identify candidate SSIDs that use WPA3-SAE + WPA2-PSK.

---

### 6.2 Run the Downgrade Workflow (`attack.py`)

Basic syntax:

```bash
# Recommended: 2 interfaces (monitor + managed)
sudo python3 attack.py -m wlan0mon -r wlan1

# Passive mode: single interface (less control over reconnections)
sudo python3 attack.py -m wlan0mon
```

What the script does:

1. **Pre-checks**
   - Confirms root privileges.
   - Verifies required tools are installed.
   - Verifies monitor/managed mode for given interfaces.

2. **Initial scan**
   - Runs `airodump-ng` for ~60 seconds, saving a `discovery-*.pcap` capture in a timestamped folder (e.g. `scan-YYYY-MM-DD-HH-MM/`).

3. **Analyze RSN / WPA IEs**
   - Extracts SSID/BSSID, ciphers, AKM (PSK/SAE), and MFP capabilities.
   - Identifies:
     - **WPA3 transition (SAE+PSK)** networks.
     - WPA3 networks with weak/optional MFP.

4. **AP selection**
   - Shows a numbered list of vulnerable APs.
   - You can choose:
     - A subset (`1,3,5`)
     - `all`
     - `none` (abort)

5. **Station capture**
   - For each selected AP, runs `airodump-ng` again (BSSID + channel) to enumerate **associated client stations**.
   - Parses CSV and displays station MACs.

6. **Rogue AP configuration**
   - For each AP with at least one station:
     - Generates a `hostapd-mana` config file, e.g.:

       ```text
       interface=<managed_iface>
       driver=nl80211
       hw_mode=g
       channel=<channel>
       ssid=<target_ssid>
       mana_wpaout=/absolute/path/<SSID>-handshake.hccapx
       wpa=2
       wpa_key_mgmt=WPA-PSK
       wpa_pairwise=TKIP CCMP
       wpa_passphrase=12345678
       ```

7. **Launching the rogue AP**
   - Asks:

     ```text
     Stations are connected. Would you like to start the attack? (y/n)
     ```

   - On `y`, starts `hostapd-mana` with the generated configs and monitors output.
   - When a WPA(2) handshake is captured, it prints a success message and stops the rogue AP.

8. **Offline password cracking (manual step)**
   - After a handshake is captured, you can use `hashcat` (or similar) manually, e.g.:

     ```bash
     hashcat -a 0 -m 2500 <SSID>-handshake.hccapx <wordlist> --force
     ```

   - This step is **not automated** in the script; you bring your own wordlist and cracking strategy.

---

### 6.3 Optional: SAE Clogging / Anti-Clogging Token PoC (`sae_clogging_attack.c`)

> **Warning:** This can stress target AP resources; treat it as a denial-of-service style research PoC.  
> Only use on testbed/own APs where such testing is explicitly permitted.

#### Compile

```bash
gcc -o sae_clogging_attack sae_clogging_attack.c -lpthread
```

#### Run

```bash
sudo ./sae_clogging_attack wlan0mon 00:11:22:33:44:55
#           ^iface in monitor/raw-capable mode   ^target AP MAC
```

What it does:

- Sends many fake **SAE commit frames** from random spoofed MACs to the AP.
- Listens for SAE responses that may contain **anti-clogging tokens** (logged to stdout).
- Demonstrates how an attacker could force the AP into its **anti-clogging defense path**.

---

## 7. Attack Flow Summary

1. Use `scanner.py` to detect WPA3 transition networks (SAE+PSK).
2. Use `attack.py` to:
   - scan and find vulnerable APs,
   - identify associated client stations,
   - spin up a rogue WPA2 AP.
3. (Optionally) use deauthentication via `aireplay-ng` or similar tools.
4. Capture the WPA2 handshake and run offline password cracking.
5. (Optional) experiment with `sae_clogging_attack` for SAE anti-clogging behavior.

---

## 8. Limitations & Notes

- Requires Wi-Fi hardware with good driver support for monitor mode and raw injection.
- Behavior of WPA3, SAE, and transition mode can vary between vendors and firmware versions.
- Management Frame Protection (MFP) configuration may mitigate some attack vectors.
- This toolkit **does not** automatically perform deauthentication or password cracking; those steps remain manual by design.

---

## 9. Legal & Ethical Disclaimer

- Use of this code **without authorization** on third-party networks may violate local laws and institutional policies.
- The authors and contributors of this project accept **no liability** for misuse.
- Always obtain **explicit permission** and follow your organization’s **responsible disclosure** and **testing** policies.
- Treat all experiments as part of a controlled, ethical security evaluation or academic lab.
