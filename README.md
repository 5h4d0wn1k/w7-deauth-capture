# W7 — Deauth + Capture

Deauthenticate clients and capture WPA handshake for offline cracking.

## Overview

This project implements a WiFi deauthentication attack that:
- Scans for target networks
- Deauthenticates connected clients
- Captures WPA 4-way handshake
- Saves handshake for offline cracking

**WARNING: Educational use only. Test on your own lab network.**

## Hardware

| Component | Connection | Role |
|-----------|------------|------|
| ESP32-C6 | Main board | WiFi attack + capture |

## Serial Commands

```
scan        - Scan for networks
select N    - Select network N
deauth      - Send deauth packets
capture     - Start handshake capture
status      - Show capture status
help        - Show commands
```

## Attack Flow

1. **Scan**: Discover nearby networks
2. **Select**: Choose target network
3. **Deauth**: Force clients to disconnect
4. **Capture**: Wait for reconnection handshake
5. **Crack**: Use aircrack-ng offline

## Build & Flash

```bash
arduino-cli compile --fqbn esp32:esp32:esp32c6 w7_deauth_capture
arduino-cli upload --fqbn esp32:esp32:esp32c6 --port /dev/ttyACM0 w7_deauth_capture
```

## References

- IEEE 802.11 Management Frames
- WPA 4-Way Handshake

## License

MIT

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Using capture output to deauth real networks it wasn't authorized for
- Any activity that violates applicable laws or regulations — this build emits no radio
- Commercial use without proper licensing

### Regulatory Framework
- **Federal Communications Act (47 U.S.C. § 333)**: Willful interference with authorized radio communications is prohibited; this tool never transmits.
- **47 CFR Part 15**: Unauthorized intentional radiators are regulated; the capture path is byte-level simulation only.
- **CFAA / ECPA / Wiretap Act**: Capturing deauth traffic on networks you're not authorized to monitor violates federal and state interception laws.
- **Safety gate**: capture-session *simulation* requires `--i-understand-this-is-an-offline-lab-simulation-with-no-radio-emission` AND a `00:11:22:*` lab target; missing either -> exit 2.

## Live Lab Test Plan

Offline (this repo, no radio):
1. `python3 firmware/deauth_capture.py` — analyze the 15-frame synthetic capture; 2 victims,
   1 forged-source frame, exit 0.
2. Gated capture-session simulation:
   `python3 firmware/deauth_capture.py --capture reports/cap.pcap --target 00:11:22:33:44:66
   --i-understand-this-is-an-offline-lab-simulation-with-no-radio-emission --json reports/w7.json`
   — exit 0. Without the flag or with a non-lab target -> exit 2.
3. `python3 -m unittest discover -s tests` — byte-exact parse/correlation tests (exit 0).

Authorized lab (only with written scope):
4. Against your own test AP/client, capture its deauth frames with authorized tooling and run
   `--analyze captures/<you>.pcap`; confirm victim/AP/attacker correlation matches the lab plan.
5. `green = permitted`: analysis/simulation only by default; any real-air capture or deauth
   requires written scope against equipment you own.

## Metrics

- Deauth parse (byte-exact): FC subtype, DA/SA/BSSID, seq, retry, reason code, FCS verify
- Victim correlation: per-DA frames, AP set, attacker set; reason histogram; forged-source count
- Deterministic fixture: 14-frame storm + 1 spoofed deauth (ATTACKER = locally-administered non-OUI)
- Safety gate: capture simulation requires giant confirmation flag AND lab-OUI target (exit 2 else)
- pcap classic (linktype 105) capture fixture + analyze; captures/ and reports/ gitignored
- Defensive posture: radio_emitted always False; no deauth frames ever transmitted

- Test suite: `python3 -m unittest discover -s tests`
- Reports: `reports/` (gitignored)
- Associated firmware: `firmware/w7_deauth_capture/w7_deauth_capture.ino` (ESP32-C6, ESP-NOW OSD)

## License

MIT
