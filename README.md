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
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept
