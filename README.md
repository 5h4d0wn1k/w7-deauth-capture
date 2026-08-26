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
