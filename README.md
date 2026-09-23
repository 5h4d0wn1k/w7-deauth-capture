> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# W7 — Deauth Capture & Handshake-Hunter (Wi-Fi Security Lab)

Offline deauth-capture analysis toolkit: byte-exact deauth frame parsing, per-victim attacker/AP correlation, synthetic capture fixtures, and pcap analysis — with an ESP32-C6 reference firmware. No radio is ever emitted.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/w7-deauth-capture.svg)](https://github.com/5h4d0wn1k/w7-deauth-capture)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/w7-deauth-capture.svg)](https://github.com/5h4d0wn1k/w7-deauth-capture)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/w7-deauth-capture.svg)](https://github.com/5h4d0wn1k/w7-deauth-capture)

## Why

Deauthentication attacks are a classic Wi-Fi disruption technique — and one best understood by dissecting the frames, not by disrupting a network. W7 teaches the mechanics offscreen: parse 802.11 deauth management frames byte-exactly (subtype, DA/SA/BSSID, sequence, retry, reason code, FCS), correlate them per victim to isolate attacker and AP frames, and analyze `.pcap` captures you own. The demo runs against a deterministic synthetic fixture that includes a forged-source frame, so the defensive tradecraft (spotting forged deauths) can be practiced without touching the air.

## Features

- **Byte-exact deauth parsing** — frame control subtype, DA/SA/BSSID, seq, retry, reason code, FCS verify
- **Victim correlation** — per-DA frames, AP set, attacker set, reason histogram, forged-source count
- **Deterministic fixture** — 14-frame storm + 1 spoofed deauth (locally-administered non-OUI attacker), `--gen-fixture`
- **Capture-session simulation** — gated `--capture` writes a classic pcap (linktype 105) with lab-OUI targets
- **pcap analysis** — `--analyze captures/<file>.pcap` for captures you own
- **Hard safety gate** — requires `--i-understand-this-is-an-offline-lab-simulation-with-no-radio-emission` and a `00:11:22:` lab target; anything else exits 2

## Quickstart

```bash
git clone https://github.com/5h4d0wn1k/w7-deauth-capture.git && cd w7-deauth-capture

# Analyze the bundled synthetic capture (offline, no flag needed)
python3 firmware/deauth_capture.py

# Gated capture-session simulation to pcap (no radio)
python3 firmware/deauth_capture.py --capture reports/cap.pcap \
    --target 00:11:22:33:44:66 \
    --i-understand-this-is-an-offline-lab-simulation-with-no-radio-emission \
    --json reports/w7.json

# Analyze a pcap you own
python3 firmware/deauth_capture.py --analyze captures/you.pcap

# Unit tests
python3 -m unittest discover -s tests
```

## Project structure

- `firmware/deauth_capture.py` — parser, correlator, capture/analyze CLI; `firmware/frame_core.py` — frame builder
- `firmware/w7_deauth_capture/` — ESP32-C6 reference firmware (Arduino, ESP-NOW OSD)
- `tests/` — byte-exact parse and correlation tests; `captures/`, `reports/` gitignored

## Documentation

- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New parse rules, correlation metrics and fixture coverage are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); the project stays passive — simulation and analysis only.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized wireless-security lab use only.