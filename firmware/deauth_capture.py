#!/usr/bin/env python3
"""W7 — Deauth Capture (offscreen sniff + victim correlation).

Sniffs synthetic deauth traffic the way the ESP32/CC1101 sketch would: parses
each deauth off the wire (CRC, reason, addressing, seq, retry), correlates
victims (DA) with attacker (SA) and AP (BSSID), and emits capture-session
stats. Armed with a passive-only stance: the simulated capture session is
gated behind a confirmation flag AND a lab-OUI target.

The analysis path (--analyze) needs no radio flag — it only reads bytes that
an authorized capture already produced. No deauth frames are ever transmitted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict

try:
    from firmware import frame_core as fc
except ImportError:
    try:
        import frame_core as fc
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "firmware"))
        import frame_core as fc

SAFETY_FLAG = "--i-understand-this-is-an-offline-lab-simulation-with-no-radio-emission"
START_TS = 1700000000.0
LAB_TARGET = "00:11:22:33:44:66"
LAB_AP = "00:11:22:33:44:55"
ATTACKER = "02:aa:bb:cc:dd:01"


def _is_lab_mac(mac: str) -> bool:
    return mac.startswith("00:11:22")


# ----------------------------------------------------------------------
# Deterministic deauth capture fixture
# ----------------------------------------------------------------------

def build_capture_frames(targets: list[str] = (LAB_TARGET,)) -> list[dict]:
    """Sniffable deauth stream: storm on target + a spoofed one on target2."""
    frames = []
    seq = 0
    t2 = "00:11:22:44:00:22"
    for i in range(14):
        seq = (seq + 1) & 0xFFFF
        d = fc.build_deauth(targets[0], LAB_AP, LAB_AP, reason=7, seq_num=seq,
                            flags=fc.FC_FLAG_RETRY)
        frames.append({"ts": START_TS + 2.0 + 0.03 * i, "kind": "deauth",
                       "da": targets[0], "sa": LAB_AP, "bssid": LAB_AP,
                       "data": d + fc.fcs(d)})
    # spoofed deauth aimed at a second lab victim
    seq = (seq + 1) & 0xFFFF
    d = fc.build_deauth(t2, ATTACKER, LAB_AP, reason=8, seq_num=seq)
    frames.append({"ts": START_TS + 3.0, "kind": "deauth", "da": t2,
                   "sa": ATTACKER, "bssid": LAB_AP, "data": d + fc.fcs(d)})
    frames.sort(key=lambda f: f["ts"])
    return frames


def write_capture_fixture(path: str) -> int:
    frames = build_capture_frames()
    fc.write_pcap(path, [f["data"] for f in frames], ts=frames[0]["ts"])
    return len(frames)


# ----------------------------------------------------------------------
# Sniff / parse / correlate
# ----------------------------------------------------------------------

def parse_deauth(data: bytes) -> dict:
    if not fc.verify_fcs(data):
        raise ValueError("bad FCS")
    payload = data[:-4]
    fields, _ = fc.parse_mgmt_header(payload)
    if fields["subtype_val"] != fc.FC_SUBTYPE_DEAUTH:
        raise ValueError("not a deauth")
    p = fc.parse_deauth(payload)
    return {"da": fields["da"], "sa": fields["sa"], "bssid": fields["bssid"],
            "seq": fields["seq_num"], "reason": p["reason_code"],
            "retry": bool(fields["fc"].get("retry"))}


def correlate(frames: list[dict]) -> dict:
    victims = defaultdict(lambda: {"frames": 0, "aps": set(), "attackers": set()})
    for f in frames:
        v = victims[f["da"]]
        v["frames"] += 1
        v["aps"].add(f["bssid"])
        v["attackers"].add(f["sa"])
    reasons = Counter(f["reason"] for f in frames)
    abs_frames = [f for f in frames if not f["sa"].startswith("00:11:22")
                  or f["sa"] == ATTACKER]
    return {
        "frames_captured": len(frames),
        "unique_victims": len(victims),
        "reason_histogram": dict(reasons),
        "victims": {k: {"frames": v["frames"], "aps": sorted(v["aps"]),
                        "attackers": sorted(v["attackers"])}
                    for k, v in victims.items()},
        "forged_source_frames": len(abs_frames),
    }


def sniff_pcap(path: str) -> list[dict]:
    out = []
    for rec in fc.read_pcap(path):
        try:
            f = parse_deauth(rec["data"])
            f["ts"] = rec["ts"]
            out.append(f)
        except ValueError:
            pass
    return out


# ----------------------------------------------------------------------
# Safety gate for the simulated capture session
# ----------------------------------------------------------------------

def gate_capture(args) -> None:
    """Capture-session simulation requires confirmation + lab-OUI target."""
    if not args.confirm:
        raise SystemExit(2)
    if not args.target:
        raise SystemExit(2)
    if not _is_lab_mac(args.target) and args.target != "00:11:22:44:00:22":
        raise SystemExit(2)


# ----------------------------------------------------------------------
# CLI / demo
# ----------------------------------------------------------------------

def build_args_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="w7-deauth-capture",
        description="Deauth capture (simulated sniff) + victim correlation over synthetic "
                    "bytes: reason/seq/retry parse, per-victim attacker+AP correlation, "
                    "session stats. Passive byte-level only.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--capture", metavar="PATH", help="simulate a capture-session to pcap (gated)")
    g.add_argument("--analyze", metavar="PATH", help="analyze an existing pcap (no flag needed)")
    p.add_argument("--target", metavar="MAC", help="lab-OUI victim MAC for capture simulation")
    p.add_argument("--gen-fixture", metavar="PATH", help="write deterministic capture fixture")
    p.add_argument("--json", metavar="PATH", help="write JSON report")
    p.add_argument(SAFETY_FLAG, dest="confirm", action="store_true",
                   help="GIANT confirmation: acknowledge offline-only lab simulation, "
                        "no radio emission")
    return p


def print_stats(stats: dict) -> None:
    print("=" * 62)
    print(" W7 — Deauth Capture (offscreen sniff + correlation)")
    print("=" * 62)
    print(f"\n[+] frames captured: {stats['frames_captured']}   "
          f"unique victims: {stats['unique_victims']}   radio_emitted=False")
    print(f"[+] reason histogram: {stats['reason_histogram']}")
    for da, v in stats["victims"].items():
        print(f"    victim {da}: {v['frames']} frames | aps={v['aps']} | "
              f"attackers={v['attackers']}")
    print(f"[+] forged-source frames: {stats['forged_source_frames']}")
    print("[+] capture analysis complete — no deauth frames were transmitted.")
    print("=" * 62)


def main(argv=None) -> int:
    args = build_args_parser().parse_args(argv)
    if args.gen_fixture:
        d = os.path.dirname(args.gen_fixture)
        if d:
            os.makedirs(d, exist_ok=True)
        n = write_capture_fixture(args.gen_fixture)
        print(f"[+] fixture -> {args.gen_fixture} ({n} frames)")
    if args.capture:
        gate_capture(args)
        frames = build_capture_frames(targets=(args.target,))
        fc.write_pcap(args.capture, [f["data"] for f in frames], ts=frames[0]["ts"])
        print(f"[+] simulated capture-session -> {args.capture} ({len(frames)} frames, lab gated)")
        stats = correlate([{"ts": f["ts"], **parse_deauth(f["data"])} for f in frames])
    elif args.analyze:
        stats = correlate(sniff_pcap(args.analyze))
    else:
        frames = build_capture_frames()
        stats = correlate([{"ts": f["ts"], **parse_deauth(f["data"])} for f in frames])
    print_stats(stats)
    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump({"name": "w7-deauth-capture", "radio_emitted": False, **stats},
                      f, indent=2, default=str)
    return 0


def run_demo() -> int:
    return main([])


if __name__ == "__main__":
    raise SystemExit(main())