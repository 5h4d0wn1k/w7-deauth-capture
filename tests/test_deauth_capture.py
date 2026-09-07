#!/usr/bin/env python3
"""Byte-exact unit tests for w7-deauth-capture."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import deauth_capture as dc
from firmware import frame_core as fc

FLAG = dc.SAFETY_FLAG


class ParseTest(unittest.TestCase):
    def test_parse_roundtrip(self):
        d = fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                            "00:11:22:33:44:55", reason=7, flags=fc.FC_FLAG_RETRY)
        f = dc.parse_deauth(d + fc.fcs(d))
        self.assertEqual(f["reason"], 7)
        self.assertTrue(f["retry"])
        self.assertEqual(f["da"], "00:11:22:33:44:66")

    def test_bad_fcs_rejected(self):
        frame = bytearray(fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                                          "00:11:22:33:44:55", reason=7)
                          + fc.fcs(fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                                                   "00:11:22:33:44:55", reason=7)))
        frame[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            dc.parse_deauth(bytes(frame))


class CorrelationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frames = [{"ts": f["ts"], **dc.parse_deauth(f["data"])}
                      for f in dc.build_capture_frames()]
        cls.stats = dc.correlate(cls.frames)

    def test_victim_correlation(self):
        self.assertEqual(self.stats["unique_victims"], 2)
        self.assertIn(dc.LAB_TARGET, self.stats["victims"])
        self.assertEqual(self.stats["victims"][dc.LAB_TARGET]["frames"], 14)

    def test_forged_source_counted(self):
        self.assertEqual(self.stats["forged_source_frames"], 1)

    def test_reasons(self):
        self.assertEqual(self.stats["reason_histogram"].get(8), 1)


class GateTest(unittest.TestCase):
    def test_capture_no_flag_exit2(self):
        with self.assertRaises(SystemExit) as cm:
            dc.main(["--capture", "x.pcap"])
        self.assertEqual(cm.exception.code, 2)

    def test_capture_bad_target_exit2(self):
        with self.assertRaises(SystemExit) as cm:
            dc.main(["--capture", "x.pcap", FLAG, "--target", "aa:bb:cc:dd:ee:ff"])
        self.assertEqual(cm.exception.code, 2)

    def test_capture_flagged_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.pcap")
            rc = dc.main(["--capture", path, FLAG, "--target", dc.LAB_TARGET])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(path))


class CLITest(unittest.TestCase):
    def test_demo_exit_zero(self):
        self.assertEqual(dc.run_demo(), 0)

    def test_analyze_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cap.pcap")
            dc.write_capture_fixture(path)
            out = os.path.join(tmp, "o.json")
            rc = dc.main(["--analyze", path, "--json", out])
            self.assertEqual(rc, 0)
            data = json.load(open(out))
            self.assertFalse(data["radio_emitted"])
            self.assertEqual(data["frames_captured"], 15)


if __name__ == "__main__":
    unittest.main()