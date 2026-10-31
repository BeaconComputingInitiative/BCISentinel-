#!/usr/bin/env python3
# BEACON COMPUTING INITIATIVE
# Developer Seal: CJB-DEV-2026
# Component: Universal Interface Tests v4.6.14-FLEX
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

select = load("bci_monitor_select")
exporter = load("sentinel_exporter")

class InterfaceTests(unittest.TestCase):
    def test_prefer_active_monitor(self):
        links = select.parse_link_inventory(json.dumps([
            {"ifname":"wlan0", "flags":["UP"]},
            {"ifname":"wlan1", "flags":["UP"]}]))
        wireless = [{"name":"wlan0","type":"managed"},
                    {"name":"wlan1","type":"monitor"}]
        self.assertEqual(select.choose_any(links, wireless), ("wlan1", "monitor"))

    def test_down_ethernet_no_online_gate(self):
        links = select.parse_link_inventory('[{"ifname":"eth0","flags":[],"operstate":"DOWN"}]')
        self.assertEqual(select.choose_any(links, []), ("eth0", "ethernet"))

    def test_missing_adapter_is_idle(self):
        self.assertEqual(select.choose_any([], []), ("none", "idle"))

    def test_explicit_loopback_or_managed(self):
        links = select.parse_link_inventory('[{"ifname":"lo","flags":["UP"]},{"ifname":"wlan0","flags":[]}]')
        wlan = [{"name":"wlan0","type":"managed"}]
        self.assertEqual(select.choose_any(links, wlan, "lo"), ("lo", "loopback"))
        self.assertEqual(select.choose_any(links, wlan, "wlan0"), ("wlan0", "managed"))

    def test_unknown_explicit_interface_refused(self):
        with self.assertRaises(ValueError):
            select.choose_any([], [], "wlan99")

    def test_virtual_only_is_idle(self):
        links = select.parse_link_inventory('[{"ifname":"lo","flags":["UP"]},{"ifname":"docker0","flags":["UP"]},{"ifname":"tailscale0","flags":["UP"]}]')
        self.assertEqual(select.choose_any(links, []), ("none", "idle"))

    def test_idle_does_not_overwrite_historical_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bci_state.json"
            runtime = Path(tmp) / "bci_runtime_status.json"
            path.write_text('{"historical":true}\n')
            with patch.object(exporter, "STATE_FILE", path), \
                 patch.object(exporter, "RUNTIME_FILE", runtime), \
                 patch.object(exporter, "CAPTURE_MODE", "idle"), \
                 patch.object(exporter, "CAPTURE_STATE", "idle"), \
                 patch.object(exporter, "IFACE", "none"), \
                 patch.dict(exporter.metrics, {"frames_total": 0}):
                exporter._persist_state()
            self.assertTrue(json.loads(path.read_text())["historical"])
            status = json.loads(runtime.read_text())
            self.assertEqual(status["capture_state"], "idle")
            self.assertEqual(status["developer_seal"], "CJB-DEV-2026")

    def test_ethernet_has_no_ap_visibility(self):
        with patch.object(exporter, "CAPTURE_MODE", "ethernet"):
            self.assertIn("no_80211_beacon_or_AP_inference", exporter.snapshot()["visibility"])

    def test_nonexistent_interface_is_not_up(self):
        self.assertFalse(exporter._interface_up("bci-absent-adapter"))
