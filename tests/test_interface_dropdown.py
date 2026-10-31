#!/usr/bin/env python3
# BEACON COMPUTING INITIATIVE
# Developer Seal: CJB-DEV-2026
# Component: Offline Interface GUI Selection Tests v4.6.15-IFACEGUI
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("bci_ifaces", ROOT / "bci_monitor_select.py")
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)

class InterfaceDropdownTests(unittest.TestCase):
    def test_lists_all_interfaces_even_offline(self):
        links = json.dumps([
            {"ifname": "lo", "flags": ["UP"]},
            {"ifname": "wlan0", "flags": [], "operstate": "DOWN"},
            {"ifname": "eth0", "flags": ["UP"]},
            {"ifname": "docker0", "flags": []}
        ])
        result_ip = subprocess.CompletedProcess(["ip"], 0, links, "")
        result_iw = subprocess.CompletedProcess(["iw"], 0,
            "phy#0\n Interface wlan0\n type managed\n", "")
        with patch.object(selector.subprocess, "run", side_effect=[result_ip, result_iw]):
            choices = selector.interface_choices()
        keys = {choice["name"]: choice for choice in choices}
        self.assertIn("auto", keys)
        self.assertIn("none", keys)
        self.assertEqual(keys["none"]["mode"], "idle")
        self.assertEqual(keys["wlan0"]["mode"], "managed")
        self.assertFalse(keys["wlan0"]["up"])
        self.assertIn("offline", keys["wlan0"]["label"])
        self.assertIn("eth0", keys)
        self.assertIn("lo", keys)
        self.assertIn("docker0", keys)

    def test_no_interfaces_still_lists_auto_idle(self):
        with patch.object(selector, "discover_interfaces", return_value=([], [])):
            options = selector.interface_choices()
        self.assertEqual([c["name"] for c in options], ["auto", "none"])

    def test_network_api_not_required_for_selection(self):
        with patch.object(selector.subprocess, "run", side_effect=[
            subprocess.CompletedProcess(["ip"], 0, '[{"ifname":"eth0","flags":[]}]', ""),
            FileNotFoundError("iw absent")
        ]):
            options = selector.interface_choices()
        self.assertEqual(options[-1]["name"], "eth0")
        self.assertIn("offline", options[-1]["label"])

    def test_gui_has_separate_scope_and_capture_selection(self):
        source = (ROOT / "sentinel_gui.py").read_text()
        for phrase in (
            "Network scope:", "Capture interface:", "capture_iface_selector",
            "refresh_capture_interfaces", "start_selected_capture",
            "Start selected", "selected interface is no longer present",
            "self.poll_timer.timeout.connect(self.update_capture_source_status)",
            "BCI_ACTIVE_PROBE_ENABLED"
        ):
            self.assertIn(phrase, source)
        self.assertNotIn("ip link set", source)
        self.assertNotIn("set type monitor", source)

    def test_start_command_does_not_install_or_reconfigure_network(self):
        source = (ROOT / "sentinel_gui.py").read_text()
        self.assertIn('["bash", self.script, "start"]', source)
        self.assertIn('env["BCI_IFACE"] = self.interface', source)
        self.assertIn('env["BCI_ACTIVE_PROBE_ENABLED"] = "0"', source)

if __name__ == "__main__":
    unittest.main()
