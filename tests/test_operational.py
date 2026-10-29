#!/usr/bin/env python3
# BEACON COMPUTING INITIATIVE | ORBITAL TESTS
# Developer Seal: CJB-DEV-2026
# SHA-256: see SHA256SUMS
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent.parent

def module(name):
    s=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
select=module('bci_monitor_select')
ex=module('sentinel_exporter')

class Monitor(unittest.TestCase):
    txt='phy#78\n Interface wlan1\n type monitor\nphy#0\n Interface wlan0\n type managed'
    def test_auto_wlan1(self):
        self.assertEqual(select.choose_monitor(select.parse_iw_inventory(self.txt)),'wlan1')
    def test_auto_wlan2(self):
        self.assertEqual(select.choose_monitor(select.parse_iw_inventory(self.txt.replace('wlan1','wlan2'))),'wlan2')
    def test_no_monitor(self):
        with self.assertRaises(ValueError): select.choose_monitor(select.parse_iw_inventory('phy#0\n Interface wlan0\n type managed'))
    def test_shared_radio(self):
        with self.assertRaises(ValueError): select.choose_monitor(select.parse_iw_inventory('phy#0\n Interface wlan0\n type managed\n Interface wlan1\n type monitor'))
    def test_ambiguous(self):
        x=select.parse_iw_inventory('phy#1\n Interface wlan1\n type monitor\nphy#2\n Interface wlan2\n type monitor')
        with self.assertRaises(ValueError): select.choose_monitor(x)
        self.assertEqual(select.choose_monitor(x,'wlan2'),'wlan2')
    def test_managed_rejected(self):
        with self.assertRaises(ValueError): select.choose_monitor(select.parse_iw_inventory(self.txt),'wlan0')

class Exporter(unittest.TestCase):
    def setUp(self):
        ex.active_aps.clear();ex.active_stations.clear()
        ex.metrics.update(frames_total=0,aps_active=0,stations_active=0,rx_errors=0)
    def test_snapshot_has_dashboard_fields(self):
        s=ex.snapshot()
        for field in ('metrics','aps','stations','seal'): self.assertIn(field,s)
        for field in ('frames_total','aps_active','stations_active','rx_errors'):self.assertIn(field,s['metrics'])
    def test_distinct_files(self):
        self.assertNotEqual(str(ex.DATA_DIR/'bci_state.json'),str(ex.DATA_DIR/'bci_discovery_state.json'))
    def test_atomic_replace(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'bci_state.json';p.write_text('OLD')
            ex.write_snapshot({'test':7},p)
            self.assertEqual(json.loads(p.read_text()),{'test':7})
            self.assertEqual(p.stat().st_mode&0o777,0o644)
    def test_concurrent_read(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'data.json';ex.write_snapshot({'x':0},p)
            issues=[]
            def writer():
                for i in range(40):ex.write_snapshot({'x':i},p)
            def reader():
                for _ in range(40):
                    try:json.loads(p.read_text())
                    except Exception as err:issues.append(err)
            a=threading.Thread(target=writer);b=threading.Thread(target=reader)
            a.start();b.start();a.join();b.join();self.assertEqual(issues,[])
    def test_ap_frame(self):
        classes={v:type(v,(),{}) for v in ('Dot11','Dot11Beacon','Dot11ProbeResp','Dot11Elt','Dot11ProbeReq')}
        fake=types.ModuleType('scapy.layers.dot11')
        for k,v in classes.items():setattr(fake,k,v)
        parent=types.ModuleType('scapy');layers=types.ModuleType('scapy.layers')
        class IE:
            ID=0;info=b'Test AP';payload=None
        class Frame:
            addr2='aa:bb:cc:dd:ee:ff';addr3='aa:bb:cc:dd:ee:ff';type=0
        class Packet:
            def haslayer(self,x):return x in (classes['Dot11'],classes['Dot11Beacon'])
            def __getitem__(self,x):return Frame()
            def getlayer(self,x):return IE()
        with patch.dict(sys.modules,{'scapy':parent,'scapy.layers':layers,'scapy.layers.dot11':fake}):ex.packet_handler(Packet())
        self.assertEqual(ex.metrics['aps_active'],1)
        self.assertEqual(ex.active_aps['AA:BB:CC:DD:EE:FF']['ssid'],'Test AP')
    def test_metrics_endpoint_exists(self):self.assertTrue(hasattr(ex.MetricsHandler,'do_GET'))

class Package(unittest.TestCase):
    def test_compose_services(self):
        text=(ROOT/'compose.yaml').read_text()
        self.assertIn('  sentinel:',text)
        self.assertIn('  discovery:',text)
        self.assertIn('BCI_ROLE: sentinel',text)
        self.assertIn('BCI_ROLE: discovery',text)
        self.assertIn('PROMETHEUS_PORT: "9100"',text)
        self.assertIn('PROMETHEUS_PORT: "9101"',text)

    def test_explicit_entrypoint_overrides_cached_image(self):
        # The v4.6.2 cached image has an older ENTRYPOINT. The v4.6.7
        # exporter must be invoked directly, rather than appended as CMD.
        text=(ROOT/'compose.yaml').read_text()
        self.assertIn('entrypoint: ["python3", "-u", "/opt/bci/sentinel_exporter.py"]',text)
        self.assertIn('command: []',text)
        self.assertNotIn('command: ["python3", "-u", "/opt/bci/sentinel_exporter.py"]',text)
    def test_launcher_tags_cached_image_without_pull(self):
        text=(ROOT/'orbitalctl.sh').read_text()
        self.assertIn('bci/orbital-sentinel:4.6.7-op1',text)
        self.assertIn('bci/orbital-sentinel:4.6.2-auto-ml-jsonl',text)
        self.assertIn('bci/orbital-sentinel:4.6.7-op2',text)
        self.assertIn('"${DOCKER[@]}" tag',text)

    def test_gui_features(self):
        text=(ROOT/'sentinel_gui.py').read_text()
        for item in ('Freeze Feed','Decrypt WPA Capture','Tracked Stations','Raw Prometheus Metrics','Terminal Stream'):
            self.assertIn(item,text)
    def test_no_destructive_network_ops(self):
        x=(ROOT/'orbitalctl.sh').read_text()
        for term in ('airmon-ng check kill','set type monitor','systemctl restart NetworkManager'):self.assertNotIn(term,x)
    def test_bash_syntax(self):
        for name in ('install_orbital.sh','orbitalctl.sh','start_sentinel_gui.sh'):
            self.assertEqual(subprocess.run(['bash','-n',str(ROOT/name)]).returncode,0)
    def test_python_syntax(self):
        import py_compile
        for name in ('sentinel_exporter.py','sentinel_gui.py','bci_monitor_select.py'):
            py_compile.compile(str(ROOT/name),doraise=True)

if __name__=='__main__':unittest.main()
