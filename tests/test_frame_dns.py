#!/usr/bin/env python3
# BEACON COMPUTING INITIATIVE | FRAME AND DNS OBSERVATION REGRESSION
# Developer Seal: CJB-DEV-2026
import importlib.util
import tempfile
import types
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('bci_frame_dns', ROOT/'sentinel_exporter.py')
ex = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ex)

class FrameDns(unittest.TestCase):
    def setUp(self):
        with ex.lock:
            for k in ex.metrics: ex.metrics[k] = 0
            ex.active_aps.clear(); ex.active_stations.clear(); ex.dns_per_ap.clear()

    def test_ieee_oui_base16_continuation_is_not_vendor(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'oui.txt'
            p.write_text('001122     (hex)    Valid Devices Incorporated\n'
                         '001122     (base 16)    123 Office Street\n'
                         'AABBCC     (hex)    Other Company\n')
            with patch.dict('os.environ', {'BCI_OUI_FILE':str(p)}):
                result = ex.load_oui_lookup()
        self.assertEqual(result['001122'],'Valid Devices Incorporated')
        self.assertEqual(result['AABBCC'],'Other Company')
        self.assertNotIn('16)', list(result.values()))

    def test_frame_categories_without_overlap(self):
        names = ['Dot11','Dot11Beacon','Dot11ProbeResp','Dot11ProbeReq','Dot11Elt']
        classes = {name:type(name,(),{}) for name in names}
        fake = types.ModuleType('scapy.layers.dot11')
        for name, cls in classes.items():setattr(fake,name,cls)
        class Frame:
            addr1='ff:ff:ff:ff:ff:ff';addr2='10:20:30:40:50:60'
            addr3='10:20:30:40:50:60';subtype=0;FCfield=0
            def __init__(self, t):self.type=t
        class Packet:
            def __init__(self, t):self.f=Frame(t)
            def haslayer(self,x):return x is classes['Dot11']
            def __getitem__(self,x):return self.f
        with patch.dict(sys.modules,{'scapy':types.ModuleType('scapy'),
            'scapy.layers':types.ModuleType('scapy.layers'),'scapy.layers.dot11':fake}):
            for i in (0,1,2,3):ex.packet_handler(Packet(i))
        self.assertEqual(ex.metrics['frames_total'],4)
        self.assertEqual([ex.metrics[k] for k in ('management_frames_total',
            'control_frames_total','data_frames_total','other_frames_total')],[1,1,1,1])
        self.assertEqual(ex.metrics['other_management_frames_total'],1)
        self.assertEqual(ex.metrics['dns_packets_observed_total'],0)

    def test_dns_only_plaintext_port53_and_no_raw_domains(self):
        DNS=type('DNS',(),{});UDP=type('UDP',(),{});TCP=type('TCP',(),{})
        dnsmod=types.ModuleType('scapy.layers.dns');dnsmod.DNS=DNS
        inetmod=types.ModuleType('scapy.layers.inet');inetmod.UDP=UDP;inetmod.TCP=TCP
        class Transport:
            sport=45678;dport=53
        class Packet:
            def __init__(self,qr=0,rcode=0,port=53):
                self.msg=types.SimpleNamespace(qr=qr,rcode=rcode,qname=b'private.example')
                self.transport=Transport();self.transport.dport=port
            def haslayer(self,layer):return layer in (DNS,UDP)
            def __getitem__(self,layer):return self.msg if layer is DNS else self.transport
        with patch.dict(sys.modules,{'scapy.layers.dns':dnsmod,'scapy.layers.inet':inetmod}):
            ex._observe_plaintext_dns(Packet(),types.SimpleNamespace(FCfield=0),'10:20:30:40:50:60')
            ex._observe_plaintext_dns(Packet(qr=1,rcode=3),types.SimpleNamespace(FCfield=0),'10:20:30:40:50:60')
            ex._observe_plaintext_dns(Packet(),types.SimpleNamespace(FCfield=0x40),'10:20:30:40:50:60')
            ex._observe_plaintext_dns(Packet(port=5353),types.SimpleNamespace(FCfield=0),'10:20:30:40:50:60')
        self.assertEqual(ex.metrics['dns_packets_observed_total'],2)
        self.assertEqual(ex.metrics['dns_queries_observed_total'],1)
        self.assertEqual(ex.metrics['dns_responses_observed_total'],1)
        self.assertEqual(ex.metrics['dns_nxdomain_observed_total'],1)
        data=str(ex.snapshot())
        self.assertNotIn('private.example',data)
        self.assertEqual(ex.dns_per_ap['10:20:30:40:50:60']['nxdomain'],1)

    def test_dns_and_frame_metrics_exposed(self):
        code=(ROOT/'sentinel_exporter.py').read_text()
        gui=(ROOT/'sentinel_gui.py').read_text()
        for key in ('bci_orbital_management_frames_total','bci_orbital_data_frames_total',
            'bci_orbital_control_frames_total','bci_orbital_dns_queries_observed_total',
            'bci_orbital_dns_nxdomain_observed_total'):
            self.assertIn(key,code)
        self.assertIn('DNS Observation',gui)
        self.assertIn('API OFFLINE · SHOWING SAVED OBSERVATIONS',gui)
        self.assertIn('AP Mgmt Frames',gui)

if __name__=='__main__':unittest.main()
