#!/usr/bin/env python3
# BEACON COMPUTING INITIATIVE | ORBITAL INTELLIGENCE TESTS
# Developer Seal: CJB-DEV-2026
# SHA-256: see SHA256SUMS
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import types
import sys
ROOT=Path(__file__).parent.parent

def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'))
    mod=importlib.util.module_from_spec(spec)
    sys.modules[name]=mod
    spec.loader.exec_module(mod)
    return mod

fi=load('flow_intel')
ex=load('sentinel_exporter')

class FlowIntelligence(unittest.TestCase):
    @staticmethod
    def base():
        return dict(src='10.1.1.20',dst='203.0.113.100',port=443,proto='tcp',bytes=200,
                    src_port=43210,service='tls',tcp_flags='',domain='',dst_asn='',http_method='',ts=0)
    def event_types(self,flows=(),dns=(),ioc=None):
        if ioc is None: ioc=fi.load_ioc(None)
        events, summary=fi.analyze(sorted(flows,key=lambda x:x['ts']),sorted(dns,key=lambda x:x['ts']),ioc)
        return {e['type'] for e in events},summary
    def test_regular_callback_intervals(self):
        flows=[{**self.base(),'ts':i*60} for i in range(8)]
        types,_=self.event_types(flows)
        self.assertIn('periodic_external_flow',types)
    def test_random_cadence_not_flagged(self):
        flows=[{**self.base(),'ts':v} for v in (0,10,123,170,551,981,1030)]
        self.assertNotIn('periodic_external_flow',self.event_types(flows)[0])
    def test_dga_like_nxdomain(self):
        dns=[dict(src='10.0.0.1',ts=i,domain='az8qkt4p8z9w'+str(i)+'.invalid',rcode='NXDOMAIN',answers=[]) for i in range(20)]
        self.assertIn('dga_like_nxdomain',self.event_types(dns=dns)[0])
    def test_smtp_fanout(self):
        flows=[{**self.base(),'dst':f'203.0.113.{i}','port':25,'ts':i*2} for i in range(1,20)]
        self.assertIn('smtp_fanout',self.event_types(flows)[0])
    def test_scan_targets(self):
        flows=[{**self.base(),'dst':f'198.51.100.{i}','port':22,'ts':i} for i in range(1,40)]
        self.assertIn('external_target_fanout',self.event_types(flows)[0])
    def test_protocol_mismatch(self):
        flows=[{**self.base(),'port':53,'service':'tls'}]
        self.assertIn('protocol_port_mismatch',self.event_types(flows)[0])
    def test_syn_spike(self):
        flows=[{**self.base(),'tcp_flags':'S','ts':i*0.2} for i in range(120)]
        self.assertIn('possible_syn_flood',self.event_types(flows)[0])
    def test_udp_volume(self):
        flows=[{**self.base(),'proto':'udp','bytes':100000,'ts':i*0.3} for i in range(120)]
        self.assertIn('outbound_udp_volume_spike',self.event_types(flows)[0])
    def test_get_spike(self):
        flows=[{**self.base(),'http_method':'GET','ts':i*0.2} for i in range(120)]
        self.assertIn('high_rate_http_get',self.event_types(flows)[0])
    def test_ip_reputation_and_asn(self):
        ioc=fi.load_ioc(None);ioc['ips'].add('203.0.113.100')
        self.assertIn('local_ioc_match',self.event_types([self.base()],ioc=ioc)[0])
        ioc['ips'].clear();ioc['asns'].add('64500')
        self.assertIn('local_ioc_match',self.event_types([{**self.base(),'dst_asn':'AS64500'}],ioc=ioc)[0])
    def test_shared_ddns_flux(self):
        dns=[]
        for i in range(4):
            dns.append(dict(src=f'10.0.0.{i+1}',ts=i,domain='node.ddns.example',
                            rcode='NOERROR',answers=[f'198.51.100.{k}' for k in range(1,8)]))
        ioc=fi.load_ioc(None);ioc['ddns_suffixes'].add('ddns.example')
        types,_=self.event_types(dns=dns,ioc=ioc)
        self.assertIn('shared_suspicious_domain',types)
        self.assertIn('multiple_dns_answers',types)
    def test_jsonl_roundtrip_and_no_raw_ips_in_ml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f=root/'flow.jsonl'
            f.write_text(json.dumps({'ts':0,'src_ip':'10.0.0.8', 'dst_ip':'198.51.100.4',
                      'dst_port':53,'proto':'tcp','service':'tls'})+'\n')
            rows=fi.load_jsonl(f,'flow');self.assertEqual(len(rows),1)
            ev,summary=fi.analyze(rows,[],fi.load_ioc(None))
            fi.write_outputs(ev,summary,root/'out')
            text=(root/'out'/'flow_ml_features.jsonl').read_text()
            self.assertNotIn('10.0.0.8',text)
            self.assertIn('"label": null',text)
            for entry in (root/'out'/'SHA256SUMS').read_text().splitlines():
                self.assertEqual(len(entry.split()[0]),64)
    def test_invalid_data_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'x.jsonl';f.write_text('{bad}\n')
            with self.assertRaises(ValueError):fi.load_jsonl(f,'flow')

class WirelessAnalysis(unittest.TestCase):
    def setUp(self):
        with ex.lock:
            ex.active_aps.clear();ex.active_stations.clear();ex.indicators.clear();ex.ml_pending.clear();ex.ml_last_export.clear()
            for key in ex.metrics:ex.metrics[key]=0
    def test_mac_randomization_disables_vendor_claim(self):
        self.assertIn('Randomized',ex.get_vendor('CE:12:3F:F8:1D:2B'))
    def test_vendor_from_database(self):
        with patch.object(ex,'OUI_DB',{'102030':'Example manufacturer'}):
            self.assertEqual(ex.get_vendor('10:20:30:40:50:60'),'Example manufacturer')
    def test_station_evidence_ranks(self):
        with ex.lock:
            ex._mark_station_locked('10:20:30:44:55:66','22:30:40:50:60:70','traffic_observed')
            ex._mark_station_locked('10:20:30:44:55:66',None,'unconfirmed')
        st=ex.active_stations['10:20:30:44:55:66']
        self.assertEqual(st['ap'],'22:30:40:50:60:70'.upper())
        self.assertEqual(st['association_evidence'],'traffic_observed')
    def test_beacon_profile_hash(self):
        class Elt:
            def __init__(self,ID,info):self.ID=ID;self.info=info;self.payload=None
        class Packet:
            def __init__(self):self.elt=Elt(0,b'Example AP')
            def getlayer(self,any):return self.elt
        p=Packet();self.assertEqual(ex._beacon_profile(p,Elt)['ssid'],'Example AP')
        self.assertEqual(len(ex._beacon_profile(p,Elt)['ie_sha256']),64)
    def test_ml_export_has_pseudonyms(self):
        with tempfile.TemporaryDirectory() as t,patch.object(ex,'DATA_DIR',Path(t)):
            bssid='10:20:30:40:50:60'
            ap=ex._make_ap(bssid);ap['beacons']=5;ex.active_aps[bssid]=ap
            ex.flush_ml();text=(Path(t)/'ml'/'sentinel_beacon_windows.jsonl').read_text()
            self.assertNotIn(bssid,text)
            self.assertIn('beacons_since_last_window',text)
            ex.finalize_ml_manifest()
            self.assertTrue((Path(t)/'ml'/'sentinel_SHA256SUMS').exists())
    def test_packet_handler_counts_beacons_by_bssid(self):
        classes = {name:type(name, (), {}) for name in (
            'Dot11','Dot11Beacon','Dot11ProbeResp','Dot11ProbeReq',
            'Dot11Elt','Dot11AssoResp','Dot11ReassoResp')}
        fake=types.ModuleType('scapy.layers.dot11')
        for name,cls in classes.items():setattr(fake,name,cls)
        class Frame:
            addr1='ff:ff:ff:ff:ff:ff';addr2='10:20:30:40:50:60'
            addr3='10:20:30:40:50:60';type=0;subtype=8;FCfield=0
        class Beacon:
            beacon_interval=100
            timestamp=1234567
        class IE:
            ID=0;info=b'BeaconLab';payload=None
        class Packet:
            dBm_AntSignal=-48
            def haslayer(self,layer):return layer in (classes['Dot11'],classes['Dot11Beacon'])
            def __getitem__(self,layer):return Frame() if layer==classes['Dot11'] else Beacon()
            def getlayer(self,layer):return IE() if layer==classes['Dot11Elt'] else None
        with patch.dict(sys.modules,{'scapy':types.ModuleType('scapy'),
                'scapy.layers':types.ModuleType('scapy.layers'),
                'scapy.layers.dot11':fake}):
            ex.packet_handler(Packet());ex.packet_handler(Packet())
        ap=ex.active_aps['10:20:30:40:50:60']
        self.assertEqual(ap['beacons'],2)
        self.assertEqual(ap['ssid'],'BeaconLab')
        self.assertEqual(ap['beacon_interval_tu'],100)
        self.assertEqual(len(ap['recent_beacons']),2)
        self.assertEqual(ex.metrics['beacons_total'],2)
    def test_beacon_history_bounded(self):
        ap=ex._make_ap('10:20:30:40:50:60')
        # Data model supports rolling observation history without raw unlimited captures.
        for i in range(50):
            ap['recent_beacons'].append({'timestamp_utc':str(i)})
            if len(ap['recent_beacons'])>24:del ap['recent_beacons'][:-24]
        self.assertEqual(len(ap['recent_beacons']),24)

    def test_gui_old_features_retained(self):
        text=(ROOT/'sentinel_gui.py').read_text()
        for name in ('Decrypt WPA Capture','Freeze Feed','Raw Prometheus Metrics',
                     'Tracked Stations','Terminal Stream','Wireless Indicators','Edge Flow Intelligence'):
            self.assertIn(name,text)

if __name__=='__main__':unittest.main()
