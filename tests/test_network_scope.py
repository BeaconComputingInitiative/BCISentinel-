#!/usr/bin/env python3
# BEACON COMPUTING INITIATIVE | NETWORK SCOPE REGRESSION
# Developer Seal: CJB-DEV-2026
import importlib.util, json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('scope_lib', ROOT/'network_scope.py')
sc=importlib.util.module_from_spec(spec);spec.loader.exec_module(sc)
spec=importlib.util.spec_from_file_location('scope_exporter',ROOT/'sentinel_exporter.py')
ex=importlib.util.module_from_spec(spec);spec.loader.exec_module(ex)
A='10:20:30:40:50:60';B='20:30:40:50:60:70'
class ScopeTests(unittest.TestCase):
    def setUp(self):
        with ex.lock:
            for m in ex.metrics:ex.metrics[m]=0
            ex.active_aps.clear();ex.active_stations.clear();ex.indicators.clear()
            a=ex._make_ap(A);a['ssid']='Shared';a['beacons']=11;a['channel']='1'
            b=ex._make_ap(B);b['ssid']='Shared';b['beacons']=17;b['channel']='6'
            ex.active_aps.update({A:a,B:b})
            ex.active_stations['A']={'mac':'A','ap':A,'association_evidence':'traffic_observed'}
            ex.active_stations['B']={'mac':'B','ap':B,'association_evidence':'association_response_observed'}
            ex.active_stations['C']={'mac':'C','ap':'Unconfirmed','association_evidence':'unconfirmed'}
            ex.indicators.extend([{'bssid':A,'type':'first'}, {'bssid':B,'type':'second'}])
    def test_same_ssid_distinct_ap_scope(self):
        self.assertEqual([x['bssid'] for x in sc.visible_aps(ex.active_aps.values(),A)],[A])
        self.assertEqual([x['bssid'] for x in sc.visible_aps(ex.active_aps.values(),B)],[B])
        self.assertEqual(len(sc.visible_aps(ex.active_aps.values())),2)
        self.assertIn(A,sc.scoped_ap_label(ex.active_aps.values(),A))
    def test_no_station_without_ap_evidence(self):
        self.assertEqual([x['mac'] for x in sc.visible_stations(ex.active_stations.values(),A)],['A'])
        self.assertEqual(len(sc.visible_stations(ex.active_stations.values())),3)
    def test_indicators_and_dns_dont_cross_network(self):
        self.assertEqual([x['type'] for x in sc.visible_indicators(ex.indicators,B)],['second'])
        dns={A:{'queries':5},B:{'queries':7}}
        self.assertEqual(sc.visible_dns(dns,A),{A:{'queries':5}})
        self.assertEqual(len(sc.visible_dns(dns)),2)
    def test_c2_scope_never_assigns_imported_flow_to_ap(self):
        with tempfile.TemporaryDirectory() as d,patch.object(ex,'DATA_DIR',Path(d)):
            p=Path(d)/'flow_intel';p.mkdir();(p/'flow_summary.json').write_text(json.dumps({'events':9,'event_types':{'dns_nxdomain_burst':9}}))
            ok,r=ex.execute_c2_hunt(A)
            self.assertTrue(ok)
            self.assertEqual(r['scope_bssid'],A)
            self.assertEqual((r['aps_observed'],r['total_stations_analyzed'],r['beacons_observed']),(1,1,11))
            self.assertEqual(r['wireless_indicators_found'],1)
            self.assertEqual(r['flow_indicators_found'],0)
            self.assertTrue(r['flow_evidence_unattributed'])
            self.assertFalse(r['flow_evidence_available'])
            self.assertEqual(r['anomalies'][0]['associated_ap'],A)
            self.assertNotIn(A,(p.parent/'ml'/'sentinel_c2_hunts.jsonl').read_text())
    def test_global_c2_retains_independent_flow(self):
        with tempfile.TemporaryDirectory() as d,patch.object(ex,'DATA_DIR',Path(d)):
            p=Path(d)/'flow_intel';p.mkdir();(p/'flow_summary.json').write_text(json.dumps({'events':9}))
            ok,r=ex.execute_c2_hunt()
            self.assertTrue(ok)
            self.assertEqual(r['aps_observed'],2)
            self.assertEqual(r['flow_indicators_found'],9)
            self.assertIsNone(r['scope_bssid'])
    def test_invalid_scope_fails_closed(self):
        with tempfile.TemporaryDirectory() as d,patch.object(ex,'DATA_DIR',Path(d)):
            self.assertFalse(ex.execute_c2_hunt('invalid')[0])
            self.assertFalse(ex.execute_c2_hunt('AA:AA:AA:AA:AA:AA')[0])
    def test_gui_uses_shared_scope_without_retuning(self):
        s=(ROOT/'sentinel_gui.py').read_text()
        self.assertIn('Network scope:',s)
        self.assertIn('self.selected_bssid()',s)
        self.assertIn('visible_dns(',s)
        self.assertIn('visible_stations(',s)
        self.assertNotIn('set channel',s)
if __name__=='__main__':unittest.main()
