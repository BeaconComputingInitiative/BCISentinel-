#!/usr/bin/env python3
# BEACON COMPUTING INITIATIVE | C2 HUNT INTEGRATION TESTS
# Developer Seal: CJB-DEV-2026
# SHA-256: see SHA256SUMS
import importlib.util, json, tempfile, types, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('bci_c2_exporter',ROOT/'sentinel_exporter.py')
ex=importlib.util.module_from_spec(spec);spec.loader.exec_module(ex)

class Hunt(unittest.TestCase):
    def setUp(self):
        with ex.lock:
            ex.active_aps.clear();ex.active_stations.clear();ex.indicators.clear()
            for k in ex.metrics:ex.metrics[k]=0

    def test_metric_exists(self):
        self.assertIn('c2_hunts_executed',ex.metrics)

    def test_no_fabricated_c2_from_traffic_count(self):
        with tempfile.TemporaryDirectory() as d,patch.object(ex,'DATA_DIR',Path(d)):
            ex.active_stations['10:20:30:40:50:60']={'mac':'10:20:30:40:50:60','packets':20000,'vendor':'Example','ap':'10:20:30:40:50:70'}
            result,report=ex.execute_c2_hunt()
            self.assertTrue(result)
            self.assertEqual(report['suspicious_nodes_found'],0)
            self.assertEqual(report['sweep_channels'],[])
            self.assertEqual(ex.metrics['c2_hunts_executed'],1)
            self.assertEqual(report['mode'],'passive_snapshot_no_transmissions')

    def test_indicator_provenance_without_botnet_label(self):
        with tempfile.TemporaryDirectory() as d,patch.object(ex,'DATA_DIR',Path(d)):
            ap=ex._make_ap('10:20:30:40:50:60');ap['channel']='1';ex.active_aps[ap['bssid']]=ap
            ex.indicators.append({'bssid':ap['bssid'],'type':'beacon_ie_profile_change','detail':'test','timestamp_utc':'2026-01-01T00:00:00Z'})
            ok,report=ex.execute_c2_hunt()
            self.assertTrue(ok)
            self.assertEqual(report['wireless_indicators_found'],1)
            self.assertEqual(report['anomalies'][0]['classification'],'wireless_anomaly_not_c2_evidence')
            self.assertEqual(report['observed_channels'],['1'])
            ml=(Path(d)/'ml'/'sentinel_c2_hunts.jsonl').read_text()
            self.assertNotIn(ap['bssid'],ml)
            self.assertIsNone(json.loads(ml)['label'])
            ex.finalize_ml_manifest()
            self.assertIn('sentinel_c2_hunts.jsonl',(Path(d)/'ml'/'sentinel_SHA256SUMS').read_text())

    def test_separately_imported_flow_summary(self):
        with tempfile.TemporaryDirectory() as d,patch.object(ex,'DATA_DIR',Path(d)):
            dest=Path(d)/'flow_intel';dest.mkdir()
            (dest/'flow_summary.json').write_text(json.dumps({'events':4,'event_types':{'periodic_contact_pattern':4}}))
            ok,report=ex.execute_c2_hunt()
            self.assertTrue(ok)
            self.assertEqual(report['flow_indicators_found'],4)
            self.assertTrue(report['flow_evidence_available'])
            self.assertEqual(report['suspicious_nodes_found'],0)

    def test_missing_flow_summary_is_not_a_failure(self):
        with tempfile.TemporaryDirectory() as d,patch.object(ex,'DATA_DIR',Path(d)):
            ok,report=ex.execute_c2_hunt()
            self.assertTrue(ok)
            self.assertFalse(report['flow_evidence_available'])

    def test_api_route_and_gui_preserved(self):
        s=(ROOT/'sentinel_exporter.py').read_text()
        g=(ROOT/'sentinel_gui.py').read_text()
        self.assertIn("self.path == '/hunt_c2'",s)
        self.assertIn('bci_orbital_c2_hunts_total',s)
        for value in ('Hunt C2 Signatures','C2HuntWorker','Freeze Feed','Decrypt WPA Capture',
                      'Wireless Indicators','Edge Flow Intelligence','Raw Prometheus Metrics',
                      'Tracked Stations'):
            self.assertIn(value,g)
        self.assertNotIn('6C:94:66:DE:95:1D',s)
        import inspect
        self.assertNotIn('sendp(', inspect.getsource(ex.execute_auto_trace))
        self.assertNotIn('set channel', inspect.getsource(ex.execute_auto_trace))

if __name__=='__main__':unittest.main()
