#!/usr/bin/env python3
# BEACON COMPUTING INITIATIVE — AUTO-TRACE REGRESSION TESTS
# Developer Seal: CJB-DEV-2026
# SHA-256: see release SHA256SUMS
import importlib.util
import json
import tempfile
import types
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib import request, error
ROOT = Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('bci_trace_exporter', ROOT/'sentinel_exporter.py')
ex=importlib.util.module_from_spec(spec)
spec.loader.exec_module(ex)
AP1='10:20:30:40:50:60'
AP2='20:30:40:50:60:70'
ST='30:40:50:60:70:80'

class AutoTrace(unittest.TestCase):
    def setUp(self):
        with ex.lock:
            ex.active_aps.clear(); ex.active_stations.clear()
            for key in ex.metrics: ex.metrics[key]=0
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path_patch=patch.object(ex,'DATA_DIR',Path(self.tmp.name))
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)

    def setup_aps(self):
        x=ex._make_ap(AP1);x.update(ssid='BCI-Lab',channel='1',beacons=10,packets=18,vendor='Lab AP')
        y=ex._make_ap(AP2);y.update(ssid='Other',channel='6',beacons=40,packets=42,vendor='Second AP')
        ex.active_aps.update({AP1:x,AP2:y})
        st=ex._make_station(ST);st.update(ap=AP2,association_evidence='traffic_observed',ap_ssid='Other')
        ex.active_stations[ST]=st

    def test_no_aps(self):
        ok,reason=ex.execute_auto_trace()
        self.assertFalse(ok);self.assertIn('No observed',reason)

    def test_auto_select_most_beacons_and_assoc(self):
        self.setup_aps()
        ok,report=ex.execute_auto_trace()
        self.assertTrue(ok)
        self.assertEqual(report['target_bssid'],AP2)
        self.assertEqual(report['associated_stations_count'],1)
        self.assertEqual(report['stations'],[ST])
        self.assertEqual(report['mode'],'passive_no_transmission')
        self.assertFalse(report['channel_changed'])
        self.assertEqual(report['frames_transmitted'],0)
        self.assertEqual(ex.metrics['traces_executed'],1)

    def test_explicit_target_selection(self):
        self.setup_aps()
        ok,report=ex.execute_auto_trace(AP1)
        self.assertTrue(ok);self.assertEqual(report['target_bssid'],AP1)
        self.assertEqual(report['associated_stations_count'],0)

    def test_unknown_target_does_not_export(self):
        self.setup_aps()
        ok,reason=ex.execute_auto_trace('42:20:30:40:50:60')
        self.assertFalse(ok)
        self.assertEqual(ex.metrics['traces_executed'],0)
        self.assertFalse((Path(self.tmp.name)/'ml').exists())

    def test_private_jsonl_with_hash(self):
        self.setup_aps();self.assertTrue(ex.execute_auto_trace()[0])
        filename=Path(self.tmp.name)/'ml'/'sentinel_traces.jsonl'
        text=filename.read_text()
        self.assertNotIn(AP2,text);self.assertNotIn(ST,text)
        doc=json.loads(text)
        self.assertEqual(doc['schema_version'],'bci.orbital.trace.v1')
        self.assertIsNone(doc['label'])
        self.assertEqual(doc['features']['stations_with_ap_evidence'],1)
        ex.finalize_ml_manifest()
        self.assertIn('sentinel_traces.jsonl',(filename.parent/'sentinel_SHA256SUMS').read_text())

    def test_disabled_probe_does_not_transmit(self):
        self.setup_aps()
        with patch.object(ex,'ACTIVE_PROBE_ENABLED',False):
            ok,message=ex.execute_explicit_probe(AP2,True)
        self.assertFalse(ok);self.assertEqual(ex.metrics['trace_probes_sent'],0)

    def test_unauthorized_probe_rejected(self):
        self.setup_aps()
        with patch.object(ex,'ACTIVE_PROBE_ENABLED',True),patch.object(ex,'ROLE','sentinel'):
            ok,message=ex.execute_explicit_probe(AP2,False)
        self.assertFalse(ok);self.assertIn('authorization',message)

    def test_invalid_target_type_rejected(self):
        self.setup_aps()
        with patch.object(ex,'ACTIVE_PROBE_ENABLED',True),patch.object(ex,'ROLE','sentinel'):
            ok,message=ex.execute_explicit_probe(['invalid'],True)
        self.assertFalse(ok)

    def test_current_channel_mismatch_rejected(self):
        self.setup_aps()
        with patch.object(ex,'ACTIVE_PROBE_ENABLED',True),patch.object(ex,'ROLE','sentinel'), \
             patch.object(ex,'_monitor_radio_identity',return_value=('ce:12:3f:f8:1d:2b',1)):
            ok,reason=ex.execute_explicit_probe(AP2,True)
        self.assertFalse(ok);self.assertIn('different channel',reason)
        self.assertEqual(ex.metrics['trace_probes_sent'],0)

    def test_iw_monitor_identity_parser(self):
        response=types.SimpleNamespace(stdout='Interface wlan1\n addr ce:12:3f:f8:1d:2b\n type monitor\n channel 1 (2412 MHz)\n')
        with patch.object(ex.subprocess,'run',return_value=response):
            self.assertEqual(ex._monitor_radio_identity('wlan1'),('ce:12:3f:f8:1d:2b',1))

    def test_http_get_and_probe_disabled(self):
        self.setup_aps()
        server=ex.ThreadingHTTPServer(('127.0.0.1',0), ex.MetricsHandler)
        t=threading.Thread(target=server.serve_forever,daemon=True)
        t.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base=f'http://127.0.0.1:{server.server_address[1]}'
        with request.urlopen(base+'/trace',timeout=4) as r:
            report=json.load(r)
        self.assertTrue(report['success'])
        self.assertEqual(report['report']['target_bssid'],AP2)
        with request.urlopen(base+'/metrics',timeout=4) as r:
            self.assertIn('bci_orbital_traces_total 1',r.read().decode())
        body=json.dumps({'bssid':AP2,'authorized':True}).encode()
        with patch.object(ex,'ACTIVE_PROBE_ENABLED',False):
            with self.assertRaises(error.HTTPError) as captured:
                request.urlopen(request.Request(base+'/trace/probe',data=body,
                                  headers={'Content-Type':'application/json'},method='POST'),timeout=4)
            self.assertEqual(captured.exception.code,400)

    def test_old_features_and_gui_preserved(self):
        gui=(ROOT/'sentinel_gui.py').read_text()
        for phrase in ('Auto-Trace AP','AutoTraceWorker','Hunt C2 Signatures','C2HuntWorker',
                       'Freeze Feed','Decrypt WPA Capture','Wireless Indicators','Edge Flow Intelligence',
                       'Tracked Stations','Raw Prometheus Metrics'):
            self.assertIn(phrase,gui)
        self.assertIn('flow-analyze', (ROOT/'orbitalctl.sh').read_text())
        self.assertIn('trace-probe', (ROOT/'orbitalctl.sh').read_text())
        exporter=(ROOT/'sentinel_exporter.py').read_text()
        self.assertNotIn('6C:94:66:DE:95:1D',exporter)
        self.assertNotIn('Dot11Deauth',exporter)

if __name__=='__main__': unittest.main()
