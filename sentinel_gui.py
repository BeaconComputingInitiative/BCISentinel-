#!/usr/bin/env python3
# =====================================================================
# BEACON COMPUTING INITIATIVE | ORBITAL SENTINEL PYQT6 CONTROL CENTER
# Developer Seal: CJB-DEV-2026
# OPERATOR: Chance Joaquin Boone
# =====================================================================

import os
import sys

if '/usr/lib/python3/dist-packages' not in sys.path:
    sys.path.insert(0, '/usr/lib/python3/dist-packages')

import json
from network_scope import (visible_aps, visible_stations, visible_indicators,
                           visible_dns, scoped_ap_label)
from datetime import datetime, timezone
import subprocess
import urllib.request
import urllib.error
from urllib.parse import urlencode

__version__ = "4.6.13-NETSCOPE"
OPERATOR_NAME = "Chance Joaquin Boone"
PROMETHEUS_METRICS_URL = "http://127.0.0.1:9100/metrics"
C2_HUNT_API_URL = "http://127.0.0.1:9100/hunt_c2"
TRACE_API_URL = "http://127.0.0.1:9100/trace"
STATE_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures", "bci_state.json")

def decrypt_wpa_capture(pcap_path, ssid, passphrase, output_path=None):
    if not pcap_path or not os.path.exists(pcap_path): return False, "Capture file does not exist."
    if not ssid or not passphrase: return False, "SSID and passphrase required."
    if not output_path:
        base, ext = os.path.splitext(pcap_path)
        output_path = f"{base}_decrypted{ext or '.pcap'}"
    key_string = f'wpa-pwd,{passphrase}:{ssid}'
    cmd = ["tshark", "-r", pcap_path, "-o", "wlan.enable_decryption:TRUE", "-o", f"uat:80211_keys:\"{key_string}\"", "-w", output_path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return (True, output_path) if res.returncode == 0 else (False, res.stderr.strip())
    except Exception as e: return False, str(e)

def main():
    try:
        from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                                     QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
                                     QPushButton, QTabWidget, QHeaderView, QTextEdit,
                                     QLineEdit, QMessageBox, QInputDialog, QFileDialog, QSizePolicy, QComboBox)
        from PyQt6.QtCore import QTimer, Qt, QThread, pyqtSignal
    except ImportError as e:
        sys.exit(f"PyQt6 load error: {e}")

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet("""
        QMainWindow, QWidget { background-color: #0b0b10; color: #d8d8e5; font-family: 'Segoe UI', sans-serif; font-size: 14px; }
        QTabWidget::pane { border: 1px solid #1e1e2d; background-color: #101017; border-radius: 8px; }
        QTabBar::tab { background-color: #14141e; color: #8e8eaf; padding: 10px 18px; border: 1px solid #1e1e2d; border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; font-weight: 600; }
        QTabBar::tab:selected { background-color: #1a1a28; color: #00f5ff; border-bottom: 2px solid #00f5ff; }
        QTableWidget { background-color: #101017; color: #d8d8e5; gridline-color: #1e1e2d; border: 1px solid #1e1e2d; selection-background-color: #1a1a28; selection-color: #00f5ff; }
        QHeaderView::section { background-color: #161622; color: #00f5ff; padding: 8px; font-family: monospace; border: none; border-right: 1px solid #1e1e2d; }
        QPushButton { background-color: #161622; color: #00f5ff; border: 1px solid #00f5ff; padding: 8px 16px; border-radius: 6px; font-weight: 600; }
        QPushButton:hover { background-color: #00f5ff; color: #0b0b10; }
        QTextEdit { background-color: #0d0d14; color: #00f5ff; border: 1px solid #1e1e2d; font-family: monospace; }
    """)


    class C2HuntWorker(QThread):
        def __init__(self, bssid=None, parent=None):
            super().__init__(parent)
            self.bssid = bssid

        finished_report = pyqtSignal(dict)
        failed_report = pyqtSignal(str)

        def run(self):
            try:
                url = C2_HUNT_API_URL + ('?' + urlencode({'bssid':self.bssid}) if self.bssid else '')
                req = urllib.request.Request(
                    url, headers={'User-Agent': 'BCI-Sentinel-GUI'})
                with urllib.request.urlopen(req, timeout=8.0) as response:
                    result = json.loads(response.read(2_000_000).decode('utf-8'))
                if result.get('success'):
                    self.finished_report.emit(result.get('report') or {})
                else:
                    self.failed_report.emit(result.get('error', 'Unknown API error'))
            except (OSError, ValueError, urllib.error.URLError) as exc:
                self.failed_report.emit(f'{type(exc).__name__}: {exc}')

    class AutoTraceWorker(QThread):
        finished_report = pyqtSignal(dict)
        failed_report = pyqtSignal(str)

        def __init__(self, bssid=None, parent=None):
            super().__init__(parent)
            self.bssid = bssid

        def run(self):
            try:
                url = TRACE_API_URL + ('?' + urlencode({'bssid': self.bssid}) if self.bssid else '')
                request = urllib.request.Request(url, headers={'User-Agent': 'BCI-Sentinel-GUI'})
                with urllib.request.urlopen(request, timeout=8) as response:
                    result = json.loads(response.read(2_000_000).decode('utf-8'))
                if result.get('success'):
                    self.finished_report.emit(result.get('report') or {})
                else:
                    self.failed_report.emit(str(result.get('error', 'Unknown trace error')))
            except (OSError, ValueError, urllib.error.URLError) as exc:
                self.failed_report.emit(f'{type(exc).__name__}: {exc}')

    class BCIControlCenter(QMainWindow):
        def __init__(self):
            super().__init__()
            self.frozen = False
            self.c2_worker = None
            self.trace_worker = None
            self.current_snapshot = None
            self.last_state_version = None
            self.last_state_timestamp = None
            self.setWindowTitle(f"Beacon Computing Initiative — Orbital Sentinel v{__version__} [Operator: {OPERATOR_NAME}]")
            self.resize(1400, 900)

            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            main_layout = QVBoxLayout(central_widget)
            main_layout.setContentsMargins(12, 12, 12, 12)
            main_layout.setSpacing(10)

            top_bar_layout = QHBoxLayout()
            self.status_lbl = QLabel("● SYSTEM ACTIVE")
            self.status_lbl.setStyleSheet("color: #00f5ff; font-weight: bold; font-family: monospace;")
            top_bar_layout.addWidget(self.status_lbl)
            top_bar_layout.addStretch()

            self.c2_btn = QPushButton("🕵️ Hunt C2 Signatures")
            self.c2_btn.setStyleSheet("background-color: #2b1f0b; color: #ffb800; border: 1px solid #ffb800;")
            self.c2_btn.clicked.connect(self.do_c2_hunt)
            top_bar_layout.addWidget(self.c2_btn)

            self.trace_btn = QPushButton("📍 Auto-Trace AP")
            self.trace_btn.setStyleSheet("background-color: #1b1028; color: #00f5ff; border: 1px solid #00f5ff;")
            self.trace_btn.clicked.connect(self.do_auto_trace)
            top_bar_layout.addWidget(self.trace_btn)

            self.freeze_btn = QPushButton("❄ Freeze Feed")
            self.freeze_btn.clicked.connect(self.toggle_freeze)
            top_bar_layout.addWidget(self.freeze_btn)

            decrypt_btn = QPushButton("🔓 Decrypt WPA Capture")
            decrypt_btn.clicked.connect(self.do_decrypt_dialog)
            top_bar_layout.addWidget(decrypt_btn)
            main_layout.addLayout(top_bar_layout)

            selection_bar = QHBoxLayout()
            selection_bar.addWidget(QLabel('Network scope:'))
            self.network_selector = QComboBox()
            self.network_selector.setMinimumWidth(440)
            self.network_selector.setMaximumWidth(750)
            self.network_selector.addItem('All observed networks (global capture)', None)
            self.network_selector.currentIndexChanged.connect(self.on_network_changed)
            selection_bar.addWidget(self.network_selector)
            self.scope_info = QLabel('Selected AP filters views and hunt reports, not radio capture.')
            self.scope_info.setStyleSheet('color: #8e9cac;')
            selection_bar.addWidget(self.scope_info)
            selection_bar.addStretch()
            main_layout.addLayout(selection_bar)

            self.tabs = QTabWidget()
            self.tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            main_layout.addWidget(self.tabs)

            self.tab_dashboard = QWidget()
            self.init_dashboard_tab()
            self.tabs.addTab(self.tab_dashboard, "📡 APs & Telemetry")

            self.tab_stations = QWidget()
            self.init_stations_tab()
            self.tabs.addTab(self.tab_stations, "📱 Tracked Stations")

            self.tab_indicators = QWidget()
            self.init_indicators_tab()
            self.tabs.addTab(self.tab_indicators, "⚠ Wireless Indicators")

            self.tab_dns = QWidget()
            self.init_dns_tab()
            self.tabs.addTab(self.tab_dns, "🌐 DNS Observation")

            self.tab_flow = QWidget()
            self.init_flow_tab()
            self.tabs.addTab(self.tab_flow, "🔎 Edge Flow Intelligence")

            self.tab_metrics = QWidget()
            self.init_metrics_tab()
            self.tabs.addTab(self.tab_metrics, "📊 Raw Prometheus Metrics")

            self.tab_terminal = QWidget()
            self.init_terminal_tab()
            self.tabs.addTab(self.tab_terminal, "💻 Terminal Stream")

            self.poll_timer = QTimer(self)
            self.poll_timer.timeout.connect(self.poll_data)
            self.poll_timer.start(1500)

        def init_dashboard_tab(self):
            layout = QVBoxLayout(self.tab_dashboard)
            metrics_layout = QHBoxLayout()
            self.lbl_frames = QLabel("<b>Total Frames:</b> 0")
            self.lbl_beacons = QLabel("<b>Beacons:</b> 0")
            self.lbl_data = QLabel("<b>Data Frames:</b> 0")
            self.lbl_control = QLabel("<b>Control Frames:</b> 0")
            self.lbl_management = QLabel("<b>Management:</b> 0")
            self.lbl_dns = QLabel("<b>Plaintext DNS:</b> 0")
            self.lbl_aps = QLabel("<b>Active APs:</b> 0")
            self.lbl_stations = QLabel("<b>Stations Tracked:</b> 0")
            self.lbl_rx_errors = QLabel("<b>RX Errors:</b> 0")
            self.lbl_hunts = QLabel("<b>C2 Hunts:</b> 0")
            self.lbl_traces = QLabel("<b>AP Traces:</b> 0")
            for lbl in [self.lbl_frames, self.lbl_beacons, self.lbl_data,
                        self.lbl_control, self.lbl_management, self.lbl_dns,
                        self.lbl_aps, self.lbl_stations, self.lbl_rx_errors,
                        self.lbl_hunts, self.lbl_traces]:
                lbl.setStyleSheet("background-color: #14141f; border: 1px solid #1e1e2d; padding: 12px; color: #00f5ff; border-radius: 6px;")
                metrics_layout.addWidget(lbl)
            layout.addLayout(metrics_layout)

            layout.addWidget(QLabel("<b>Detected AP advertisements (Packets = Beacons + Probe Responses only; not all AP traffic):</b>"))
            self.ap_table = QTableWidget()
            self.ap_table.setColumnCount(9)
            self.ap_table.setHorizontalHeaderLabels(["BSSID", "SSID", "Channel", "Vendor", "AP Mgmt Frames", "Beacons", "Interval TU", "Security", "IE Changes"])
            self.ap_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            self.ap_table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
            self.ap_table.cellDoubleClicked.connect(self.choose_ap_row)
            for index, width in enumerate((170, 210, 90, 280, 145, 110, 130, 310, 120)):
                self.ap_table.setColumnWidth(index, width)
            layout.addWidget(self.ap_table)

        def init_stations_tab(self):
            layout = QVBoxLayout(self.tab_stations)
            layout.addWidget(QLabel("<b>Detected Client Stations / Probing Devices:</b>"))
            self.station_table = QTableWidget()
            self.station_table.setColumnCount(6)
            self.station_table.setHorizontalHeaderLabels(["Station MAC", "Vendor", "Observed AP BSSID", "AP SSID", "Evidence", "Packets"])
            self.station_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            self.station_table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
            for index, width in enumerate((200, 360, 200, 200, 220, 110)):
                self.station_table.setColumnWidth(index, width)
            layout.addWidget(self.station_table)

        def init_indicators_tab(self):
            layout = QVBoxLayout(self.tab_indicators)
            layout.addWidget(QLabel('Wireless anomalies are indicators, not botnet verdicts.'))
            self.indicators_table = QTableWidget()
            self.indicators_table.setColumnCount(4)
            self.indicators_table.setHorizontalHeaderLabels(["UTC", "Type", "BSSID", "Evidence"])
            self.indicators_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.indicators_table)

        def init_dns_tab(self):
            layout = QVBoxLayout(self.tab_dns)
            layout.addWidget(QLabel("DNS observation: plaintext, decoded UDP/TCP port 53 only. Encrypted Wi-Fi and DoH/DoT are not decoded."))
            self.dns_summary = QLabel("Decoded DNS queries: 0 | Responses: 0 | NXDOMAIN: 0")
            self.dns_summary.setStyleSheet("color: #00f5ff; padding: 8px; font-family: monospace;")
            layout.addWidget(self.dns_summary)
            self.dns_table = QTableWidget()
            self.dns_table.setColumnCount(4)
            self.dns_table.setHorizontalHeaderLabels(["Observed AP BSSID", "Queries", "Responses", "NXDOMAIN"])
            self.dns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.dns_table)
            self.dns_import_label = QLabel("Imported DNS logs: none (use Edge Flow Intelligence)")
            layout.addWidget(self.dns_import_label)

        def init_flow_tab(self):
            layout = QVBoxLayout(self.tab_flow)
            layout.addWidget(QLabel('Optional analysis of separately supplied firewall/Zeek/NetFlow JSONL. Not observable in encrypted Wi-Fi beacons.'))
            self.flow_text = QTextEdit()
            self.flow_text.setReadOnly(True)
            self.flow_text.setPlainText('No edge telemetry imported yet. Run orbitalctl.sh flow-analyze --help.')
            layout.addWidget(self.flow_text)

        def init_metrics_tab(self):
            layout = QVBoxLayout(self.tab_metrics)
            self.raw_table = QTableWidget()
            self.raw_table.setColumnCount(3)
            self.raw_table.setHorizontalHeaderLabels(["Metric Name", "Current Value", "Status"])
            self.raw_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.raw_table)

        def init_terminal_tab(self):
            layout = QVBoxLayout(self.tab_terminal)
            self.terminal_out = QTextEdit()
            self.terminal_out.setReadOnly(True)
            self.terminal_out.append("[+] BCI Orbital Sentinel GUI Console initialized under Developer Seal CJB-DEV-2026.")
            layout.addWidget(self.terminal_out)

        def toggle_freeze(self):
            self.frozen = not self.frozen
            if self.frozen:
                self.freeze_btn.setText("▶ Unfreeze Feed")
                self.freeze_btn.setStyleSheet("background-color: #00f5ff; color: #0b0b10;")
                self.status_lbl.setText("● FEED FROZEN")
                self.status_lbl.setStyleSheet("color: #ff2d55; font-weight: bold; font-family: monospace;")
            else:
                self.freeze_btn.setText("❄ Freeze Feed")
                self.freeze_btn.setStyleSheet("")
                self.status_lbl.setText("● SYSTEM ACTIVE")
                self.status_lbl.setStyleSheet("color: #00f5ff; font-weight: bold; font-family: monospace;")

        def selected_bssid(self):
            return self.network_selector.currentData()

        def on_network_changed(self, _index):
            if self.current_snapshot is not None:
                self.render_snapshot(self.current_snapshot)

        def choose_ap_row(self, row, _column):
            item = self.ap_table.item(row, 0)
            if item is None:
                return
            key = item.text().upper()
            for idx in range(self.network_selector.count()):
                if self.network_selector.itemData(idx) == key:
                    self.network_selector.setCurrentIndex(idx)
                    break

        def update_network_choices(self, aps):
            old = self.selected_bssid()
            self.network_selector.blockSignals(True)
            self.network_selector.clear()
            self.network_selector.addItem('All observed networks (global capture)', None)
            for ap in sorted(aps,key=lambda x:(str(x.get('ssid','')).casefold(),str(x.get('bssid','')))):
                bssid = str(ap.get('bssid','')).upper()
                if bssid:
                    self.network_selector.addItem(f"{ap.get('ssid', '<Hidden SSID>')} | {bssid} | Ch {ap.get('channel','?')}", bssid)
            found = next((idx for idx in range(self.network_selector.count())
                          if self.network_selector.itemData(idx) == old), 0)
            self.network_selector.setCurrentIndex(found)
            self.network_selector.blockSignals(False)

        def render_snapshot(self, state):
            metrics = state.get('metrics', {})
            aps = state.get('aps', [])
            stations = state.get('stations', [])
            indicators = state.get('indicators', [])
            selected = self.selected_bssid()
            # The top counters remain explicitly global; values are never
            # falsely presented as per-AP measurements.
            self.scope_info.setText('Scope: ' + scoped_ap_label(aps, selected) +
                ' | Frame totals global; edge logs not attributed to AP')
            self.lbl_frames.setText(f"<b>Global frames:</b> {int(metrics.get('frames_total', 0))}")
            self.lbl_beacons.setText(f"<b>Global beacons:</b> {int(metrics.get('beacons_total', 0))}")
            self.lbl_data.setText(f"<b>Global data:</b> {int(metrics.get('data_frames_total', 0))}")
            self.lbl_control.setText(f"<b>Global control:</b> {int(metrics.get('control_frames_total', 0))}")
            self.lbl_management.setText(f"<b>Global mgmt:</b> {int(metrics.get('management_frames_total', 0))}")
            self.lbl_dns.setText(f"<b>Global clear DNS:</b> {int(metrics.get('dns_packets_observed_total', 0))}")
            scoped_dns = visible_dns(state.get('dns_observation',{}).get('per_ap',{}),selected)
            if selected:
                counts = scoped_dns.get(selected, {})
                self.dns_summary.setText('Selected AP plaintext DNS | Queries: {} | Responses: {} | NXDOMAIN: {} (no clear DNS ≠ no DNS)'.format(
                    counts.get('queries',0),counts.get('responses',0),counts.get('nxdomain',0)))
            else:
                self.dns_summary.setText('All captured decoded DNS | Queries: {} | Responses: {} | NXDOMAIN: {}'.format(
                    metrics.get('dns_queries_observed_total',0), metrics.get('dns_responses_observed_total',0),
                    metrics.get('dns_nxdomain_observed_total',0)))
            self.dns_table.setRowCount(len(scoped_dns))
            for row,(bssid,counts) in enumerate(sorted(scoped_dns.items())):
                for col,value in enumerate((bssid,counts.get('queries',0),counts.get('responses',0),counts.get('nxdomain',0))):
                    self.dns_table.setItem(row,col,QTableWidgetItem(str(value)))
            self.lbl_aps.setText(f"<b>Global APs:</b> {int(metrics.get('aps_active',0))}")
            self.lbl_stations.setText(f"<b>Global stations:</b> {int(metrics.get('stations_active',0))}")
            self.lbl_rx_errors.setText(f"<b>Global RX errors:</b> {int(metrics.get('rx_errors',0))}")
            self.lbl_hunts.setText(f"<b>C2 hunts:</b> {int(metrics.get('c2_hunts_executed',0))}")
            self.lbl_traces.setText(f"<b>AP traces:</b> {int(metrics.get('traces_executed',0))}")
            ap_rows=visible_aps(aps,selected)
            self.ap_table.setRowCount(len(ap_rows))
            for row, ap in enumerate(ap_rows):
                vals = (ap.get('bssid',''),ap.get('ssid',''),ap.get('channel',''),ap.get('vendor',''),
                    ap.get('packets',0),ap.get('beacons',0),ap.get('beacon_interval_tu',''),
                    ap.get('security',''),ap.get('profile_changes',0))
                for col,v in enumerate(vals): self.ap_table.setItem(row,col,QTableWidgetItem(str(v)))
            station_rows=visible_stations(stations,selected)
            self.station_table.setRowCount(len(station_rows))
            for row, st in enumerate(station_rows):
                vals=(st.get('mac',''),st.get('vendor',''),st.get('ap',''),st.get('ap_ssid','Unknown'),
                      st.get('association_evidence','unconfirmed'),st.get('packets',0))
                for col,v in enumerate(vals): self.station_table.setItem(row,col,QTableWidgetItem(str(v)))
            indicator_rows=visible_indicators(indicators,selected)
            self.indicators_table.setRowCount(len(indicator_rows))
            for row, e in enumerate(indicator_rows):
                for col, key in enumerate(('timestamp_utc','type','bssid','detail')):
                    self.indicators_table.setItem(row,col,QTableWidgetItem(str(e.get(key,''))))
            if selected:
                self.flow_text.setPlainText('Selected AP: '+selected+'\n\nImported flow/DNS evidence is not mapped to a Wi-Fi BSSID.\n' +
                    'Return to All observed networks for the independent edge-flow summary.')
            else:
                flow_path = os.path.join(os.path.dirname(STATE_FILE_PATH),'flow_intel','flow_summary.json')
                if os.path.exists(flow_path):
                    try:
                        with open(flow_path,encoding='utf-8') as f:summary=json.load(f)
                        self.flow_text.setPlainText(json.dumps(summary,indent=2))
                        self.dns_import_label.setText(f"Imported DNS logs: {int(summary.get('dns_rows',0))} (separate source, no BSSID attribution)")
                    except (OSError,ValueError) as exc:
                        self.flow_text.setPlainText(f'Imported edge-flow summary unreadable: {type(exc).__name__}')
                else:
                    self.flow_text.setPlainText('No edge telemetry imported yet. Run orbitalctl.sh flow-analyze --help.')

        def poll_data(self):
            if self.frozen: return
            try:
                if os.path.exists(STATE_FILE_PATH):
                    with open(STATE_FILE_PATH, 'r', encoding='utf-8') as f:
                        state = json.load(f)
                    self.current_snapshot=state
                    self.last_state_version=state.get('version','unknown')
                    self.last_state_timestamp=state.get('updated_at_utc')
                    self.update_network_choices(state.get('aps',[]))
                    self.render_snapshot(state)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self.status_lbl.setText(f"● STATE UNAVAILABLE: {type(exc).__name__}")

            try:
                req = urllib.request.Request(PROMETHEUS_METRICS_URL, headers={'User-Agent': 'BCI-Sentinel-GUI'})
                with urllib.request.urlopen(req, timeout=0.35) as resp: content = resp.read().decode('utf-8')
                raw_metrics = {}
                for line in content.splitlines():
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2: raw_metrics[parts[0].split("{")[0]] = float(parts[1])
                # API liveness alone does not establish freshness of the saved state.
                try:
                    last = datetime.fromisoformat(str(getattr(self, 'last_state_timestamp', '')).replace('Z', '+00:00'))
                    fresh = abs((datetime.now(timezone.utc) - last).total_seconds()) <= 10
                except (ValueError, TypeError):
                    fresh = False
                if not self.frozen:
                    if fresh and getattr(self, 'last_state_version', '') == __version__:
                        self.status_lbl.setText("● API LIVE · SNAPSHOT FRESH")
                    else:
                        self.status_lbl.setText("● API LIVE · SAVED STATE STALE/OLDER VERSION")
                self.raw_table.setRowCount(len(raw_metrics))
                for row, (m_name, val) in enumerate(sorted(raw_metrics.items())):
                    self.raw_table.setItem(row, 0, QTableWidgetItem(m_name))
                    self.raw_table.setItem(row, 1, QTableWidgetItem(str(val)))
                    self.raw_table.setItem(row, 2, QTableWidgetItem("ACTIVE"))
            except (OSError, ValueError, urllib.error.URLError) as exc:
                if not self.frozen:
                    self.status_lbl.setText("● API OFFLINE · SHOWING SAVED OBSERVATIONS")
                if self.terminal_out.document().blockCount() < 100:
                    self.terminal_out.append(f"[BCI] Metrics polling: {type(exc).__name__}")

        def do_c2_hunt(self):
            if self.c2_worker is not None and self.c2_worker.isRunning():
                return
            self.c2_btn.setEnabled(False)
            self.status_lbl.setText('● REVIEWING C2-LIKE INDICATORS')
            self.c2_worker = C2HuntWorker(self.selected_bssid(), self)
            self.c2_worker.finished_report.connect(self._show_c2_hunt)
            self.c2_worker.failed_report.connect(self._c2_hunt_failed)
            self.c2_worker.finished.connect(lambda: self.c2_btn.setEnabled(True))
            self.c2_worker.start()

        def _show_c2_hunt(self, rep):
            lines = [
                'BEACON COMPUTING INITIATIVE — C2 HUNT REPORT',
                'Developer Seal: CJB-DEV-2026',
                'Mode: Passive wireless snapshot; no RF injection or channel sweep',
                f"Network scope: {rep.get('scope_bssid') or 'All observed networks'}",
                f"Imported edge flow not attributable to selected AP: {rep.get('flow_evidence_unattributed',False)}",
                f"Observed channels: {', '.join(rep.get('observed_channels', [])) or 'none'}",
                f"Access points observed: {rep.get('aps_observed', 0)}",
                f"Stations observed: {rep.get('total_stations_analyzed', 0)}",
                f"Wireless anomalies for review: {rep.get('wireless_indicators_found', 0)}",
                f"Separately imported edge-flow indicators: {rep.get('flow_indicators_found', 0)}",
                f"Edge-flow telemetry available: {rep.get('flow_evidence_available', False)}",
                '',
                'Wi-Fi beacon metadata alone cannot identify botnet C2 communications.',
            ]
            for event in rep.get('anomalies', [])[:30]:
                lines.append(f"• {event.get('indicator', 'Indicator')} | AP: {event.get('associated_ap', 'Unknown')}")
                lines.append(f"  {event.get('detail', '')}")
            msg = '\n'.join(lines)
            QMessageBox.information(self, 'C2 Hunt Report', msg)
            self.terminal_out.append(
                f"[BCI] C2 HUNT complete: {rep.get('wireless_indicators_found', 0)} wireless indicators; "
                f"{rep.get('flow_indicators_found', 0)} imported edge-flow indicators")
            if not self.frozen:
                self.status_lbl.setText('● SYSTEM ACTIVE')

        def _c2_hunt_failed(self, reason):
            QMessageBox.warning(self, 'C2 Hunt Failed', str(reason))
            self.terminal_out.append(f'[BCI] C2 hunt unavailable: {reason}')
            if not self.frozen:
                self.status_lbl.setText('● SYSTEM ACTIVE')

        def do_auto_trace(self):
            if self.trace_worker is not None and self.trace_worker.isRunning():
                return
            # Selected AP if a row is selected; otherwise automatically use
            # the most-observed beaconing AP. No RF transmission or retune.
            bssid = self.selected_bssid()
            idx = self.ap_table.currentRow()
            if bssid is None and idx >= 0 and self.ap_table.item(idx, 0) is not None:
                bssid = self.ap_table.item(idx, 0).text()
            self.trace_btn.setEnabled(False)
            self.trace_worker = AutoTraceWorker(bssid, self)
            self.trace_worker.finished_report.connect(self._show_auto_trace)
            self.trace_worker.failed_report.connect(self._auto_trace_failed)
            self.trace_worker.finished.connect(lambda: self.trace_btn.setEnabled(True))
            self.trace_worker.start()

        def _show_auto_trace(self, report):
            lines = [
                'BEACON COMPUTING INITIATIVE — AUTO-TRACE REPORT',
                'Developer Seal: CJB-DEV-2026',
                f"Mode: {report.get('mode', 'unknown')}",
                f"SSID: {report.get('target_ssid')}",
                f"BSSID: {report.get('target_bssid')}",
                f"Vendor: {report.get('vendor')}",
                f"Channel: {report.get('channel')}",
                f"Beacon count: {report.get('beacons_observed')}",
                f"Advertised interval: {report.get('beacon_interval_tu')} TU",
                f"RSSI: {report.get('rssi_last_dbm')} dBm",
                f"Station relationships observed: {report.get('associated_stations_count')}",
                '', 'Station relationships (inferred unless association response observed):'
            ]
            for station in report.get('station_evidence', [])[:30]:
                lines.append(f"• {station.get('mac')} | {station.get('vendor')} | {station.get('association_evidence')}")
            lines.extend(['', 'This trace did not transmit or change channels.',
                          'AP association evidence does not prove botnet activity.'])
            QMessageBox.information(self, 'Auto-Trace Report', '\n'.join(lines))
            self.terminal_out.append(
                f"[BCI] AUTO-TRACE {report.get('target_bssid')}: "
                f"{report.get('beacons_observed', 0)} beacons, "
                f"{report.get('associated_stations_count', 0)} station relationships")

        def _auto_trace_failed(self, error):
            QMessageBox.warning(self, 'Auto-Trace Failed', str(error))
            self.terminal_out.append(f'[BCI] Auto-Trace unavailable: {error}')

        def do_decrypt_dialog(self):
            file_path, _ = QFileDialog.getOpenFileName(self, "Select PCAP", os.path.expanduser("~"), "PCAP Files (*.pcap *.cap)")
            if not file_path: return
            ssid, ok1 = QInputDialog.getText(self, "WPA Decryption", "Target SSID:")
            if not ok1 or not ssid: return
            passphrase, ok2 = QInputDialog.getText(self, "WPA Decryption", "Passphrase:", QLineEdit.EchoMode.Password)
            if not ok2 or not passphrase: return
            success, result = decrypt_wpa_capture(file_path, ssid, passphrase)
            if success: QMessageBox.information(self, "Success", f"Saved to: {result}")
            else: QMessageBox.critical(self, "Failed", result)

    win = BCIControlCenter()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
