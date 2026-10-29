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
import subprocess
import urllib.request
import urllib.error
from urllib.parse import urlencode

__version__ = "4.6.11-TRACE"
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
                                     QLineEdit, QMessageBox, QInputDialog, QFileDialog, QSizePolicy)
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
        finished_report = pyqtSignal(dict)
        failed_report = pyqtSignal(str)

        def run(self):
            try:
                req = urllib.request.Request(
                    C2_HUNT_API_URL, headers={'User-Agent': 'BCI-Sentinel-GUI'})
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
            self.lbl_aps = QLabel("<b>Active APs:</b> 0")
            self.lbl_stations = QLabel("<b>Stations Tracked:</b> 0")
            self.lbl_rx_errors = QLabel("<b>RX Errors:</b> 0")
            self.lbl_hunts = QLabel("<b>C2 Hunts:</b> 0")
            self.lbl_traces = QLabel("<b>AP Traces:</b> 0")
            for lbl in [self.lbl_frames, self.lbl_aps, self.lbl_stations, self.lbl_rx_errors, self.lbl_hunts, self.lbl_traces]:
                lbl.setStyleSheet("background-color: #14141f; border: 1px solid #1e1e2d; padding: 12px; color: #00f5ff; border-radius: 6px;")
                metrics_layout.addWidget(lbl)
            layout.addLayout(metrics_layout)

            layout.addWidget(QLabel("<b>Detected Access Points (BSSID / SSID / Channel / Vendor / Packets):</b>"))
            self.ap_table = QTableWidget()
            self.ap_table.setColumnCount(9)
            self.ap_table.setHorizontalHeaderLabels(["BSSID", "SSID", "Channel", "Vendor", "Packets", "Beacons", "Interval TU", "Security", "IE Changes"])
            self.ap_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.ap_table)

        def init_stations_tab(self):
            layout = QVBoxLayout(self.tab_stations)
            layout.addWidget(QLabel("<b>Detected Client Stations / Probing Devices:</b>"))
            self.station_table = QTableWidget()
            self.station_table.setColumnCount(6)
            self.station_table.setHorizontalHeaderLabels(["Station MAC", "Vendor", "Observed AP BSSID", "AP SSID", "Evidence", "Packets"])
            self.station_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.station_table)

        def init_indicators_tab(self):
            layout = QVBoxLayout(self.tab_indicators)
            layout.addWidget(QLabel('Wireless anomalies are indicators, not botnet verdicts.'))
            self.indicators_table = QTableWidget()
            self.indicators_table.setColumnCount(4)
            self.indicators_table.setHorizontalHeaderLabels(["UTC", "Type", "BSSID", "Evidence"])
            self.indicators_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.indicators_table)

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

        def poll_data(self):
            if self.frozen: return
            try:
                if os.path.exists(STATE_FILE_PATH):
                    with open(STATE_FILE_PATH, "r", encoding="utf-8") as f: state = json.load(f)
                    metrics, aps, stations = state.get("metrics", {}), state.get("aps", []), state.get("stations", [])
                    indicators = state.get("indicators", [])
                    self.status_lbl.setText("● SYSTEM ACTIVE")
                    self.lbl_frames.setText(f"<b>Total Frames:</b> {int(metrics.get('frames_total', 0))}")
                    self.lbl_aps.setText(f"<b>Active APs:</b> {int(metrics.get('aps_active', 0))}")
                    self.lbl_stations.setText(f"<b>Stations Tracked:</b> {int(metrics.get('stations_active', 0))}")
                    self.lbl_rx_errors.setText(f"<b>RX Errors:</b> {int(metrics.get('rx_errors', 0))}")
                    self.lbl_hunts.setText(f"<b>C2 Hunts:</b> {int(metrics.get('c2_hunts_executed', 0))}")
                    self.lbl_traces.setText(f"<b>AP Traces:</b> {int(metrics.get('traces_executed', 0))}")

                    self.ap_table.setRowCount(len(aps))
                    for row, ap in enumerate(aps):
                        self.ap_table.setItem(row, 0, QTableWidgetItem(ap.get("bssid", "")))
                        self.ap_table.setItem(row, 1, QTableWidgetItem(ap.get("ssid", "")))
                        self.ap_table.setItem(row, 2, QTableWidgetItem(str(ap.get("channel", ""))))
                        self.ap_table.setItem(row, 3, QTableWidgetItem(ap.get("vendor", "")))
                        self.ap_table.setItem(row, 4, QTableWidgetItem(str(ap.get("packets", 0))))
                        self.ap_table.setItem(row, 5, QTableWidgetItem(str(ap.get("beacons", 0))))
                        self.ap_table.setItem(row, 6, QTableWidgetItem(str(ap.get("beacon_interval_tu", ""))))
                        self.ap_table.setItem(row, 7, QTableWidgetItem(str(ap.get("security", ""))))
                        self.ap_table.setItem(row, 8, QTableWidgetItem(str(ap.get("profile_changes", 0))))

                    self.station_table.setRowCount(len(stations))
                    for row, st in enumerate(stations):
                        self.station_table.setItem(row, 0, QTableWidgetItem(st.get("mac", "")))
                        self.station_table.setItem(row, 1, QTableWidgetItem(st.get("vendor", "")))
                        self.station_table.setItem(row, 2, QTableWidgetItem(st.get("ap", "")))
                        self.station_table.setItem(row, 3, QTableWidgetItem(st.get("ap_ssid", "Unknown")))
                        self.station_table.setItem(row, 4, QTableWidgetItem(st.get("association_evidence", "unconfirmed")))
                        self.station_table.setItem(row, 5, QTableWidgetItem(str(st.get("packets", 0))))
                    self.indicators_table.setRowCount(len(indicators))
                    for row, e in enumerate(indicators):
                        for col, key in enumerate(("timestamp_utc", "type", "bssid", "detail")):
                            self.indicators_table.setItem(row, col, QTableWidgetItem(str(e.get(key, ""))))
                    flow_path = os.path.join(os.path.dirname(STATE_FILE_PATH), 'flow_intel', 'flow_summary.json')
                    if os.path.exists(flow_path):
                        with open(flow_path, encoding='utf-8') as f:
                            flow_summary = json.load(f)
                        self.flow_text.setPlainText(json.dumps(flow_summary, indent=2))
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
                self.raw_table.setRowCount(len(raw_metrics))
                for row, (m_name, val) in enumerate(sorted(raw_metrics.items())):
                    self.raw_table.setItem(row, 0, QTableWidgetItem(m_name))
                    self.raw_table.setItem(row, 1, QTableWidgetItem(str(val)))
                    self.raw_table.setItem(row, 2, QTableWidgetItem("ACTIVE"))
            except (OSError, ValueError, urllib.error.URLError) as exc:
                if self.terminal_out.document().blockCount() < 100:
                    self.terminal_out.append(f"[BCI] Metrics polling: {type(exc).__name__}")

        def do_c2_hunt(self):
            if self.c2_worker is not None and self.c2_worker.isRunning():
                return
            self.c2_btn.setEnabled(False)
            self.status_lbl.setText('● REVIEWING C2-LIKE INDICATORS')
            self.c2_worker = C2HuntWorker(self)
            self.c2_worker.finished_report.connect(self._show_c2_hunt)
            self.c2_worker.failed_report.connect(self._c2_hunt_failed)
            self.c2_worker.finished.connect(lambda: self.c2_btn.setEnabled(True))
            self.c2_worker.start()

        def _show_c2_hunt(self, rep):
            lines = [
                'BEACON COMPUTING INITIATIVE — C2 HUNT REPORT',
                'Developer Seal: CJB-DEV-2026',
                'Mode: Passive wireless snapshot; no RF injection or channel sweep',
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
            bssid = None
            idx = self.ap_table.currentRow()
            if idx >= 0 and self.ap_table.item(idx, 0) is not None:
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
