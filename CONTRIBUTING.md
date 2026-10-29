# Beacon Computing Initiative — Contributing

Developer Seal: `CJB-DEV-2026`

Preserve the stable passive capture pipeline and both service roles. Make only
scoped, test-backed changes and document any change to transmitted traffic.

Run:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile sentinel_exporter.py sentinel_gui.py flow_intel.py bci_monitor_select.py
bash -n orbitalctl.sh install_orbital.sh start_sentinel_gui.sh
sha256sum -c SHA256SUMS
```

The archive's `SHA256SUMS` covers release files; intentionally change and
regenerate it if contributing source changes. Never commit real capture data,
observed MAC addresses, local operational logs, credentials, or training
artifacts derived from nearby uninvolved networks.
