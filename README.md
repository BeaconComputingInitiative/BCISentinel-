# BCI Orbital Sentinel

**Beacon Computing Initiative · Defensive wireless observation and network threat-intelligence analysis**  
**Release:** v4.6.13-NETSCOPE · **Developer seal:** `CJB-DEV-2026` · **Platform:** Kali Linux / Debian-compatible Linux · **Python, Docker, Scapy, PyQt6, Prometheus**

![Cerberus guarding the BCI gates — Orbital Sentinel project emblem](assets/cerberus-bci.jpg)

> **Observe accurately. Preserve faithfully. Analyze transparently. Communicate securely. Act deliberately.**

## What is Orbital Sentinel?

**Orbital Sentinel is a locally operated, defensive 802.11 observation and traffic-intelligence workstation developed by the Beacon Computing Initiative (BCI).** Its purpose is to turn wireless management traffic and independently obtained network telemetry into structured, reviewable evidence about nearby access points, client activity, changes in radio behavior, and patterns that may warrant security investigation.

A dedicated Wi-Fi adapter, already configured in **monitor mode**, listens for 802.11 frames without associating with the observed networks. Two isolated capture roles—**Sentinel** and **Discovery**—run in Docker and expose metrics over local-only HTTP endpoints. The **PyQt6 control center** presents the observed AP inventory, stations, wireless indicators, imported edge-flow findings, raw Prometheus metrics, and operational logs. Capture-state snapshots and machine-readable JSONL records support offline comparison, incident review, and future supervised ML pipelines; the software does not invent ground-truth malware labels.

The project is **not a Wi-Fi intrusion tool or proof-of-compromise engine**. It does not need a password or network association to observe public management frames. It cannot decode third-party encrypted application traffic merely by monitoring beacons. C2-related indicators require corroborating information such as authorized DNS, router, firewall, or Zeek/NetFlow records.

### Who is it for?

Orbital Sentinel is intended for defensive researchers, wireless administrators, blue teams, and purple teams who operate on their own equipment or with authorization. It is useful for establishing a local wireless baseline, noticing management-frame irregularities, studying AP advertising behavior, and correlating authorized edge traffic with known security indicators.

## How the system works

```text
Dedicated monitor-mode Wi-Fi interface (e.g., wlan1)
                      |
                802.11 frames
                      |
       +--------------+--------------+
       |                             |
  Sentinel service              Discovery service
  Docker + Scapy                 Docker + Scapy
       |                             |
       +--- AP / station / beacon observations
       |    association-evidence / wireless indicators
       |
       +--- /data state JSON and JSONL feature windows
       |                             |
       +--- localhost:9100          +--- localhost:9101
                      |
         PyQt6 Orbital Control Center
         APs | Stations | Indicators | Flow Intel
         Metrics | Terminal | C2 Hunt | Auto-Trace
                      ^
                      |
        Authorized firewall / Zeek / DNS logs
                  (offline import)
```

### Wireless observation: what the radio can actually see

| Evidence | Implementation and significance | Important limitation |
| --- | --- | --- |
| **AP beacons** | Per-BSSID observation counts, SSID, advertised channel, timing, RSSI, intervals, RSN/security advertisement, and information-element changes | Beacons advertise network configuration; they are not malware callbacks |
| **Vendor** | Manufacturer label inferred from locally installed OUI data | Locally administered/randomized MAC addresses may not identify a vendor |
| **Stations and AP relationships** | Records observed BSSID/SSID relationships and differentiates association-response evidence, traffic evidence, and unconfirmed links | An observed MAC address is not proof of user/device identity or authenticated membership |
| **Wireless indicators** | Deauthentication/disassociation bursts, EAPOL observations, beacon TSF discontinuities, and profile changes | Indicators can result from normal operations, interference, or configuration changes |
| **Passive AP Auto-Trace** | Selects an observed AP and summarizes its advertised profile, beacon evidence, and station relationships | Does not locate the physical AP or access its encrypted content |

### Network threat intelligence: a *separate* evidence stream

When **authorized flow and DNS logs** are supplied, an offline analyzer can look for patterns consistent with regular outbound check-ins, unusual DNS failures / algorithmically generated domains, destination/port anomalies, elevated ICMP or TCP SYN activity, outbound scanning, SMTP fan-out, and locally supplied IoC matches. These are **investigation leads, not botnet verdicts**; periodic connections and unusual DNS behavior can have benign causes. The analyzer never treats an AP's ordinary Wi-Fi beacon periodicity as C2 traffic.

**C2 Hunt** (`/hunt_c2`) is a bounded, read-only review of available wireless indicators and separately imported flow intelligence. It does **not** launch a channel sweep, transmit frames, or connect to a network. **Auto-Trace** (`/trace`) provides a passive AP-centered report. A small directed-probe facility exists separately for expressly authorized testing and is **disabled by default**; never enable it against networks you do not administer or have permission to test.

## Control center and operation

The Qt GUI contains **APs & Telemetry**, **Tracked Stations**, **Wireless Indicators**, **Edge Flow Intelligence**, **Raw Prometheus Metrics**, and **Terminal Stream** tabs. Operator controls include **Hunt C2 Signatures**, **Auto-Trace AP**, **Freeze Feed**, and a local WPA capture-file decryption dialog (requiring keys and authorization).

Two Docker services expose local-only HTTP telemetry on ports **9100** and **9101**. Their packet counters may overlap because both observe the same radio; do not sum them to estimate unique traffic. A successful Docker start is only a *process-liveness* result: confirm increasing frame counters and populated state files to verify actual radio reception. The capture radio is selected from interfaces already in monitor mode; managed `wlan0` is not repurposed by the installer.

Typical control commands after installation:

```bash
ORBITAL="$HOME/BCI/Docker Projects/orbital/orbitalctl.sh"
bash "$ORBITAL" doctor
bash "$ORBITAL" verify
bash "$ORBITAL" test
bash "$ORBITAL" start
bash "$ORBITAL" status
bash "$ORBITAL" metrics
bash "$ORBITAL" gui
# In a second terminal:
bash "$ORBITAL" hunt-c2
bash "$ORBITAL" trace
```

**Run the installer as your normal Kali desktop user, not through `sudo`.** It writes under `$HOME/BCI/Docker Projects/orbital`, backs up overwritten project files, preserves existing `captures/`, and uses Docker privilege escalation only when needed. It checks the full source `SHA256SUMS` manifest before installation; the 2026-10-29 integrity hotfix explicitly installs nested workflow files and dotfiles so the installed manifest also verifies.

## Evidence, privacy, and operational assurance

- **Local first:** captures, state files, indicators, and JSONL features remain on the workstation unless the operator explicitly moves them. There is no automated cloud synchronization.
- **Evidence fidelity:** SSID/BSSID and station MACs appear in the local operator-facing view; ML-oriented records use per-session pseudonyms. Review logs and captures before publication because they may reveal nearby devices and networks.
- **Integrity:** Release source files are SHA-256 hashed. Outputs may also receive per-role checksums on orderly shutdown. A hash establishes *byte integrity*, not that observations are true or malicious.
- **Authorization boundary:** Passive radio observation and optional active probing must comply with applicable rules and permissions. Deauthentication and forced-disconnection functions are not part of the Auto-Trace workflow.
- **Validation status:** Unit and synthetic integration tests cover processing and APIs. The user's earlier v4.6.7 deployment received actual monitor-mode traffic on channel 1; the newer v4.6.11 live hardware/GUI behavior still requires its own validation.

## Why Cerberus?

The project's emblem is **Cerberus**, the three-headed guardian of the underworld's gates in Greek mythology, reinterpreted as BCI's perimeter sentinel. The **three heads** symbolize concurrent observation, correlation, and deliberate response. The **gates** represent the boundary between trusted assets and untrusted network activity. **BCI** is forged into the gate itself to mark the protector and the protected domain. The **black/obsidian armor**, **maroon-red light**, and **electric cyan eyes** carry the Beacon Computing Initiative's visual identity. The artwork communicates the product's mission: **watch the boundary, preserve the evidence, and investigate before acting**. It is a project illustration, not an assertion that the program blocks or controls network ingress/egress.

---

## Technical reference, install procedure, and release notes

The following sections document implementation details, supported inputs, and commands.

Developer Seal: **CJB-DEV-2026**. Project seal: BEACON-COMPUTING-INITIATIVE-ORBITAL-SENTINEL-LINUX.

## Feature-preserving upgrade from v4.6.7-op2

Retains the existing **two passive Docker services**, Prometheus on localhost ports **9100/9101**, PyQt6 dashboard, frozen feed, station/AP tables, terminal stream, offline WPA-capture decryption dialog, automatic eligible monitor-mode interface selection, storage checks, and graceful shutdown. Capture interface is never reconfigured by this release.

Enhancements:
- Per-BSSID beacon counts, last signal, interval, TSF reset indicators, interarrival timing, a limited rolling beacon history, IE profile changes, and WPA/RSN advertisement.
- AP and station vendor labels from an OUI database copied locally from the host when available; randomized/local MACs are labelled as unknown.
- Associated AP BSSID and SSID for observed station traffic with **association_response_observed**, **traffic_observed**, or **unconfirmed** evidence categories. This is not authentication proof.
- Passive deauthentication/disassociation burst indicators and EAPOL counters. These indicators alone do **not** prove botnet compromise.
- Streaming per-AP beacon feature windows (`captures/ml/{role}_beacon_windows.jsonl`), wireless anomaly records (`{role}_indicators.jsonl`), and per-role SHA-256 checksums on graceful shutdown.
- Separate **offline** edge network intelligence: reads operator-provided normalized/Zeek JSONL flow and DNS records and optional local IoC JSON for periodic network callouts, NXDOMAIN/DGA-like activity, protocol/port mismatches, large ICMP, TCP SYN spikes, SMTP fanout, external scanning patterns, reputation matches, shared DDNS/new domains, and multiple DNS answers. Generates `flow_indicators.jsonl`, `flow_ml_features.jsonl`, summary JSON, and SHA-256 manifest.

## Limits — do not conflate two types of beacons

**802.11 Wi-Fi beacons** are AP management broadcasts and can be read without joining the network. **Botnet/C2 check-in beaconing** refers to periodic IP network connections and is **not observable from encrypted Wi-Fi beacons alone**. The optional flow analyzer requires independently obtained lawful edge telemetry from firewalls, flow collectors, routers, or DNS resolvers. `wlan1` monitoring does not supply that data.

Detection rules are configurable heuristics, not attribution or malware verdicts. DNS flux / shared dynamic DNS can be legitimate CDN/DDNS. Nearby vendors are inferred only for globally administered MAC OUIs present in the local manufacturer database. The release does not inject packets, decrypt Wi-Fi traffic, or run port scans. It does not automatically download threat feeds.

## Install — run as your normal desktop user

```bash
# BEACON COMPUTING INITIATIVE | CJB-DEV-2026
# Stop current v4.6.7-op2 capture before upgrading:
"$HOME/BCI/Docker Projects/orbital/orbitalctl.sh" stop
cd ~/Downloads
unzip -o BCI-Orbital-Sentinel-v4.6.13-NETSCOPE.zip
cd BCI-Orbital-Sentinel-v4.6.13-NETSCOPE
sha256sum -c SHA256SUMS
bash install_orbital.sh
ORBITAL="$HOME/BCI/Docker Projects/orbital/orbitalctl.sh"
bash "$ORBITAL" test
bash "$ORBITAL" start
bash "$ORBITAL" metrics
bash "$ORBITAL" gui
```

**Never `sudo bash install_orbital.sh`**; Docker permission prompts are handled by the control script. The installed directory with spaces is intentional and existing captures are preserved.

## Optional external telemetry import

```bash
# Review help and permitted fields; supply your OWN authorized edge logs.
bash "$ORBITAL" flow-analyze --help
bash "$ORBITAL" flow-analyze \
  --flows /path/to/zeek_conn.jsonl \
  --dns /path/to/zeek_dns.jsonl \
  --ioc /path/to/local_ioc.json \
  --out-dir "$HOME/BCI/Docker Projects/orbital/captures/flow_intel"
```

Inputs: Zeek JSONL `conn.log` fields `ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `orig_bytes`, `resp_bytes`, etc.; Zeek JSONL `dns.log` with `query`, `rcode_name`, `answers`, `id.orig_h`; or normalized flow records with `ts`, `src_ip`, `dst_ip`, `dst_port`, `proto`, `bytes`, `service`, `tcp_flags`, `domain`, `dst_asn`. Local IoC JSON lists: `ips`, `domains`, `asns`, `new_domains`, `ddns_suffixes`.

Data set `label` remains `null`. ML exports pseudonymize host/AP identifiers within a session. Hashes prove file integrity against the accompanying manifest, not data correctness or authorship.

## Operational verification

```bash
bash "$ORBITAL" doctor
bash "$ORBITAL" status
bash "$ORBITAL" metrics
find "$HOME/BCI/Docker Projects/orbital/captures/ml" -name '*.jsonl' -type f
```

Container capture on your actual Kali adapter, vendor database availability, and PyQt6 GUI rendering must be verified after installation. All integration tests are local/synthetic until that validation.

## v4.6.13-NETSCOPE — integrated GUI button and local API

The GUI adds **Hunt C2 Signatures**, a nonblocking request to
`http://127.0.0.1:9100/hunt_c2`. It performs a bounded review of already
observed wireless indicators and any **separately imported**, authorized
edge-flow intelligence. It does not inject probe frames, retune the radio,
spoof another adapter's MAC address, or infer C2 from high packet count.

The endpoint returns backward-compatible response keys (`success`, `report`,
`anomalies`, `sweep_channels`), along with the true `observed_channels` and
`mode`. `sweep_channels` is empty because no RF scan was performed by the C2
Hunt action. Metrics expose `bci_orbital_c2_hunts_total`; the GUI displays
this counter. Each successful hunt appends a pseudonymized ML feature record
in `captures/ml/sentinel_c2_hunts.jsonl`. On graceful shutdown the exporter
updates its role-specific SHA-256 manifest. Neither wireless indicators nor
flow heuristics are verified botnet labels.

CLI equivalent: `bash orbitalctl.sh hunt-c2`. The HTTP interface is bound
to `127.0.0.1` only. Both original passive services are unchanged.

## v4.6.13-NETSCOPE — AP Auto-Trace integration

The **Auto-Trace AP** GUI button and `bash orbitalctl.sh trace [BSSID]` query
`GET /trace` at `127.0.0.1:9100`. The button uses a selected AP row when available,
or automatically selects the AP with the most **observed beacons**. The report
contains BSSID, SSID, channel, vendor, beacon count, advertised interval, RSSI,
security, and observed station relationship evidence. It does not claim a station
is authenticated based solely on a data-frame header. The passive trace does not
change channels, inject frames, deauthenticate clients, or connect to an AP.

Each successful trace appends a pseudonymized `captures/ml/sentinel_traces.jsonl`
record (or `discovery_traces.jsonl` when called on the discovery API). Raw station
MACs and BSSIDs appear in the operator-facing report, not in the ML JSONL. A
per-role SHA-256 manifest is finalized on graceful shutdown. Prometheus adds
`bci_orbital_traces_total` and `bci_orbital_trace_probes_sent_total`.

### Explicit active trace (optional, disabled by default)

The original user-supplied Auto-Trace snippet proposed automatically switching
channels and injecting 25 frames using another adapter's hardcoded MAC. This
release replaces that with a separate, opt-in `POST /trace/probe` action that
requires an observed target BSSID, affirmative authorization, the current radio
channel already matching the advertised AP channel, and a 60-second cooldown.
It sends at most two directed **probe requests**, using the selected monitor
interface's real MAC. It never sends deauthentication frames. A successful Scapy
call does not prove transmission or a response.

For a network you administer and are authorized to probe, stop capture then
start with `BCI_ACTIVE_PROBE_ENABLED=1 bash orbitalctl.sh start`, and use
`bash orbitalctl.sh trace-probe BSSID --authorize`. To return to disabled
mode, stop and restart without that environment variable. The active endpoint
is only served by the sentinel role on loopback. Ordinary `trace` and GUI use
passive mode regardless of this setting.

This is an operational integration; real wireless probe transmission and GUI
rendering require verification on the Kali adapter. No botnet attribution is
inferred from Wi-Fi beacon periodicity or station packet counts.

## Installation integrity hotfix (2026-10-29)

The installer now copies `.github/workflows/ci.yml`, `.gitignore`, and
`CONTRIBUTING.md` into the installed project because these files are included
in `SHA256SUMS`. Previously their absence prevented `orbitalctl.sh start`
from passing the release integrity gate. A clean-install regression test
now verifies every manifest entry after installation. Existing capture files
are preserved.


## v4.6.13-NETSCOPE — Frame classes and DNS visibility

Frame totals now distinguish 802.11 management, data, control and other frames;
`beacons_total` and `probe_responses_total` are specific management subsets,
not additional frames. The AP table's *AP Mgmt Frames* column means beacon
plus probe-response advertisements from that BSSID, **not all IP traffic**.
The station table remains observational and does not assume authentication.

### Passive DNS observation

The DNS tab counts only **successfully decoded unprotected Wi-Fi data frames**
containing DNS over UDP/TCP port 53. It displays query/response/NXDOMAIN counts
and per-BSSID totals, without storing raw queried domains, source IPs or payloads.
These counters can remain zero on WPA2/WPA3 networks even while frames rise.
Encrypted DNS-over-HTTPS/TLS and VPN DNS are not decoded. The Edge Flow panel
remains a **separate** offline pipeline for authorized DNS or Zeek logs, with
`dns_rows`, NXDOMAIN/DGA heuristics, and IoC corroboration.

Metrics: `bci_orbital_management_frames_total`, `data_frames_total`,
`control_frames_total`, `other_frames_total`,
`other_management_frames_total`, `beacons_total`,
`dns_packets_observed_total`, `dns_queries_observed_total`,
`dns_responses_observed_total`, and `dns_nxdomain_observed_total`.

The GUI differentiates API-offline saved observations from live, current-version
state. Manufacturer lookup ignores IEEE `(base 16)` address continuation lines.
No wireless injection, AP joining, automatic channel hopping, or firewall changes
were introduced. Network monitoring must comply with applicable authorization.

## v4.6.13-NETSCOPE — per-network investigation scope

A **Network scope** selector now filters AP inventory, stations with observed AP evidence, wireless indicators, and passively decoded plaintext DNS metadata by selected **BSSID**. Identical SSIDs may refer to distinct APs, so the selector distinguishes their BSSIDs and channel. The selection persists across refreshes and a double-click on an AP row chooses that network. The **All observed networks** choice restores global view.

**Global frame-class counters remain global** and say so. A passive network selection does not retune the radio, transmit packets, or force a Wi-Fi association. Plaintext DNS is displayed per AP only when an unprotected frame can be decoded with a reliable AP header. Encrypted traffic, DNS-over-HTTPS and resolver/Zeek imports are **not** assigned to a wireless BSSID without separate authoritative correlation.

`Hunt C2 Signatures` passes the selected BSSID to `/hunt_c2?bssid=...`; this filters only wireless indicators belonging to that AP. Imported edge-flow findings are held separate and explicitly marked unassociated in AP-scoped reports. API defaults without `bssid` remain compatible. CLI: `bash orbitalctl.sh hunt-c2 [BSSID]` and `bash orbitalctl.sh trace [BSSID]`.
