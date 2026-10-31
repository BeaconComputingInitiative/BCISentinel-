# BEACON COMPUTING INITIATIVE
**Developer Seal:** `CJB-DEV-2026`  
**Component:** BCISentinel- / Orbital Sentinel developer history register  
**Audit baseline:** October 31, 2026  
**Repository:** https://github.com/BeaconComputingInitiative/BCISentinel-

## Evidence semantics

A published commit verifies that source was changed; a passing CI run verifies only the asserted checks. Chat-origin requirements and local testing reports are labeled as such, not silently converted to GitHub releases. This record combines public main-branch history with available related ChatGPT development discussions. Times in commit ledger use UTC. No credentials, personal device addresses or unredacted private network observations are published.

## Historical GitHub updates — one entry for each existing commit

**Audited baseline commit:** `2b4ab0c6c458e0749c86fe3055b7fe4046b2a4a2` (16 commits). The repository's release manifest identifies an in-development 4.6.15 interface GUI, not a validated production deployment.

| # | Git timestamp | Commit | Change recorded in Git | GitHub Actions result for that commit |
|---:|---|---|---|---|
| 01 | 2026-10-29 10:10:35 UTC | [`5064f09ee74`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/5064f09ee7484735301c7a6208e54ea6d344070c) | docs: initialize BCISentinel with Orbital Sentinel 4.6.11 overview | no per-commit workflow evidence |
| 02 | 2026-10-29 10:11:49 UTC | [`77f1f932db8`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/77f1f932db8f13ef07bf25523ff5d72c0ef07deb) | feat: publish Orbital Sentinel v4.6.11 Auto-Trace, C2 Hunt and ML telemetry | [success](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/40855641832) |
| 03 | 2026-10-29 10:35:26 UTC | [`f0ede87adea`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/f0ede87adea2f02a21f0854a7abcc62ed5796fac) | fix: complete Sentinel integrity installer and document Cerberus BCI guardian | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/40858841000) |
| 04 | 2026-10-29 11:05:09 UTC | [`f0928185fc1`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/f0928185fc1b1f3d101857ace30bffa33f468bdd) | feat: release v4.6.13 network-scoped 802.11 and plaintext DNS telemetry | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/40862647833) |
| 05 | 2026-10-29 11:14:25 UTC | [`1094da3f005`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/1094da3f0056baaee2995155de79a90a5d8d9297) | fix: restore tested operational regression file matching v4.6.13 SHA256SUMS | [success](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/40863838856) |
| 06 | 2026-10-31 20:33:23 UTC | [`1605da505b4`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/1605da505b49f23a5f81fce9658f045c3a316c11) | feat(gui): allow Nexus tabs in existing Sentinel Qt window | [success](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41239456859) |
| 07 | 2026-10-31 21:40:39 UTC | [`80613ef8907`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/80613ef8907f88f1baa61891619a597536a6d9fc) | feat(sentinel): select any existing interface or idle mode without internet checks | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41244701703) |
| 08 | 2026-10-31 21:41:18 UTC | [`5c0c9ff1a48`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/5c0c9ff1a48fc70d32907df4842d0ca282f67eb0) | feat(sentinel): capture link packets without radio/internet and preserve historical state in idle | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41244751978) |
| 09 | 2026-10-31 21:42:39 UTC | [`2651114d588`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/2651114d5884f264f605915d4c01eb93ec79ad0b) | test(sentinel): offline interface selection and preservation of capture history | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41244854011) |
| 10 | 2026-10-31 21:43:12 UTC | [`680169e1744`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/680169e17443af3710ed6926d12b3aa88a9aae64) | chore(release): seal universal-interface Sentinel v4.6.14-FLEX hashes | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41244894438) |
| 11 | 2026-10-31 21:44:09 UTC | [`ce0a8612d9d`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/ce0a8612d9d6eb9ca470c40090baf68c9fb7a7a0) | fix(sentinel): repair universal-interface shell selector and remove duplicated tail | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41244965630) |
| 12 | 2026-10-31 21:44:34 UTC | [`730258d4f3c`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/730258d4f3c2ab4aa6a1b5c5c0c4eee855daa78c) | chore(integrity): seal repaired passive interface launcher | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41244996472) |
| 13 | 2026-10-31 21:45:23 UTC | [`d6cbbc3e9ca`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/d6cbbc3e9ca4ccdd9c612a6c6bfd4d258aa80be7) | test(sentinel): isolate probe cooldown across regression cases | [success](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41245062209) |
| 14 | 2026-10-31 21:47:15 UTC | [`ed6e4725a22`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/ed6e4725a2253428569235f275fe9aa9468593f9) | feat(gui): offline-capable capture interface dropdown, refresh, and approved start | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41245205817) |
| 15 | 2026-10-31 21:47:58 UTC | [`450a3882017`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/450a3882017ea1f3ec9377195d4e83965accb60e) | test(release): seal capture-interface dropdown with offline enumeration coverage | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41245261114) |
| 16 | 2026-10-31 21:49:31 UTC | [`2b4ab0c6c45`](https://github.com/BeaconComputingInitiative/BCISentinel-/commit/2b4ab0c6c458e0749c86fe3055b7fe4046b2a4a2) | fix(integrity): reconcile GUI blob SHA-256 with published source | [failure](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41245378767) |

## Chat-driven development updates (including work predating GitHub)

Each line below represents a feature request or operator discussion in the available ChatGPT development record. Its status is intentionally independent of whether a matching commit was eventually published.

| Chat update | Date (2026) | Conversation requirement or observation | Evidence and limitation |
|---|---|---|---|
| SN-C01 | Oct 28–29 | Evolve Orbital/Purple Team Sentinel from a single-script Kali radio monitor with vendor OUI database, channel awareness, EAPOL/beacon/probe capture, station inventory and PyQt UI into a managed defensive capture service. | Development notes and terminal output; no standalone Git release for every early script revision |
| SN-C02 | Oct 29 and prior | v4.6.0: divide passive Sentinel and Discovery capture roles, Docker services, a dedicated existing monitor interface, source integrity, operator safeguards and local Prometheus telemetry. | Chat and historical project documentation; actual unattended deployment varies by workstation |
| SN-C03 | Oct 29 and prior | v4.6.3–4.6.4: repair monitor-mode identification using \`iw dev\`, tolerate DORMANT/NO-CARRIER states, avoid changing radio modes/NetworkManager, and reject ambiguous radio selections. | Chat/history and saved project documentation, not one-to-one Git commits |
| SN-C04 | Oct 29 and prior | v4.6.7: monitor-mode source observed receiving real radio traffic on the chosen channel; do not equate radio reception with reliable AP attribution. | Conversation-reported local observation |
| SN-C05 | Oct 29 | Publish v4.6.11 with AP and beacon history, OUI/vendor mapping, station-AP evidence, Auto-Trace, C2 Hunt, offline edge-flow imports, PyQt6, Docker roles, Prometheus, JSONL; GitHub repo has a trailing hyphen in its name. | Git and prior conversation; initial CI success reported |
| SN-C06 | Oct 29 | v4.6.12/13: distinguish management/control/data/cleartext DNS counters and per-BSSID scope; fix integrity/operational tests. | Git commits and CI; plaintext DNS observations alone cannot establish encrypted C2 |
| SN-C07 | Oct 29 | Operator reported active monitor capture: approximately +2,434 frames and +1,028 beacons in a 10-second interval, 76 APs, 181 stations, snapshot age about 1.2 seconds. | **Operator-reported runtime verification for the earlier monitor release**, not proof of the later flexible-interface build |
| SN-C08 | Oct 31 | Embed Sentinel's existing QMainWindow into BCI Nexus rather than spawning a second window, retaining the control center as the source of capture views. | Git changes and Nexus integrated-GUI screenshots |
| SN-C09 | Oct 31 | GUI showed stored historical state and offline API; operator confirmed their dedicated monitor-mode adapter was unavailable. | Operator explanation and screenshot; historical data must not be represented as live traffic |
| SN-C10 | Oct 31 | Remove mandatory online/monitor-adapter startup gate: support monitor Wi-Fi, managed Wi-Fi, Ethernet, explicit loopback and no-interface idle; do not configure interface modes or routing. | Git v4.6.14-FLEX implementation; managed/Ethernet packets cannot provide surrounding 802.11 beacon inventory |
| SN-C11 | Oct 31 | Preserve last real capture snapshot during idle; publish a distinct runtime-status JSON, capture readiness and non-802.11 counters; periodically refresh status without fabricating frames. | Git implementation, unit tests; current hardware-level behavior unverified |
| SN-C12 | Oct 31 | Add a native Capture interface selector (Auto, None/Idle, detected devices including DOWN), refresh inventory, and explicit operator-confirmed start, separate from Network scope. | Git v4.6.15-IFACEGUI implementation; **current head CI still fails two tests** |
| SN-C13 | Oct 31 | Adopt one consolidated GitHub update per five chat-driven substantive development changes in each BCI repository. | User's release workflow; apply prospectively rather than reclassifying historical commits |

## Current release/CI decision

**Latest GitHub head at audit:** \`2b4ab0c6c458e0749c86fe3055b7fe4046b2a4a2\`. The source manifest declares \`4.6.15-IFACEGUI\`, but GitHub has no published release object for it, and [CI run 41245378767](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41245378767) **failed** (85 tests, 2 failures). Do not label this build accepted merely because earlier versions had successful tests.

Failure details recovered from that run:
1. \`test_auto_trace.AutoTrace.test_current_channel_mismatch_rejected\`: observed “Probe cooldown active (60 seconds)” instead of the expected “different channel” diagnostic; test state/cooldown isolation still requires repair.
2. \`test_interface_dropdown.InterfaceDropdownTests.test_gui_has_separate_scope_and_capture_selection\`: a case-sensitive source assertion expected “selected interface is no longer present”; the GUI string differed. Reconcile the assertion/GUI behavior, then rerun CI and manually verify dropdown behavior.

The previous [passing Sentinel run 41245062209](https://github.com/BeaconComputingInitiative/BCISentinel-/actions/runs/41245062209) covers the earlier \`4.6.14-FLEX\` development state, not \`4.6.15-IFACEGUI\`.

### Acceptance and safety gates still open

- Verify universal-interface packet capture with each supported OS link type on the target Kali host; no internet association is required, but an UP interface, permissions and observed packets are necessary for actual packet capture.
- Ensure \`none/idle\` mode keeps metrics/control APIs available while retaining historical data with explicit labels.
- Inspect the installed copy separately from the source checkout before activation; avoid unwanted capture-service recreation and keep user approval for starts/scans.
- Preserve physical 802.11 distinctions: Ethernet/managed Wi-Fi cannot passively enumerate nearby AP beacons as a monitor radio can.
- Fix the two CI failures, validate the SHA-256 release manifest, then explicitly verify UI source switching and preservation of operator connectivity.

## Five-development-update publication rule

After this one-time historical documentation baseline, record five *substantive chat-requested changes*, each with intended behavior, implementation status, review notes, test evidence and known failures. Do not interpret mechanical checksum/docs commits as new chat updates. Group five accepted changes into **one consolidated GitHub publication**, if and only if the combined changes and CI pass. Do not push a broken hardware/control update merely to satisfy the batch count. Any emergency out-of-cycle security publication requires explicit operator authorization.

## Check the integrity of this record

```bash
# BEACON COMPUTING INITIATIVE
# Developer Seal: CJB-DEV-2026
cd "$HOME/BCI/BCISentinel-"
sha256sum -c docs/DEVELOPERS_LOG.md.sha256
sha256sum -c SHA256SUMS
python3 -m unittest discover -s tests -v
```

The audit document is informational; it does not restart capture services, change Wi-Fi modes, or touch BCILock.
