# Agent narrative — full walkthrough with real outputs

This is what a single analyst prompt actually looks like end-to-end. Every output below is captured live from the seeded demo workspace (see `sample-runs/`).

> **Analyst prompt:**
> *"What's the worst thing happening in my environment right now, and what should I do about it?"*

The agent makes 5 MCP tool calls in sequence. Each output feeds the next call's parameters.

---

## Phase 1 — Anomali: fresh, high-confidence IOCs

**Tool call:** `ti_fresh_high_conf_iocs(hours=24, min_confidence=85)`

```kql
-- kql/01-anomali-fresh-iocs.kql
ThreatIntelIndicators
| where SourceSystem == "Anomali ThreatStream"
| where ObservableValue in ("DEADBEEF99", "yeg88tzva7avny")
```

| ObservableKey | ObservableValue | Confidence | IndicatorName |
|---|---|---|---|
| x-jamf-team-id | `DEADBEEF99` | 95 | Anomali ThreatStream — malicious Apple TeamID DEADBEEF99 |
| file:hashes.'SHA-256' | `yeg88tzva7avny` | 92 | Anomali ThreatStream — malicious macOS scp wrapper (SHA256) |

**Agent decides:** *"Two fresh high-confidence IOCs. The TeamID is the broader pivot — let me check Jamf first."*

---

## Phase 2 — Jamf: which Macs ran something signed by this TeamID?

**Tool call:** `Jamf_IOC_Sweep(indicator="DEADBEEF99")`

```kql
-- kql/02-jamf-affected-macs.kql
JamfProtectAlertsDemo_CL
| join (Anomali IOC list) on TargetBinarySigningTeamID == ObservableValue
       or TargetProcessSHA256 == ObservableValue
```

**82 alerts across 9 Macs.** The most concerning row:

| Host | Process | Sig | Result | WhyFlagged |
|---|---|---|---|---|
| **`jdoe-mbp.contoso.local`** | **`scp`** | App Store (TeamID `DEADBEEF99`) | Prevented | `[high-severity, exec-prevented, exfil-capable-tool]` |

**Agent decides:** *"`scp` is a data-exfil tool. Jamf prevented this execution but the TeamID has signed other binaries on this Mac — I need the full host picture and the Mac's IP for network pivot."*

**Tool call:** `Jamf_Host_Investigation(host="jdoe-mbp.contoso.local")`

> 43 total alerts · 14 High severity · 13 ad-hoc execs · 5 distinct TeamIDs · IP `10.42.7.31`

---

## Phase 3 — Gigamon: where did this Mac talk to on the network?

**Tool call:** `gigamon_host_network_trail(ip="10.42.7.31", hours=2)`

```kql
-- kql/03-gigamon-mac-network-trail.kql
GigamonCcfMcpDemo_CL
| where src_ip == "10.42.7.31"
| summarize by dst_ip, dst_port, protocol
```

| dst | port | app | FlowReason |
|---|---|---|---|
| `185.220.101.42` | 443 | TLS | `[known-malicious-ja3, outbound-tls-to-external, large-upload]` |
| `10.42.10.50` | 445 | SMB | `[smb-bulk-read]` |
| `10.42.0.10` | 53 | DNS | `[c2-dns-lookup]` (queried `update-mac-helper.com`) |

**Agent decides:** *"This Mac beaconed to a known-malicious JA3 fingerprint on an external IP **and** bulk-read from an internal file server. The file server is at `10.42.10.50` — what's actually on it?"*

---

## Phase 4 — BigID: how bad is the blast radius?

**Tool call:** `bigid_assets_for_device(ip="10.42.10.50")`

```kql
-- kql/04-bigid-blast-radius.kql
BigIDDSPMAssetStoreDemo_CL
| where IPAddress == "10.42.10.50"
```

| AssetName | Classification | Sensitivity | Records | Owner | ExposureReason |
|---|---|---|---|---|---|
| `Q4-2025-Earnings-PRE-RELEASE.xlsx` | PII / Financial / Confidential | Highly Confidential | 12,482 | Jane Smith (Finance) | `[highly-confidential, material-non-public-info, contains-ssn, contains-bank-accounts]` |

**Agent decides:** *"This is **MNPI** — material non-public information. Earnings pre-release. SOX-relevant. The exfil attempt was material. Recovery readiness is now critical — what does Veeam say?"*

---

## Phase 5 — Veeam: can we recover from a clean point?

**Tool call:** `veeam_machine_recovery_path(machine="fin-files-01")`

```kql
-- kql/05-veeam-recovery-target.kql
VeeamMalwareEventsDemo_CL
| where MachineDisplayName == "fin-files-01"
```

| RestorePointId | Status | Malware | AffectedFiles | RecoveryReason |
|---|---|---|---|---|
| `rp-fin-files-01-2026-05-13-T19-15` | **Infected** | macOS.ExfilStealer.A | 47 (incl. earnings + board materials) | `[infected-snapshot, high-severity, immutable-snapshot, mass-file-impact]` |
| `rp-fin-files-01-2026-05-13-T06-00` | **Clean** | — | 0 | `[clean-restore-target, immutable-snapshot]` |

**Agent decides:** *"There's a clean immutable snapshot from 13 hours ago. That's my recovery target."*

---

## Final synthesis — the agent's recommendation to the analyst

> **`jdoe-mbp.contoso.local` is exfiltrating Q4 earnings pre-release data (MNPI, 12 482 PII records) to `update-mac-helper.com`. The activity ties to a fresh Anomali IOC (Apple TeamID `DEADBEEF99`, confidence 95) signing a malicious `scp` wrapper. Jamf prevented one execution but allowed others. Network shows ~15 MB outbound to the C2 over TLS with a known-malicious JA3, plus 16 MB SMB read from `fin-files-01`. The affected share is SOX-relevant — owner Jane Smith (Finance).**
>
> **Recommended actions:**
> 1. **Isolate** `jdoe-mbp` via Jamf Self Service quarantine.
> 2. **Block** TeamID `DEADBEEF99` and SHA `yeg88tzva7avny` across the Mac fleet (Jamf Protect block-list).
> 3. **Restore** `fin-files-01` from `rp-fin-files-01-2026-05-13-T06-00` (Veeam, immutable, 13 h old, last known clean).
> 4. **Notify** Jane Smith and Finance leadership; loop in Legal — SOX-relevant disclosure considerations.
> 5. **Push** the IOC back into Anomali as confirmed-malicious for downstream tenants.

---

## The "magic" query — one KQL, all five partners

For the engineering-leadership audience: the punchline isn't just that the agent can call 5 tools in sequence — it's that **the underlying data really is correlated end-to-end across vendors**. This single KQL joins all 5 partner tables in one round trip:

```kql
-- kql/06-cross-partner-correlation.kql
let anomali_iocs   = ThreatIntelIndicators | where SourceSystem == "Anomali ThreatStream" ...;
let jamf_hits      = JamfProtectAlertsDemo_CL | where TargetBinarySigningTeamID == "DEADBEEF99" ...;
let gigamon_trail  = GigamonCcfMcpDemo_CL    | where src_ip == "10.42.7.31" ...;
let bigid_exposure = BigIDDSPMAssetStoreDemo_CL | where IPAddress == "10.42.10.50" ...;
let veeam_recovery = VeeamMalwareEventsDemo_CL | where MachineDisplayName == "fin-files-01" ...;
jamf_hits
| join gigamon_trail on $left.MacIp == $right.src_ip
| join bigid_exposure on $left.FileServerIp == $right.IPAddress
| join veeam_recovery on $left.Machine == $right.MachineDisplayName
| extend AnomaliIOCs = toscalar(anomali_iocs | project IocValues)
```

**Live output for `jdoe-mbp.contoso.local`** (see `sample-runs/06-cross-partner-correlation.json`):

| Column | Value |
|---|---|
| DvcHostname | `jdoe-mbp.contoso.local` |
| AnomaliIOCs | `["DEADBEEF99", "yeg88tzva7avny"]` (confidence 95) |
| JamfAlertCount / Prevented / HighSev | 6 / 4 / 1 |
| Processes | `[scp, ruby, ssh, osascript, zsh, sh]` |
| Gigamon C2 DNS | `update-mac-helper.com` |
| Gigamon External Dsts | `[185.220.101.42, 10.42.10.50, 10.42.0.10]` |
| JA3 | `e7d705a3286e19ea42f587b344ee6865` |
| Sensitive Assets | `Q4-2025-Earnings-PRE-RELEASE.xlsx` |
| Sensitivity | Highly Confidential |
| Blast Radius (records) | 12,482 |
| Data Owner | Jane Smith |
| Veeam Infected RP | `rp-fin-files-01-2026-05-13-T19-15` |
| **Veeam Clean RP** | **`rp-fin-files-01-2026-05-13-T06-00`** |
| Veeam Malware | macOS.ExfilStealer.A (Anomali-classified) |

That's five vendors of data, one row, real joins.
