# Partner repos referenced in this demo

This meta-repo orchestrates a narrative across 5 separate per-partner MCP demo repos. Each partner repo is self-contained — it has its own LogSeeder configs, MCP tool KQL files, terminal-demo client, and publish script. This repo just stitches them together with correlating data and a unified runbook.

| Partner | UI repo (public) | Tools | What it contributes to the chain |
|---|---|---|---|
| **Anomali** | https://github.com/MitchellGulledge3/anomali-sentinel-mcp-demo-ui | 6 | Fresh IOCs from ThreatStream — kicks off the chain |
| **Jamf** | https://github.com/MitchellGulledge3/jamf-sentinel-mcp-demo-ui | 9 | Mac endpoint detection + telemetry; finds affected hosts from the IOC |
| **Gigamon** | https://github.com/MitchellGulledge3/gigamon-sentinel-mcp-demo-ui | 8 | Network metadata; confirms C2 + finds lateral SMB movement |
| **BigID** | https://github.com/MitchellGulledge3/bigid-sentinel-mcp-demo-ui | 5 | DSPM catalog; quantifies sensitive-data blast radius |
| **Veeam** | https://github.com/MitchellGulledge3/veeam-sentinel-mcp-demo-ui | 8 | Backup/cyber-recovery; identifies clean restore target |
| **Total** | | **36** | |

> The 6th partner (Rubrik) is a direct Veeam competitor — we don't feature them in the same demo. Rubrik's repo lives at https://github.com/MitchellGulledge3/rubrik-sentinel-mcp-demo-ui and provides 5 tools that fit the same recovery-readiness slot if customers prefer Rubrik.

## Tool inventory per partner

### Anomali (6)
- `ti_fresh_high_conf_iocs`
- `ti_search_indicators`
- `ti_actor_campaigns`
- `ti_indicator_validation`
- `ti_kill_chain_coverage`
- `ti_source_quality`

### Jamf (9)
- `Jamf_Daily_Triage_Queue` ← starts the SOC day
- `Jamf_Host_Investigation`
- `Jamf_IOC_Sweep` ← **used in this demo**
- `Jamf_Rare_Binary_Hunt`
- `Jamf_USB_Anomaly_Hunt`
- `Jamf_Mac_Endpoint_Risk_Profile`
- `Jamf_Process_Lineage`
- `Jamf_MITRE_ATTACK_Coverage`
- `Jamf_Alert_Tuning_Candidates`

### Gigamon (8)
- Flow summary, DNS / SMB / TLS hunts, JA3 anomaly detection, etc. (see Gigamon repo)

### BigID (5)
- Sensitive-asset lookup, classification queries, permission-sprawl, owner mapping, exposure scoring

### Veeam (8)
- Malware events, Coveware findings, security-compliance posture, auth events, sessions, alarms

## What this meta-repo adds on top

- **The narrative** that threads them together (`docs/agent-script.md`)
- **The diagram** that makes the value visible (`docs/flow-diagram.md`)
- **The seed data** that makes the chain *actually correlate* across vendor tables (`seed/seed-narrative.py`)
- **The cross-vendor KQL** that proves the joins really work (`kql/06-cross-partner-correlation.kql`)
- **The demo runbook** for live walkthroughs (`docs/demo-runbook.md`)
