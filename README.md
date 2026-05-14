# Sentinel MCP — Agentic SOC End-to-End Demo

> **One analyst prompt. Six vendors. Zero tool-switching. Real KQL joins across all five partners.**
>
> This is the demo we want to show as the "what's actually possible" milestone for Sentinel MCP — and the pattern we want to publish as the next blog post.

## TL;DR

A single agent prompt — *"What's the worst thing happening in my environment right now and what should I do about it?"* — kicks off a 5-phase tool chain across five separate ISV MCP collections. Each tool's output feeds the next tool's parameters. The same compromised Mac, IP, IOC, file server, and backup machine literally appear in 5 different Sentinel tables and join end-to-end with real KQL.

```
🟣 Anomali    →   🔵 Jamf        →   🟠 Gigamon     →   🟢 BigID       →   🔴 Veeam
"new IOCs"        "which Macs?"      "what network?"    "what data?"        "what recovery?"
```

See **[docs/flow-diagram.md](docs/flow-diagram.md)** for the full visual.

## The story

| Phase | Partner | What the agent learns |
|---|---|---|
| 1 | **Anomali** | Fresh malicious Apple TeamID `DEADBEEF99` + SHA `yeg88tzva7avny` (confidence 95) |
| 2 | **Jamf** | 82 alerts across 9 Macs; worst is `jdoe-mbp` running `scp` signed by that TeamID (Prevented) |
| 3 | **Gigamon** | Same Mac beaconed to `update-mac-helper.com` (known-bad JA3) and SMB-read 16 MB from `fin-files-01` |
| 4 | **BigID** | `fin-files-01` holds `Q4-2025-Earnings-PRE-RELEASE.xlsx` — 12 482 PII records, MNPI, SOX-relevant |
| 5 | **Veeam** | Clean immutable snapshot `rp-fin-files-01-2026-05-13-T06-00` is 13 hours old — recovery target |

Final agent recommendation: **isolate the Mac, block the IOC fleet-wide, restore from the clean snapshot, notify Finance/Legal — MNPI disclosure may apply.**

See **[docs/agent-script.md](docs/agent-script.md)** for the full walkthrough with real query outputs at every step.

## The "money shot" — one KQL, five vendors

The thing that makes this demo land for engineers: the underlying data really is correlated across vendor tables. A single KQL ([`kql/06-cross-partner-correlation.kql`](kql/06-cross-partner-correlation.kql)) joins all 5 partner tables and returns one row per affected host with columns from every vendor:

```
DvcHostname           = jdoe-mbp.contoso.local
AnomaliIOCs           = [DEADBEEF99, yeg88tzva7avny]   (confidence 95)
JamfAlertCount        = 6   (4 Prevented, 1 High sev)
GigamonFlows          = 6   (C2 + SMB)
JA3                   = e7d705a3286e19ea42f587b344ee6865
SensitiveAssets       = [Q4-2025-Earnings-PRE-RELEASE.xlsx]
BlastRadius_Records   = 12 482
DataOwner             = Jane Smith
Veeam_InfectedSnapshot = rp-fin-files-01-2026-05-13-T19-15
Veeam_CleanSnapshot    = rp-fin-files-01-2026-05-13-T06-00
```

That's 5 vendors of data, one row, real joins. Live output is in [`sample-runs/06-cross-partner-correlation.json`](sample-runs/06-cross-partner-correlation.json).

## Repo structure

```
├── README.md                    ← you are here
├── partners.md                  ← links to all 5 partner UI repos (and Rubrik as alternate)
├── docs/
│   ├── flow-diagram.md          ← Mermaid flowchart + sequence diagram (the visual)
│   ├── agent-script.md          ← full agent narrative with real outputs at every step
│   └── demo-runbook.md          ← Friday eng-leadership demo walkthrough script
├── kql/
│   ├── 01-anomali-fresh-iocs.kql
│   ├── 02-jamf-affected-macs.kql
│   ├── 03-gigamon-mac-network-trail.kql
│   ├── 04-bigid-blast-radius.kql
│   ├── 05-veeam-recovery-target.kql
│   └── 06-cross-partner-correlation.kql  ← the money shot
├── sample-runs/                 ← live JSON output captured against the seeded workspace
└── seed/
    └── seed-narrative.py        ← idempotent script that seeds the correlating data
```

## Running the demo yourself

### Prerequisites
- Azure CLI (`az`) signed in to a tenant with the seeded workspace
- Python 3.8+
- `Monitoring Metrics Publisher` on the partner DCRs (one-time, already granted when the per-partner demos were deployed)

### Setup (60 s)
```bash
git clone <this repo>
cd sentinel-mcp-agentic-soc-demo
python3 seed/seed-narrative.py     # idempotent; safe to re-run before each demo
```

### Run each phase
Open the Sentinel Logs blade against workspace `77429a58-865a-4764-8429-aaacdfe3cb73` and paste each `kql/*.kql` file in order. The last one (`06-cross-partner-correlation.kql`) is the show-stopper.

For the live presenter version, follow [`docs/demo-runbook.md`](docs/demo-runbook.md).

## Why this is the right demo for engineering leadership

- **MCP value prop, made literal.** One prompt → 5 vendor tools chained → recommendation. No human routing.
- **Real correlation, not pitch slides.** Same Mac/IP/IOC/server/snapshot literally appears in 5 Sentinel tables. The joins are real KQL, not narrative-only.
- **Reason codes propagate.** Every tool returns a `WhyFlagged` / `FlowReason` / `ExposureReason` / `RecoveryReason` array the next tool (and the LLM) can quote verbatim.
- **It's the full Microsoft Security pitch via partner tools** — protect (Jamf), detect (Anomali/Jamf), respond (Gigamon/BigID), recover (Veeam) — all through MCP, not Microsoft slides.
- **Scales to the other 5 partners.** Same pattern applies to Rubrik (recovery), CrowdStrike (endpoint), Cisco, Palo Alto, etc.

## What's next (post-Friday)

1. **Publish all 5 MCP collections to one tenant** so a single agent can call across them. Currently each is a separate collection — works for demo, would be cleaner as a unified "agentic-soc" collection.
2. **Wire an orchestrator** that takes the analyst prompt and auto-routes through the 5 phases (today this is system-prompted into the agent; tomorrow it should be a first-class MCP workflow).
3. **Blog post** with the diagram, the magic KQL, and a video of the chain running live.
4. **Roadshow** — same demo against Rubrik instead of Veeam for Rubrik partner conversations; against Cisco SecureX instead of Gigamon for Cisco partner conversations; etc.

## Credits / source partner repos

| Partner | API repo (private) | UI repo (public) |
|---|---|---|
| Anomali | MitchellGulledge3/anomali-sentinel-mcp-demo | MitchellGulledge3/anomali-sentinel-mcp-demo-ui |
| Jamf | MitchellGulledge3/jamf-sentinel-mcp-demo | MitchellGulledge3/jamf-sentinel-mcp-demo-ui |
| Gigamon | MitchellGulledge3/gigamon-sentinel-mcp-demo | MitchellGulledge3/gigamon-sentinel-mcp-demo-ui |
| BigID | MitchellGulledge3/bigid-sentinel-mcp-demo | MitchellGulledge3/bigid-sentinel-mcp-demo-ui |
| Veeam | MitchellGulledge3/veeam-sentinel-mcp-demo | MitchellGulledge3/veeam-sentinel-mcp-demo-ui |

See [`partners.md`](partners.md) for tool inventories per partner.
