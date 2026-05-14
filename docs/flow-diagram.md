# Flow diagram — agentic SOC chain across 5 Sentinel ISV partners

This is the visual story behind the demo. One analyst prompt fires off a chain of MCP tool calls that walks across all 5 partners, each one feeding the next with concrete evidence (IOC values, hostnames, IPs, asset paths, restore-point IDs).

## High-level flow

```mermaid
flowchart LR
    USR(["👤 Analyst<br/><i>'What's the worst<br/>thing happening?'</i>"])
    AGT(("🤖<br/>Agent"))

    subgraph ANO ["🟣 ANOMALI · Threat Intel"]
        A1["fa:fa-bullhorn<br/>Fresh IOCs<br/><b>TeamID DEADBEEF99</b><br/><b>SHA yeg88tzva7avny</b>"]
    end

    subgraph JMF ["🔵 JAMF · Mac Endpoint"]
        J1["fa:fa-laptop<br/>Affected Macs<br/><b>jdoe-mbp</b> + 8 others<br/>scp / ssh / nc Prevented"]
    end

    subgraph GIG ["🟠 GIGAMON · Network"]
        G1["fa:fa-network-wired<br/>Suspicious traffic<br/><b>update-mac-helper.com</b><br/>JA3 e7d705a3...<br/>SMB → fin-files-01"]
    end

    subgraph BIG ["🟢 BIGID · Data Posture"]
        B1["fa:fa-folder-open<br/>Blast radius<br/><b>Q4 Earnings (MNPI)</b><br/>12 482 records · PII · SOX<br/>Owner: Jane Smith"]
    end

    subgraph VEE ["🔴 VEEAM · Backup"]
        V1["fa:fa-database<br/>Recovery path<br/>Infected: rp-...T19-15<br/><b>Clean: rp-...T06-00</b><br/>(immutable)"]
    end

    REC["✅<br/><b>Agent recommends</b><br/>1. Isolate jdoe-mbp via Jamf<br/>2. Block IOC in Anomali<br/>3. Restore fin-files-01<br/>&nbsp;&nbsp;&nbsp;from rp-...T06-00<br/>4. Notify Jane Smith / Finance<br/>5. SOX-relevant disclosure prep"]

    USR --> AGT
    AGT -->|"Phase 1<br/>list fresh IOCs"| A1
    A1 -->|"DEADBEEF99 + SHA"| AGT
    AGT -->|"Phase 2<br/>pivot IOC → Mac"| J1
    J1 -->|"jdoe-mbp · 10.42.7.31"| AGT
    AGT -->|"Phase 3<br/>where did this Mac talk?"| G1
    G1 -->|"C2 IP + file server IP"| AGT
    AGT -->|"Phase 4<br/>what's on that server?"| B1
    B1 -->|"MNPI + 12 482 PII records"| AGT
    AGT -->|"Phase 5<br/>do we have a clean snapshot?"| V1
    V1 -->|"rp-fin-files-01-T06-00 (clean)"| AGT
    AGT --> REC

    classDef ano fill:#7c3aed,stroke:#5b21b6,color:#fff
    classDef jmf fill:#2563eb,stroke:#1e40af,color:#fff
    classDef gig fill:#ea580c,stroke:#9a3412,color:#fff
    classDef big fill:#16a34a,stroke:#14532d,color:#fff
    classDef vee fill:#dc2626,stroke:#7f1d1d,color:#fff
    classDef agent fill:#0f172a,stroke:#1e293b,color:#fff,font-weight:bold
    classDef rec fill:#fef9c3,stroke:#854d0e,color:#422006,font-weight:bold

    class A1 ano
    class J1 jmf
    class G1 gig
    class B1 big
    class V1 vee
    class AGT,USR agent
    class REC rec
```

## Tool-call sequence

```mermaid
sequenceDiagram
    autonumber
    participant U as Analyst
    participant A as Sentinel MCP Agent
    participant TI as Anomali MCP
    participant J as Jamf MCP
    participant G as Gigamon MCP
    participant B as BigID MCP
    participant V as Veeam MCP

    U->>A: "What's the worst thing happening right now?"

    A->>TI: ti_fresh_high_conf_iocs(hours=24)
    TI-->>A: [DEADBEEF99 (TeamID, conf 95),<br/>yeg88tzva7avny (SHA, conf 92)]

    A->>J: Jamf_IOC_Sweep(indicator="DEADBEEF99")
    J-->>A: 82 alerts across 9 Macs<br/>worst: jdoe-mbp (scp prevented, signed by DEADBEEF99)

    A->>J: Jamf_Host_Investigation(host="jdoe-mbp")
    J-->>A: 43 alerts · 14 high · 5 TeamIDs · IP 10.42.7.31

    A->>G: gigamon_host_network_trail(ip="10.42.7.31")
    G-->>A: DNS→update-mac-helper.com · TLS→185.220.101.42<br/>(JA3 e7d705a3...) · SMB→10.42.10.50 (6.8 MB read)

    A->>B: bigid_assets_for_device(ip="10.42.10.50")
    B-->>A: Q4-2025-Earnings-PRE-RELEASE.xlsx · MNPI<br/>12 482 PII records · owner: Jane Smith

    A->>V: veeam_machine_recovery_path(machine="fin-files-01")
    V-->>A: Infected: rp-...T19-15 · Clean: rp-...T06-00<br/>(immutable, 13h old)

    A-->>U: "Mac jdoe-mbp is exfiltrating Q4 earnings (MNPI)<br/>to update-mac-helper.com. Isolate via Jamf,<br/>restore fin-files-01 from rp-...T06-00,<br/>block IOC DEADBEEF99 in Anomali."
```

## Why this is a good demo (for engineers)

- **One prompt, six vendors, zero tool-switching by the human.** This is the MCP value prop made visible.
- **Real data correlation, not hand-waving.** Same IP/hostname/IOC literally appears in 5 different Sentinel tables — the joins are real KQL, not narrative-only.
- **Reason codes propagate.** Each tool returns a `WhyFlagged` / `RiskHints` / `FlowReason` / `ExposureReason` / `RecoveryReason` array that the next tool (and the LLM) can quote verbatim without re-deriving the logic.
- **It's the Microsoft Security pitch via partner tools** — protect (Jamf), detect (Anomali/Jamf), respond (Gigamon/BigID), recover (Veeam) — all through MCP, not Microsoft slides.
