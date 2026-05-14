# Demo runbook — Friday eng-leadership session

Twelve-minute walkthrough. The point is to **show**, not pitch.

## Pre-flight (5 min before)

- [ ] `az login` is fresh; subscription set to `e74cc169-...-2b501de96692`
- [ ] Re-run `python3 seed/seed-narrative.py` (idempotent — refreshes the timeline so timestamps look "today")
- [ ] Open Sentinel portal → workspace `77429a58-...-aaacdfe3cb73` → Logs blade
- [ ] Have `docs/flow-diagram.md` rendered (GitHub preview works) on a second screen
- [ ] Have this file open in VS Code so you can copy KQL into Logs blade

## The session (12 min)

### 1. Set the stage (90 s)

> "MCP changes what a SOC analyst can ask Sentinel. They no longer have to know which table to query — they just describe what they want, and an agent figures it out. We've been building MCP tool collections per ISV partner — Anomali, Jamf, Gigamon, BigID, Veeam. **Today I want to show what happens when you let an agent chain across all of them with one prompt.**"

Show the high-level diagram from `docs/flow-diagram.md`.

### 2. The prompt (30 s)

> "Imagine the analyst types this:" *(read the prompt)*
>
> **`What's the worst thing happening in my environment right now, and what should I do about it?`**
>
> "Watch what the agent decides to do."

### 3. Phase 1 — Anomali (60 s)

Run `kql/01-anomali-fresh-iocs.kql` in Sentinel Logs.

> "First thing the agent does is ask Anomali for fresh, high-confidence IOCs. Two come back: an Apple Developer TeamID and a SHA256, both confidence 90+. The agent picks the TeamID because it's the broader pivot."

### 4. Phase 2 — Jamf (90 s)

Run `kql/02-jamf-affected-macs.kql`.

> "82 alerts across 9 Macs. The worst row is `jdoe-mbp` running **`scp`** signed under that TeamID — Jamf Protect prevented it. **`scp` is a data-exfil tool.** That's our suspect host. The agent grabs the Mac's IP from the host investigation tool."

### 5. Phase 3 — Gigamon (90 s)

Run `kql/03-gigamon-mac-network-trail.kql`.

> "Pivot on the Mac's IP. Three destinations: a DNS lookup of `update-mac-helper.com`, a TLS beacon to an external IP with a JA3 fingerprint we recognize as malicious, and SMB bulk-reads from an internal file server. Note the `FlowReason` array — the agent can quote `known-malicious-ja3` verbatim without re-deriving the logic."

### 6. Phase 4 — BigID (90 s)

Run `kql/04-bigid-blast-radius.kql`.

> "Now the agent asks BigID: what's on `10.42.10.50`? The answer is **`Q4-2025-Earnings-PRE-RELEASE.xlsx` — 12,482 PII records, marked MNPI, SOX-relevant, owner Jane Smith in Finance**. The blast radius is concrete. This is what differentiates a SOC tool from a SOAR runbook — the agent quantifies impact with real data classification."

### 7. Phase 5 — Veeam (60 s)

Run `kql/05-veeam-recovery-target.kql`.

> "Last question: do we have a clean snapshot? Two rows come back — one infected `rp-...T19-15`, one clean `rp-...T06-00`. The clean one is immutable, 13 hours old. **That's the recovery target.**"

### 8. The money shot (2 min) — DO THIS LAST

Run `kql/06-cross-partner-correlation.kql`.

> "Here's the part I think is the actual win. **This is a single KQL that joins all 5 partner tables in one query.** Same Mac, same IOC, same network destination, same file server, same backup machine — they really are correlated end-to-end in Log Analytics. The agent isn't doing magic — it's just walking the joins. Which means we can build agents that do this reliably."

Scroll through the joined row for `jdoe-mbp` — call out columns from each vendor.

### 9. Close (60 s)

> "What we've built: MCP tools per ISV that **all return reason codes** an agent can quote, that **all reference the same entities** (host, IP, hash, machine, asset) so they can chain. We have this working for 6 partners today, 41 tools total. The next step is **publishing them as one connected MCP collection** so any Sentinel-aware agent (Defender, Security Copilot, custom) can run this exact chain. **This is what I want to write as the next blog post.**"

## If something goes wrong

| Symptom | Fast fix |
|---|---|
| Phase 1 returns 0 rows | TI indexing lag — re-run, or fall back to showing the sample-runs JSON in the repo |
| Phase 2 returns 0 rows | `az login` token expired — `az account get-access-token` to refresh; re-run query |
| Cross-partner query is slow | Acknowledge: "this is a 5-table join, 1713 + 400 + 500 + 500 rows. Production version would materialize this." |
| Audience asks "is the data real?" | "Seeded for the demo — but the schemas, DCRs, and joins are exactly what production looks like. See `seed/seed-narrative.py`." |

## What to leave them with

- Repo link (private, shared via GitHub)
- The flow diagram
- Comment that 5 of the 6 partner repos are public and they can browse them
- Pitch: this is the blog post we'll publish next
