"""Seed correlating rows across 5 Sentinel tables so the agentic-SOC chain
demo has end-to-end data continuity.

Storyline: a compromised Mac (`jdoe-mbp.contoso.local`, IP `10.42.7.31`) runs a
binary signed under Apple TeamID `DEADBEEF99` with SHA `yeg88tzva7avny`. Anomali
ThreatStream already flagged that TeamID + SHA as malicious. The Mac beacons to
a C2, then pivots over SMB to a finance file server (`fin-files-01`,
`10.42.10.50`). BigID has that share catalogued as PII/Financial. Veeam detects
malware on that server's backups and identifies the last clean restore point.

What this script writes (idempotent — safe to re-run):

  1. ThreatIntelIndicators   <-  2 STIX indicators (TeamID + SHA)            via TI Upload API
  2. JamfProtectAlertsDemo_CL <- (already has the anchor alert — skipped)
  3. GigamonCcfMcpDemo_CL    <-  6 flow rows (Mac->C2 TLS, DNS, Mac->SMB)   via Logs Ingestion API
  4. BigIDDSPMAssetStoreDemo_CL <- 1 asset (Q4 earnings on fin-files-01)    via Logs Ingestion API
  5. VeeamMalwareEventsDemo_CL <- 2 malware events (dirty + clean restore)  via Logs Ingestion API

Auth: uses Azure CLI's signed-in identity (DefaultAzureCredential). The same
identity must hold `Monitoring Metrics Publisher` on each DCR (already granted
when the partner demos were originally deployed).
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
import urllib.error
import urllib.request
import uuid


# ----- Storyline constants (the *single source of truth* for the demo chain) -----
MAC_HOST           = "jdoe-mbp.contoso.local"
MAC_IP             = "10.42.7.31"
MAC_USER           = "jdoe"
BAD_TEAM_ID        = "DEADBEEF99"
BAD_SHA256         = "yeg88tzva7avny"
C2_IP              = "185.220.101.42"
C2_DOMAIN          = "update-mac-helper.com"
FILE_SERVER_HOST   = "fin-files-01.contoso.local"
FILE_SERVER_IP     = "10.42.10.50"
FILE_SHARE_PATH    = "\\\\fin-files-01\\finance\\Q4-2025-earnings\\"
SENSITIVE_FILENAME = "Q4-2025-Earnings-PRE-RELEASE.xlsx"

# ----- Azure resource config (specific to this demo workspace) -----
SUBSCRIPTION_ID    = "e74cc169-760f-464c-8a00-2b501de96692"
WORKSPACE_ID       = "77429a58-865a-4764-8429-aaacdfe3cb73"
DCE_ENDPOINT       = "https://sample-data-dce-bori.westus2-1.ingest.monitor.azure.com"

DCRS = {
    "gigamon": {
        "rule_id": "dcr-9e2ea1c8c81347aba38a402899a94799",
        "stream":  "Custom-GigamonCcfMcpDemo",
    },
    "bigid": {
        "rule_id": "dcr-71f20067cf6e4d93af9e42af73308747",
        "stream":  "Custom-BigIDDSPMAssetStoreDemo",
    },
    "veeam_malware": {
        "rule_id": "dcr-ca8801f2372746fa99d67d89301f046e",
        "stream":  "Custom-VeeamMalwareEventsDemo",
    },
}

TI_API_VERSION = "2024-02-01-preview"
TI_UPLOAD_HOST = "https://api.ti.sentinel.azure.com"
TI_SOURCE      = "Anomali ThreatStream"

ARM_RESOURCE   = "https://management.azure.com"
INGEST_RESOURCE = "https://monitor.azure.com"


def now_z(offset_min: int = 0) -> str:
    """Return UTC ISO-8601 with millisecond precision, optionally offset by `offset_min`."""
    ts = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=offset_min)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def az_token(resource: str) -> str:
    completed = subprocess.run(
        ["az", "account", "get-access-token", "--resource", resource,
         "--query", "accessToken", "-o", "tsv"],
        check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def post_json(url: str, token: str, payload, *, label: str) -> None:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            n = (len(payload) if isinstance(payload, list)
                 else len(payload.get("stixobjects", [])) if isinstance(payload, dict) and "stixobjects" in payload
                 else 1)
            print(f"  ✓ {label}: HTTP {resp.status} ({n} row(s))")
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{label} failed: HTTP {e.code}: {body_text}") from e


def ingest(table_key: str, rows: list) -> None:
    cfg = DCRS[table_key]
    url = f"{DCE_ENDPOINT}/dataCollectionRules/{cfg['rule_id']}/streams/{cfg['stream']}?api-version=2023-01-01"
    token = az_token(INGEST_RESOURCE)
    post_json(url, token, rows, label=f"Logs Ingestion → {cfg['stream']}")


# ====================== Anomali TI ======================
def seed_anomali_ti() -> None:
    print("\n[1/4] Anomali ThreatStream — uploading 2 IOCs via TI Upload API...")
    indicators = [
        {
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now_z(-180), "modified": now_z(-180),
            "name": f"Anomali ThreatStream — malicious Apple TeamID {BAD_TEAM_ID}",
            "description": (
                "Apple Developer TeamID observed signing macOS payloads in a recent "
                "infostealer / data-exfil campaign targeting financial services. "
                "Anomali confidence high; pivoting on this TeamID in Sentinel reveals "
                "Mac endpoints where Jamf Protect already prevented or allowed signed "
                "binaries from this developer identity."),
            "pattern": f"[x-jamf-team-id:value = '{BAD_TEAM_ID}']",
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "valid_from": now_z(-180),
            "valid_until": now_z(60 * 24 * 30),
            "labels": ["anomalithreatstream", "apt", "data-exfil", "macos", "high"],
            "confidence": 95,
            "kill_chain_phases": [{"kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "delivery"}],
            "external_references": [{
                "source_name": TI_SOURCE,
                "external_id": "anomali-ts-2026-05-13-001",
                "url": "https://ui.threatstream.com/detail/indicator/anomali-ts-2026-05-13-001",
            }],
        },
        {
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now_z(-180), "modified": now_z(-180),
            "name": "Anomali ThreatStream — malicious macOS scp wrapper (SHA256)",
            "description": (
                "macOS scp wrapper signed under the malicious Apple TeamID. Observed "
                "exfiltrating sensitive files from compromised Mac endpoints to attacker "
                "infrastructure. Pivot this SHA against Jamf Protect alerts to find "
                "affected Macs."),
            "pattern": f"[file:hashes.'SHA-256' = '{BAD_SHA256}']",
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "valid_from": now_z(-180),
            "valid_until": now_z(60 * 24 * 30),
            "labels": ["anomalithreatstream", "malware", "data-exfil", "macos", "high"],
            "confidence": 92,
            "kill_chain_phases": [{"kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "actions-on-objectives"}],
            "external_references": [{
                "source_name": TI_SOURCE,
                "external_id": "anomali-ts-2026-05-13-002",
                "url": "https://ui.threatstream.com/detail/indicator/anomali-ts-2026-05-13-002",
            }],
        },
    ]
    token = az_token(ARM_RESOURCE)
    url = (f"{TI_UPLOAD_HOST}/workspaces/{WORKSPACE_ID}"
           f"/threat-intelligence-stix-objects:upload?api-version={TI_API_VERSION}")
    post_json(url, token, {"sourcesystem": TI_SOURCE, "stixobjects": indicators},
              label="TI Upload API")


# ====================== Gigamon flows ======================
def seed_gigamon_flows() -> None:
    print("\n[2/4] Gigamon — pushing 6 correlating flow rows to GigamonCcfMcpDemo_CL...")
    base_min = -90
    rows = []
    # 1) DNS lookup of C2 from Mac
    rows.append({
        "TimeGenerated": now_z(base_min),
        "ts": now_z(base_min),
        "src_ip": MAC_IP, "dst_ip": "10.42.0.10",  # internal DNS
        "src_port": 54321, "dst_port": 53,
        "protocol": "UDP", "ip_version": 4,
        "udp_sport": 54321, "udp_dport": 53,
        "dns_query": C2_DOMAIN, "dns_host": C2_DOMAIN,
        "dns_query_type": "A", "dns_reply_code": "NOERROR",
        "dns_host_addr": C2_IP,
        "app_name": "DNS", "app_family": "dns", "app_id": 5,
        "app_tags": "lookup",
        "total_bytes": "142", "total_packets": "2",
        "src_bytes": "71", "dst_bytes": "71",
        "src_packets": "1", "dst_packets": "1",
        "vendor": "Gigamon", "version": "6.5",
    })
    # 2-3) TLS beacons Mac -> C2 (suspicious JA3)
    for i, (off, bytes_out, ja3) in enumerate([
        (base_min + 5,  4_582,    "e7d705a3286e19ea42f587b344ee6865"),
        (base_min + 35, 12_184,   "e7d705a3286e19ea42f587b344ee6865"),
    ]):
        rows.append({
            "TimeGenerated": now_z(off), "ts": now_z(off),
            "src_ip": MAC_IP, "dst_ip": C2_IP,
            "src_port": 49_180 + i, "dst_port": 443,
            "tcp_sport": 49_180 + i, "tcp_dport": 443,
            "protocol": "TCP", "ip_version": 4,
            "app_name": "TLS", "app_family": "web", "app_id": 443,
            "app_tags": "encrypted,suspicious-ja3",
            "ssl_common_name": C2_DOMAIN,
            "ssl_fingerprint_ja3": ja3,
            "ssl_protocol_version": "TLS 1.2",
            "ssl_issuer": "CN=Let's Encrypt Authority X3",
            "ssl_certificate_subject_cn": C2_DOMAIN,
            "ssl_certificate_dn_issuer": "CN=Let's Encrypt Authority X3",
            "total_bytes": str(bytes_out), "total_packets": "28",
            "src_bytes": str(int(bytes_out * 0.85)), "dst_bytes": str(int(bytes_out * 0.15)),
            "src_packets": "18", "dst_packets": "10",
            "vendor": "Gigamon", "version": "6.5",
        })
    # 4-5) SMB Mac -> file server (bulk read)
    for i, (off, bytes_) in enumerate([
        (base_min + 50, 6_842_910),  # 6.8 MB
        (base_min + 65, 9_184_220),  # 9.1 MB
    ]):
        rows.append({
            "TimeGenerated": now_z(off), "ts": now_z(off),
            "src_ip": MAC_IP, "dst_ip": FILE_SERVER_IP,
            "src_port": 50_120 + i, "dst_port": 445,
            "tcp_sport": 50_120 + i, "tcp_dport": 445,
            "protocol": "TCP", "ip_version": 4,
            "app_name": "SMB", "app_family": "fileshare", "app_id": 445,
            "app_tags": "internal,bulk-read",
            "smb_version": "3.1.1",
            "total_bytes": str(bytes_), "total_packets": str(5_120 + i * 100),
            "src_bytes": str(int(bytes_ * 0.05)), "dst_bytes": str(int(bytes_ * 0.95)),
            "src_packets": "800", "dst_packets": str(4_320 + i * 100),
            "vendor": "Gigamon", "version": "6.5",
        })
    # 6) Second TLS beacon to C2 with payload
    rows.append({
        "TimeGenerated": now_z(base_min + 80), "ts": now_z(base_min + 80),
        "src_ip": MAC_IP, "dst_ip": C2_IP,
        "src_port": 49_222, "dst_port": 443,
        "tcp_sport": 49_222, "tcp_dport": 443,
        "protocol": "TCP", "ip_version": 4,
        "app_name": "TLS", "app_family": "web", "app_id": 443,
        "app_tags": "encrypted,suspicious-ja3,large-upload",
        "ssl_common_name": C2_DOMAIN,
        "ssl_fingerprint_ja3": "e7d705a3286e19ea42f587b344ee6865",
        "ssl_protocol_version": "TLS 1.2",
        "ssl_issuer": "CN=Let's Encrypt Authority X3",
        "ssl_certificate_subject_cn": C2_DOMAIN,
        "ssl_certificate_dn_issuer": "CN=Let's Encrypt Authority X3",
        "total_bytes": "15204882", "total_packets": "10120",
        "src_bytes": "15180120", "dst_bytes": "24762",
        "src_packets": "10050", "dst_packets": "70",
        "vendor": "Gigamon", "version": "6.5",
    })
    ingest("gigamon", rows)


# ====================== BigID asset ======================
def seed_bigid_asset() -> None:
    print("\n[3/4] BigID — pushing 1 sensitive-asset row to BigIDDSPMAssetStoreDemo_CL...")
    rows = [{
        "TimeGenerated": now_z(-120),
        "IngestionTime": now_z(-120),
        "AssetID": "asset-fin-files-01-q4earnings-001",
        "CreatedDateTime": now_z(-60 * 24 * 30),
        "LastModifiedDateTime": now_z(-30),
        "LastAccessDateTime": now_z(-15),
        "ClassificationLastScanDateTime": now_z(-60 * 24),
        "AssetName": SENSITIVE_FILENAME,
        "AssetType": "File",
        "AssetPath": FILE_SHARE_PATH + SENSITIVE_FILENAME,
        "AssetSize": 4_182_220,
        "AssetSource": "BigID DSPM scanner — SMB",
        "AssetOwner": {
            "AccountUpn": "jsmith@contoso.com",
            "DisplayName": "Jane Smith",
            "Department": "Finance",
        },
        "AssetPermissions": {
            "Read":        ["Finance-Group@contoso.com", "Exec-Leadership@contoso.com"],
            "Write":       ["jsmith@contoso.com"],
            "FullControl": ["finance-admins@contoso.com"],
        },
        "Classification": "PII / Financial / Confidential",
        "SensitivityLabel": "Highly Confidential",
        "DeviceName": "fin-files-01",
        "DomainName": "contoso.local",
        "IPAddress": FILE_SERVER_IP,
        "Provider": "BigID",
        "Workload": "FileShare",
        "SubWorkload": "SMB",
        "Region": "westus2",
        "Location": "On-prem datacenter",
        "Extension": "xlsx",
        "MD5":    "5ec1d3a9ae3a6c1842e7c08f9b9ed4a1",
        "SHA1":   "d22f1f3e7c9aa6d1f0b8e2a4d6e8f0a2c4e6f8a0",
        "SHA256": "fb18d2a3c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        "URL": f"smb://{FILE_SERVER_HOST}/finance/Q4-2025-earnings/{SENSITIVE_FILENAME}",
        "FeedType": "BigID DSPM Asset Inventory",
        "ExternalUserWithPermissionCount": 0,
        "InternalUserWithPermissionCount": 47,
        "ThreatDetected": False,
        "ThreatCategory": "",
        "ThreatName": "",
        "IsAssetRemoved": False,
        "IsProtectedByDlp": True,
        "SignatureStatus": "Signed",
        "Risks": ["high-sensitivity", "bulk-pii", "executive-board-material",
                   "pre-release-financials", "smb-share"],
        "RelatedIndicators": [BAD_SHA256, BAD_TEAM_ID, C2_DOMAIN],
        "AdditionalFields": {
            "BigIDScanID": "scan-2026-q2-fin-001",
            "BigIDPolicies": ["PII", "Financial", "SOX", "MNPI"],
            "BigIDConfidence": 0.98,
            "RecordCount": 12_482,
            "ContainsSSN": True,
            "ContainsBankAccounts": True,
            "MNPIFlag": True,
            "Note": ("Pre-release Q4 earnings workbook. SOX-relevant. "
                     "Material non-public information."),
        },
    }]
    ingest("bigid", rows)


# ====================== Veeam malware event ======================
def seed_veeam_malware() -> None:
    print("\n[4/4] Veeam — pushing 2 malware-event rows to VeeamMalwareEventsDemo_CL...")
    rows = [
        {
            # Dirty restore point — malware detected
            "TimeGenerated": now_z(-30),
            "MachineDisplayName": "fin-files-01",
            "MachineUuid": "b7e8f0a2-c4d6-4e8f-a0b1-c2d3e4f5a6b7",
            "MachineBackupObjectId": "vbr-fin-files-01-2026-05-13-T18-00",
            "VbrHostName": "vbr-westus2.contoso.local",
            "BackupRepository": "westus2-immutable-repo-01",
            "JobName": "Finance-FileServer-Daily",
            "RestorePointId": "rp-fin-files-01-2026-05-13-T19-15",
            "RestorePointCreationTime": now_z(-90),
            "EventType": "MalwareDetected",
            "Severity": "High",
            "Status": "Infected",
            "MalwareName": "macOS.ExfilStealer.A (Anomali-classified)",
            "DetectionMethod": "Inline scan + YARA + ML anomaly",
            "AffectedFileCount": 47,
            "AffectedFiles": [
                FILE_SHARE_PATH + SENSITIVE_FILENAME,
                FILE_SHARE_PATH + "Board-Materials-Draft.pptx",
                FILE_SHARE_PATH + "Earnings-Press-Release.docx",
            ],
            "OriginatingProcess": f"scp ({MAC_HOST})",
            "ImmutabilityState": "ImmutableUntil2026-08-13",
            "MarkedClean": False,
            "Analyst": "(unassigned)",
        },
        {
            # Last clean restore point — recovery target
            "TimeGenerated": now_z(-25),
            "MachineDisplayName": "fin-files-01",
            "MachineUuid": "b7e8f0a2-c4d6-4e8f-a0b1-c2d3e4f5a6b7",
            "MachineBackupObjectId": "vbr-fin-files-01-2026-05-13-T06-00",
            "VbrHostName": "vbr-westus2.contoso.local",
            "BackupRepository": "westus2-immutable-repo-01",
            "JobName": "Finance-FileServer-Daily",
            "RestorePointId": "rp-fin-files-01-2026-05-13-T06-00",
            "RestorePointCreationTime": now_z(-13 * 60),  # 13h ago
            "EventType": "CleanRestorePointIdentified",
            "Severity": "Informational",
            "Status": "Clean",
            "MalwareName": "",
            "DetectionMethod": "Inline scan + YARA + ML anomaly",
            "AffectedFileCount": 0,
            "AffectedFiles": [],
            "OriginatingProcess": "",
            "ImmutabilityState": "ImmutableUntil2026-08-13",
            "MarkedClean": True,
            "Analyst": "Veeam Automation",
        },
    ]
    ingest("veeam_malware", rows)


# ====================== main ======================
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=["anomali", "gigamon", "bigid", "veeam", "all"],
                        default="all", help="Seed only one partner (default: all).")
    args = parser.parse_args()

    print(f"Seeding agentic-SOC narrative into workspace {WORKSPACE_ID}")
    print(f"  Mac host  : {MAC_HOST} ({MAC_IP})")
    print(f"  IOC TeamID: {BAD_TEAM_ID}")
    print(f"  IOC SHA   : {BAD_SHA256}")
    print(f"  File svr  : {FILE_SERVER_HOST} ({FILE_SERVER_IP})")
    print(f"  C2        : {C2_DOMAIN} ({C2_IP})")

    if args.only in ("all", "anomali"): seed_anomali_ti()
    if args.only in ("all", "gigamon"): seed_gigamon_flows()
    if args.only in ("all", "bigid"):   seed_bigid_asset()
    if args.only in ("all", "veeam"):   seed_veeam_malware()

    print("\nDone. Verify with the KQL queries in kql/. Indexing may take 1-3 minutes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
