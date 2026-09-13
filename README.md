# SentinelSOC — Agentless Security Operations Center

SentinelSOC is a from-scratch, real-time SOC/SIEM-style educational platform. **This updated build is agentless:** the backend itself collects telemetry from the Kali host. There is no Splunk, Wazuh, Elastic, Graylog, or endpoint agent integration.

## What changed
- Removed the agent requirement from the monitoring path.
- Added native local collection of Linux authentication/security logs and host metrics.
- Added controlled **Attack Campaigns** for generating security telemetry inside the project.
- Added brute-force correlation: 5+ failed authentications from one source in 10 minutes.
- Added a **10-second full-screen red flash** when `CORR-001` brute-force detection fires.
- Added a dashboard layout closely matching the supplied SentinelSOC Command Center screenshot.
- Kept event explorer, alerts, incidents, assets, threat intel/IOC, detection rules, reports, WebSocket live updates, risk scoring and MITRE ATT&CK mapping.

## Run on Kali
```bash
cd ~/SentinelSOC_v2
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

Open `http://127.0.0.1:8000`.

## Demonstrate detection
Open **Attack Campaigns → Simulate Brute Force**. The backend creates controlled `login_failed` telemetry, the correlation engine raises `CORR-001`, the alert appears in real time, and the screen flashes for 10 seconds.

The simulation is deliberately local and non-destructive. For a real-world demonstration, only generate security events against systems you own or are explicitly authorized to test.

## Architecture
Browser → FastAPI REST/WebSocket → local collector + detection/correlation → SQLite → dashboard.

No agent is needed. The old `agent/` directory is retained only as historical project material and is not used by the backend.

## Real port-scan detection

SentinelSOC now includes an agentless packet sensor using Scapy. It watches inbound TCP SYN packets destined for the monitored Kali host and raises a `NET-002` / `T1046 Network Service Scanning` alert when the same source probes at least 8 unique destination TCP ports within 60 seconds. The event contains the source IP, destination IP, port count and observed ports.

The packet sensor requires Scapy plus permission to capture packets. If SentinelSOC is started without raw-packet capture permission, the rest of the collector continues to run and port-scan telemetry will simply be unavailable.

For a controlled lab, scan only a Kali VM/localhost you own or are authorized to test. Do not use the feature against public or third-party systems.

## Extended standalone SOC modules
The existing project now includes 24-hour event trends with Z-score anomaly scoring, source-IP/event-type drill-down, source-IP correlation with destination ports and collector/user-agent fields, L1 alert triage, drag-and-drop incident workflow, severity visualization, a 5-second brute-force flash, and persistent IP block/unblock management. Existing SQLite data is preserved.
