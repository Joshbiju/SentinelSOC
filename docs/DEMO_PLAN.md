# Safe Laboratory Demonstration

Use only VMs or systems you are authorized to monitor.

## Demo 1 — Live telemetry
1. Start the backend.
2. Start the Kali agent.
3. Open the dashboard.
4. Show host metrics, processes and network connections arriving.

## Demo 2 — Authentication detection
Generate several failed authentication events in your isolated lab.
The event stream should update and the correlation engine should create a high-risk/critical alert after the threshold.

## Demo 3 — Investigation
Open Alerts and show:
- source
- timestamp
- severity
- risk
- MITRE tactic
- MITRE technique
- evidence message

## Demo 4 — Incident
Use the incident API to create an incident from an alert and demonstrate its lifecycle:
open → investigating → contained → closed.

## Demo 5 — Reporting
Export events and alerts to CSV.

Do not perform attacks against public systems or networks.
