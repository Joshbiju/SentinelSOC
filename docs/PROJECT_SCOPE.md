# Final-Year Project Scope

## Title

SentinelSOC: Design and Development of a Real-Time Security Operations Center with Automated Threat Detection, Correlation and Incident Management

## Problem

Small organizations and educational labs need centralized visibility into endpoint security events but commercial SIEM platforms can be complex and expensive. The project demonstrates the core pipeline using software developed by the student.

## Research questions

1. How can heterogeneous endpoint events be normalized into one event model?
2. How can rule-based detection identify suspicious activity in real time?
3. How can event correlation reduce isolated-event noise?
4. How can risk scoring prioritize analyst attention?
5. How can WebSockets provide low-latency SOC visualization?

## Modules

### Collection
Agents collect host metrics, processes, network connections and OS security logs.

### Transport
Agents send JSON events over HTTP using an API key.

### Storage
SQLite stores normalized events, metrics, alerts, incidents, rules and IOCs.

### Detection
Rules match event fields. A correlation detector identifies repeated authentication failures.

### Enrichment
Alerts include severity, risk, MITRE tactic and technique.

### Response workflow
Analysts acknowledge and resolve alerts and can track incidents.

### Visualization
The dashboard consumes REST APIs and receives live updates over WebSocket.

## Evaluation

Measure:
- event ingestion rate
- average alert latency
- CPU/memory usage of the agent
- database growth
- detection precision/recall for a controlled lab test set
- false-positive rate
- dashboard update latency
