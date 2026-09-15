# 🛡️ SentinelSOC

### Agentless Security Operations Center & Threat Monitoring Platform

> **A lightweight, real-time Security Operations Center built from the ground up for security monitoring, threat detection, incident response, IOC correlation, and attack investigation — without relying on heavyweight SIEM platforms.**

[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite)](https://www.sqlite.org/)
[![WebSocket](https://img.shields.io/badge/Updates-WebSocket-purple)](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)
[![Security](https://img.shields.io/badge/Focus-Cybersecurity-red)](#)
[![Status](https://img.shields.io/badge/Status-Active-success)](#)

---

## 🚨 What is SentinelSOC?

**SentinelSOC** is a custom-built Security Operations Center platform designed to collect, analyze, correlate, and visualize security telemetry from monitored systems.

Unlike traditional enterprise SIEM platforms that can require complex deployments and large infrastructure, SentinelSOC follows an **agentless and lightweight architecture**, making it suitable for security laboratories, academic research, demonstrations, and controlled security environments.

The platform combines:

* 🔍 Security event monitoring
* 🚨 Automated threat detection
* 🧠 Event correlation
* 🎯 MITRE ATT&CK mapping
* 🕵️ IOC / Threat Intelligence analysis
* 🖥️ Asset monitoring
* 📊 Security posture scoring
* ⚔️ Controlled attack campaigns
* 🧯 Incident response workflows
* 🌐 IP management and blocking
* 📑 Security reporting
* ⚙️ SOC configuration and detection-rule management
* ⚡ Real-time dashboard updates

The goal is simple:

> **Turn raw system telemetry into actionable security intelligence.**

---

# 🎯 Project Vision

Modern security monitoring generates enormous amounts of telemetry. The challenge is not simply collecting logs — it is determining **what matters, why it matters, and what should happen next**.

SentinelSOC addresses this problem through a complete security-monitoring pipeline:

```text
┌──────────────────────┐
│   Monitored Host     │
│                      │
│ Auth / System Logs   │
│ Processes            │
│ Network Information  │
│ System Metrics       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Telemetry Layer    │
│                      │
│ Event Collection     │
│ Normalization        │
│ Classification       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Detection Engine     │
│                      │
│ Rule Matching        │
│ Correlation          │
│ Threshold Detection  │
│ Alert Cooldowns      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Security Operations  │
│                      │
│ Alerts               │
│ Incidents            │
│ IOC Correlation      │
│ MITRE ATT&CK         │
│ Risk Analysis        │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   SOC Command Center │
│                      │
│ Dashboard            │
│ Events               │
│ Alerts               │
│ Incidents             │
│ Assets               │
│ Threat Intel         │
│ Reports              │
└──────────────────────┘
```

---

# ✨ Core Capabilities

## 📊 SOC Command Center

The central dashboard provides a security-focused overview of the environment.

It provides visibility into:

* Security posture score
* Active alerts
* Total alerts
* Security events
* Unique source IPs
* Critical and high-severity activity
* Threat intelligence indicators
* MITRE ATT&CK techniques
* Top attack vectors
* Real-time security activity

The dashboard is designed around the workflow of a SOC analyst rather than simply displaying raw system statistics.

---

## 🔍 Security Event Explorer

SentinelSOC normalizes collected telemetry into security events that can be investigated through the Event Explorer.

Analysts can examine:

* Event type
* Timestamp
* Source
* Source IP
* User
* Command
* Severity
* Event metadata
* Detection context

This provides a centralized view of the activity occurring across the monitored environment.

---

## 🚨 Detection & Alerting

The detection engine evaluates incoming security events against configurable detection rules.

Current detection coverage includes:

| Rule        | Detection                          | Severity |
| ----------- | ---------------------------------- | -------- |
| `ADMIN-001` | Privileged account changes         | High     |
| `AUTH-001`  | Suspicious PowerShell activity     | High     |
| `AUTH-002`  | SSH root login                     | High     |
| `AUTH-003`  | Successful root login              | High     |
| `NET-001`   | Suspicious network connection      | Medium   |
| `NET-002`   | Network reconnaissance / port scan | High     |
| `PRIV-001`  | Privilege escalation / change      | High     |
| `PROC-001`  | Command interpreter activity       | Medium   |

### Alert Flood Protection

SentinelSOC also implements **per-rule alert cooldowns**.

Repeated telemetry should not result in hundreds of duplicate alerts for the same security condition.

The detection engine therefore applies a configurable cooldown mechanism to reduce alert noise and improve analyst usability.

---

# 🧠 Event Correlation

Individual events can sometimes appear harmless in isolation.

SentinelSOC correlates related activity to identify higher-confidence attack patterns.

### Example: Brute-Force Detection

```text
Failed Login
      │
      ▼
Multiple Attempts
      │
      ▼
Same Source IP
      │
      ▼
Time Window Correlation
      │
      ▼
CORR-001
      │
      ▼
Security Alert
      │
      ▼
Incident Investigation
```

This allows the platform to move from:

**"A login failed"**

to:

**"Multiple authentication failures from the same source within a short time window indicate possible brute-force activity."**

---

# ⚔️ Attack Campaigns

SentinelSOC includes a controlled attack-campaign environment for demonstrating and validating detection capabilities.

Campaign scenarios can generate security telemetry corresponding to activities such as:

* Brute-force authentication
* Privilege escalation
* Account manipulation
* Network reconnaissance
* Suspicious command execution

The purpose is not merely to generate attacks, but to demonstrate the complete SOC workflow:

```text
Attack Simulation
       ↓
Telemetry Generation
       ↓
Event Detection
       ↓
Correlation
       ↓
Alert Creation
       ↓
MITRE Mapping
       ↓
Analyst Investigation
       ↓
Incident Response
```

This makes the platform suitable for **SOC demonstrations, security education, and detection engineering validation**.

---

# 🎯 MITRE ATT&CK Integration

Detected activity can be mapped to MITRE ATT&CK techniques to provide additional context to analysts.

Example mappings include:

| Technique | Description                       |
| --------- | --------------------------------- |
| `T1110`   | Brute Force                       |
| `T1098`   | Account Manipulation              |
| `T1548`   | Abuse Elevation Control Mechanism |
| `T1046`   | Network Service Scanning          |

MITRE mapping helps answer an important SOC question:

> **"What attacker behavior does this alert represent?"**

---

# 🕵️ Threat Intelligence

The Threat Intelligence module provides IOC-oriented security analysis.

It supports:

* IOC management
* Indicator classification
* Threat intelligence correlation
* Matching observed activity against known indicators
* Security context for suspicious infrastructure

This connects **external threat intelligence** with **internal security telemetry**.

---

# 🖥️ Asset Management

The Asset Management module maintains visibility into monitored systems.

Analysts can inspect:

* Host information
* Operating system information
* Asset status
* Security activity
* Associated events
* Associated alerts

This provides the context necessary to answer:

> **"Which asset is being targeted?"**

---

# 🌐 IP Management

SentinelSOC provides dedicated IP-oriented security operations.

The IP Management interface supports visibility into:

* Observed IP addresses
* Suspicious addresses
* Blocked addresses
* IP-related security activity
* Network reconnaissance indicators

This creates a direct relationship between **network observations and SOC response actions**.

---

# 🧯 Incident Response Center

Alerts represent individual security detections.

Incidents represent the **investigation of those detections**.

SentinelSOC therefore provides an incident-response workflow that allows analysts to:

```text
Alert
  ↓
Triage
  ↓
Investigation
  ↓
Incident
  ↓
Evidence / Related Events
  ↓
Response
  ↓
Resolution
```

Incidents can contain:

* Severity
* Risk score
* Status
* Analyst ownership
* Summary
* Related alerts
* Investigation context

---

# 📈 Security Posture Scoring

SentinelSOC provides a dynamic security posture score based on the current security state.

The scoring model considers factors such as:

* Critical alerts
* High-severity alerts
* Active security pressure

The score uses a diminishing-risk model so that a large number of repeated alerts does not immediately collapse the dashboard into an unusable `0%` state.

This provides a more meaningful visual representation of the environment's current security posture.

---

# ⚡ Real-Time SOC Monitoring

SentinelSOC uses WebSocket-based updates to provide live dashboard activity.

Instead of requiring an analyst to constantly refresh the interface:

```text
New Event
   ↓
Backend Processing
   ↓
Detection Engine
   ↓
Alert / Correlation
   ↓
WebSocket Update
   ↓
SOC Dashboard
```

Security activity can therefore appear directly in the SOC interface as it occurs.

---

# 📑 Security Reports

The reporting module provides a consolidated view of the security environment.

Reports can include information related to:

* Events
* Alerts
* Incidents
* Threat intelligence
* Detection activity
* Security posture
* Attack techniques

This helps transform operational SOC data into information suitable for:

* Security reviews
* Demonstrations
* Academic documentation
* Incident analysis
* Management reporting

---

# ⚙️ SOC Configuration Center

SentinelSOC includes a dedicated Settings / SOC System & Configuration area.

It provides centralized visibility into platform configuration such as:

* Detection configuration
* Alert behavior
* Correlation thresholds
* System settings
* SOC operational parameters

This makes the platform easier to configure and demonstrate without modifying the application architecture itself.

---

# 🏗️ Architecture

SentinelSOC follows a modular architecture:

```text
                    ┌───────────────────────┐
                    │     SOC Dashboard     │
                    │   HTML / CSS / JS     │
                    └───────────┬───────────┘
                                │
                         REST / WebSocket
                                │
                                ▼
                    ┌───────────────────────┐
                    │      FastAPI API      │
                    │      SOC Backend      │
                    └───────────┬───────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
          ▼                     ▼                     ▼
   ┌─────────────┐      ┌──────────────┐      ┌─────────────┐
   │  Collector  │      │   Detection  │      │ Correlation │
   │             │      │    Engine    │      │   Engine    │
   └──────┬──────┘      └──────┬───────┘      └──────┬──────┘
          │                    │                     │
          └────────────────────┼─────────────────────┘
                               ▼
                       ┌────────────────┐
                       │     SQLite     │
                       │   SOC Store    │
                       └────────────────┘
```

---

# 🧰 Technology Stack

### Backend

* **Python**
* **FastAPI**
* **Uvicorn**
* **SQLite**
* **WebSocket**

### Security & Telemetry

* Linux authentication logs
* System telemetry
* Process inventory
* Network inventory
* Security event normalization
* Rule-based detection
* Event correlation
* MITRE ATT&CK mapping

### Frontend

* HTML5
* CSS3
* JavaScript
* REST API integration
* WebSocket live updates

### Network Analysis

* Scapy
* Network reconnaissance detection
* IP-oriented security analysis

---

# 📁 Project Structure

```text
SentinelSOC_v2/
│
├── dashboard/
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── server/
│   ├── app.py
│   ├── config.py
│   ├── collector.py
│   ├── detection.py
│   ├── correlation.py
│   └── ...
│
├── rules/
│   └── rules.json
│
├── data/
│   └── soc.db
│
├── README.md
└── ...
```

---

# 🚀 Getting Started

## 1. Clone the repository

```bash
git clone https://github.com/Joshbiju/SentinelSOC.git
cd SentinelSOC
```

## 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Start SentinelSOC

```bash
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

## 5. Open the SOC Dashboard

Navigate to:

```text
http://127.0.0.1:8000
```

---

# 🔬 Detection Validation

SentinelSOC includes controlled security-event generation and attack campaigns for validating the detection pipeline.

A typical validation cycle is:

```text
Generate Security Activity
          ↓
Verify Event Creation
          ↓
Verify Detection Rule
          ↓
Verify Alert
          ↓
Verify Correlation
          ↓
Verify MITRE Technique
          ↓
Create / Investigate Incident
          ↓
Verify SOC Dashboard
```

This makes the system demonstrable from **event generation all the way to analyst response**.

---

# 📊 Current Platform Coverage

| SOC Capability            | Status |
| ------------------------- | :----: |
| Security Event Collection |    ✅   |
| Event Explorer            |    ✅   |
| Detection Engine          |    ✅   |
| Alert Management          |    ✅   |
| Alert Cooldown            |    ✅   |
| Event Correlation         |    ✅   |
| Brute-Force Detection     |    ✅   |
| Attack Campaigns          |    ✅   |
| MITRE ATT&CK Mapping      |    ✅   |
| Incident Response         |    ✅   |
| Asset Management          |    ✅   |
| Threat Intelligence       |    ✅   |
| IOC Correlation           |    ✅   |
| IP Management             |    ✅   |
| Security Reports          |    ✅   |
| SOC Configuration         |    ✅   |
| Real-Time Updates         |    ✅   |
| Security Posture Score    |    ✅   |

---

# 🔐 Security Design Principles

SentinelSOC is designed around several principles:

### 1. Agentless Monitoring

The platform is designed to collect telemetry without requiring a heavyweight endpoint agent architecture.

### 2. Detection Before Visualization

Events are processed through detection and correlation logic rather than simply being displayed as raw logs.

### 3. Analyst-Centric Design

The interface is organized around the SOC analyst workflow:

**Detect → Triage → Investigate → Respond → Report**

### 4. Controlled Validation

Attack campaigns provide a controlled method for testing security detections.

### 5. Alert Noise Reduction

Rule-level cooldowns reduce duplicate alert generation from repeated telemetry.

---

# 🧪 Example SOC Workflow

Imagine repeated SSH authentication failures from a suspicious source:

```text
SSH Authentication Failures
            │
            ▼
     Event Collector
            │
            ▼
     Event Normalization
            │
            ▼
   Brute-Force Correlation
            │
            ▼
        CORR-001
            │
            ▼
      High Alert
            │
            ▼
     MITRE: T1110
            │
            ▼
   Analyst Investigation
            │
            ▼
       Incident
            │
            ▼
      SOC Response
```

This demonstrates how SentinelSOC converts low-level telemetry into an actionable security investigation.

---

# 🎓 Why SentinelSOC?

SentinelSOC is designed to demonstrate that a functional SOC does not have to begin with a large enterprise SIEM deployment.

The project focuses on understanding and implementing the **core principles behind security operations**:

> **Collect → Detect → Correlate → Prioritize → Investigate → Respond → Report**

Rather than treating cybersecurity as a collection of isolated features, SentinelSOC brings these capabilities together into a single operational workflow.

---

# 🛣️ Future Enhancements

Potential future improvements include:

* Multi-host monitoring
* Distributed collectors
* Persistent alert deduplication
* Advanced behavioral detection
* Machine-learning-assisted anomaly detection
* Automated response playbooks
* Expanded threat-intelligence feeds
* Container monitoring
* Cloud telemetry integration
* Role-based analyst access
* Advanced investigation timelines
* Extended MITRE ATT&CK coverage

---

# ⚠️ Disclaimer

SentinelSOC is intended for **educational, research, laboratory, and authorized security-testing environments**.

Attack simulation functionality should only be used against systems and networks for which you have explicit authorization.

---

# 👨‍💻 Author

**Josh Mammen Biju**

Cybersecurity • Security Operations • Threat Detection • SOC Engineering

---

## ⭐ Project Philosophy

> **A security event is only useful when it leads to understanding.**

> **SentinelSOC turns telemetry into that understanding.**

---

<p align="center">

### 🛡️ SentinelSOC

**Detect. Investigate. Respond.**

</p>
