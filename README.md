<!-- FEATURE ADDED: MTTD / MTTR Metrics -->
<!-- FEATURE ADDED: Alert Correlation Engine -->
<!-- FEATURE ADDED: Shift Handoff Report -->
<!-- FEATURE ADDED: Response Playbook Checklist -->
<!-- FEATURE ADDED: Sigma Rule Generator -->

# SentinelOps — SOC Alert Triage & Investigation Console

**Author:** Rewantth Babh Vadlakonda  
**LinkedIn:** https://www.linkedin.com/in/rewantth-babh

## Project Summary

SentinelOps is a full-stack cybersecurity dashboard that simulates SOC alert triage, enrichment, MITRE ATT&CK mapping, analyst notes, case status tracking, and investigation reporting using safe simulated alerts. It is designed as a resume-ready defensive blue-team portfolio project and does not include offensive functionality, malware, or harmful payloads.

The frontend now uses a focused workspace model: each sidebar selection opens a dedicated full-screen SOC module instead of showing every major section at once.

## Features

- Simulated alert generation with realistic safe SOC logs
- JSON alert ingestion into SQLite
- Flask API backend with SQLAlchemy models
- Single-page alert queue dashboard
- Severity, status, alert type, and search filtering
- MITRE ATT&CK classification workflow
- VirusTotal IP enrichment workflow with safe no-key fallback
- Analyst notes and investigation summary tracking
- Case status workflow from new to closed
- Case timeline with second-level timestamps
- Second-by-second live SOC clock
- Relative alert age updates every second
- Live simulated alert feed
- Start/Pause live simulation mode that creates a safe alert every 5 seconds
- Chart.js statistics and reporting panels
- Investigation export as JSON
- Dark cinematic cybersecurity UI

## Workspace Modules

- Command Center
- Live Alert Feed
- Case Queue
- Investigation War Room
- Threat Market View
- MITRE Heatmap
- Threat Intel Lookup
- Detection Lab
- Case Reports
- Analyst Profile

Each module opens as its own full-screen workspace with active sidebar highlighting, reducing clutter while preserving the full SOC workflow.

## v2.0 Features

- **MTTD / MTTR metrics:** Tracks status transitions and reports mean time to detect and respond in Command Center metrics.
- **Alert correlation engine:** Finds related alerts by source IP, MITRE tactic, and alert type with coordinated-attack indicators.
- **Shift handoff report:** Generates a print-ready eight-hour SOC handoff report for analyst continuity.
- **Response playbook checklist:** Provides per-alert incident response steps with persisted completion progress.
- **Sigma rule generator:** Produces simulated Sigma YAML from selected alerts in the Detection Engineering Lab.

## Threat Market View

Threat Market View uses a market-terminal inspired visualization style to represent SOC alert volatility, case pressure, threat movement, and investigation workload. These are cybersecurity/SOC visualizations, not finance features.

This workspace includes:

- Threat ticker tape for simulated alert activity
- Candlestick-style Alert Volatility Monitor
- Threat Volatility Index from alert workload conditions
- Case Pressure Board by severity and status
- Mini sparklines for alert and investigation movement
- Live Threat Movement Feed

Disclaimer: Threat Volatility Index and candlestick-style alert activity are simulated portfolio metrics, not real-world financial or production security scoring systems.


## Tech Stack

| Layer | Technology |
| --- | --- |
| Backend | Python, Flask |
| Database | SQLite, SQLAlchemy, Flask-SQLAlchemy |
| Data Generation | Faker |
| Enrichment | requests, python-dotenv |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |

## Setup Instructions

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python generate_alerts.py
python ingest_alerts.py
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

If port `5000` is busy:

```bash
PORT=5001 python app.py
```

## VirusTotal Setup

Create a `.env` file:

```bash
VIRUSTOTAL_API_KEY=your_api_key_here
```

The project still works without an API key. Without a key, SentinelOps returns a professional fallback message:

```text
VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to enable live IP reputation checks.
```

## API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/alerts` | Return alerts with severity, status, type, and search filters |
| GET | `/api/alerts/<alert_id>` | Return full details for one alert |
| POST | `/api/classify/<alert_id>` | Save MITRE ATT&CK tactic, technique, and description |
| POST | `/api/enrich/<alert_id>` | Run VirusTotal enrichment or no-key fallback |
| POST | `/api/update_status/<alert_id>` | Update alert status and set `closed_at` when closed |
| POST | `/api/update_notes/<alert_id>` | Save analyst notes and investigation summary |
| GET | `/api/stats` | Return metrics, distributions, top IPs, and latest alerts |
| GET | `/api/timeline/<alert_id>` | Return case timeline events |
| GET | `/api/export/<alert_id>` | Return investigation export as JSON |
| POST | `/api/simulate_alert` | Create one new safe simulated alert for live mode |
| GET | `/api/alerts/correlated/<alert_id>` | Return related alerts and coordinated-attack indicator |
| GET | `/api/reports/shift` | Generate eight-hour shift handoff report JSON |
| GET | `/api/playbook/<alert_id>` | Return response playbook steps and completion status |
| POST | `/api/playbook/<alert_id>/<step_index>` | Toggle a playbook step for an alert |
| GET | `/api/sigma/<alert_id>` | Generate simulated Sigma YAML for a selected alert |

## Real SOC Workflow Mapping

- **Alert ingestion:** `generate_alerts.py` creates safe JSON alerts and `ingest_alerts.py` stores them in SQLite.
- **Triage:** Analysts filter by severity, status, type, source IP, destination IP, or alert ID.
- **Enrichment:** Source IPs can be checked through VirusTotal when an API key is configured.
- **Classification:** Alert types map to MITRE ATT&CK tactics and techniques.
- **Investigation:** Analysts document notes and summaries in the investigation panel.
- **Escalation:** Cases can be moved through new, investigating, escalated, and closed states.
- **Closure:** Closed cases receive a `closed_at` timestamp and timeline event.
- **Reporting:** Stats, charts, timeline events, and investigation export demonstrate reporting workflow.

## Resume Value

This project demonstrates:

- Flask backend development
- SQLite database integration with SQLAlchemy
- REST API design
- Security dashboard development
- MITRE ATT&CK mapping
- Simulated SOC workflow understanding
- Analyst documentation workflow
- Case timeline and investigation reporting
- Cybersecurity UI/UX design
- Safe defensive security engineering

## Future Improvements

- Authentication
- Role-based analyst access
- WebSocket live alerts
- PDF report export
- Sigma rule generation
- Docker support
- Splunk/Elastic integration simulation
