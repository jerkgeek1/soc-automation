# Automated SOC Alert Triage & Incident Response Lab

A hands-on Security Operations Center (SOC) automation project that collects Windows security alerts from Wazuh, detects failed-login patterns, enriches indicators, generates incident records, recommends response actions, and produces analyst-ready incident reports.

## Project Overview

This project simulates a SOC Analyst L1 workflow using real Wazuh telemetry from a Windows endpoint.

The automation pipeline processes Windows Event ID 4625 (failed authentication) alerts and performs:

- Alert collection from Wazuh Indexer
- Alert parsing
- Failed-login detection
- Source IP and username correlation
- Five-minute time-window analysis
- Severity assessment
- IP enrichment
- Response recommendation
- Incident creation
- Incident status tracking
- Analyst notes
- Incident timeline
- Markdown incident reports
- Automated testing with pytest

## Architecture

```text
Windows Endpoint
       |
       | Windows Security Events
       v
     Wazuh
       |
       v
Wazuh Indexer
       |
       v
Python SOC Automation
       |
       +--> Alert Parser
       |
       +--> Detection Engine
       |       |
       |       +--> Failed Login Detection
       |       +--> IP + Username Correlation
       |       +--> Five-Minute Time Window
       |
       +--> Severity Assessment
       |
       +--> IP Enrichment
       |
       +--> Response Recommendation
       |
       v
Incident Management
       |
       +--> JSON Incident
       +--> Analyst Notes
       +--> Status Timeline
       |
       v
Markdown SOC Incident Report


#Detection Logic
The project currently focuses on Windows Event ID 4625.

Lab detection thresholds:

| Failed Attempts | Severity |
| --------------- | -------- |
| 1-2             | LOW      |
| 3-4             | MEDIUM   |
| 5+              | HIGH     |

These thresholds are project-specific laboratory rules and are not intended to represent universal SOC standards.

#Time-Window Detection

Failed-login events are correlated when they belong to the same:

Source IP
Username

The detection engine evaluates activity inside a five-minute window.

Example:
10.0.0.50
    |
    +-- testuser
          |
          +-- Failed login
          +-- Failed login
          +-- Failed login
          +-- Failed login
          +-- Failed login
                |
                v
             HIGH
#IP Enrichment

The enrichment module classifies source addresses as:

PRIVATE
PUBLIC
LOOPBACK
OTHER
INVALID
UNKNOWN

Example:

::1
 |
 +-- LOOPBACK
 +-- Private: True
 +-- Loopback: True

#Response Recommendation

The response module provides recommendations rather than automatically performing containment.

Examples:

LOOPBACK
    |
    v
INVESTIGATE_LOCAL_ACTIVITY
NO_AUTO_BLOCK
HIGH + non-private source
    |
    v
ESCALATE_AND_CONSIDER_CONTAINMENT
MANUAL_APPROVAL_REQUIRED

This design keeps defensive actions under analyst control.

#Incident Management

Each detected incident is stored as a JSON document.

Incident records contain:

Incident ID
Creation timestamp
Status
Detection type
Severity
Source IP
IP enrichment
Username
Failed attempts
Detection window
Analyst assessment
Response recommendation
Analyst notes
Incident timeline

Supported incident statuses:

OPEN
INVESTIGATING
RESOLVED
FALSE_POSITIVE

Example lifecycle:

OPEN
  |
  v
INVESTIGATING
  |
  v
RESOLVED

#Reporting

The reporting module converts incident JSON into a Markdown SOC incident report.

Reports include:

Incident overview
Detection details
Source information
Authentication activity
Analyst assessment
Recommended response
Analyst notes
Incident timeline

Reports are stored in:

incidents/reports/

#Testing

The project uses pytest for automated testing.

Current test coverage includes:

Detection
Brute-force threshold detection
IP + username correlation
Five-minute time-window detection
Incident Management
Incident creation
IP enrichment
Incident status updates
Analyst notes
Response
Loopback response
High-severity external response
Medium-severity response
Low-severity response

Current test result:

10 passed

Run the complete test suite with:

pytest -v

#Project Structure
soc-automation/
├── collectors/
│   ├── wazuh_api.py
│   └── wazuh_indexer.py
│
├── detection/
│   ├── bruteforce.py
│   ├── correlation.py
│   └── time_window.py
│
├── enrichment/
│   └── ip_enrichment.py
│
├── parsers/
│   └── alert_parser.py
│
├── reporting/
│   ├── incident.py
│   └── report_generator.py
│
├── response/
│   └── recommendation.py
│
├── tests/
│   ├── test_detection.py
│   ├── test_incident.py
│   └── test_response.py
│
├── incidents/
│   └── reports/
│
├── README.md
├── requirements.txt
└── .gitignore

#Technologies Used
Wazuh
Wazuh Indexer
Windows Security Event Logs
Python
Python Requests
pytest
Linux / WSL
SSH
JSON
Markdown
Git / GitHub
Example Investigation

A controlled Windows authentication test generated Event ID 4625 failures.

The automation:

Collected the alerts from Wazuh.
Parsed the Windows event fields.
Correlated events by source IP and username.
Detected repeated authentication failures.
Assigned laboratory severity.
Classified the source IP.
Created an incident.
Added an analyst assessment.
Generated a response recommendation.
Recorded analyst status changes.
Generated a Markdown incident report.
Security Design Principles

This project follows several SOC automation principles:

Prefer evidence-driven detection.
Correlate multiple events instead of relying on a single alert.
Preserve analyst context.
Record incident history.
Avoid automatic containment without sufficient evidence.
Keep response recommendations explainable.
Test detection logic independently from live telemetry.

#Future Improvements

Planned improvements include:

Additional Windows event detections
Authentication anomaly detection
Network-based enrichment
Threat intelligence integration
Automated alert prioritization
Email/Slack incident notifications
SOC ticketing integration
Additional unit and integration tests
Proper TLS certificate validation
Containerized deployment
Splunk integration

#Disclaimer

This project is a controlled security laboratory designed for defensive security learning and SOC analyst practice.



