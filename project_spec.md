# CyberPilot AI

## Project Vision

CyberPilot AI is an AI-powered SOC Analyst Copilot that helps security analysts analyze alerts, map threats to MITRE ATT&CK, explain incidents, and recommend remediation actions.

---

## Problem Statement

Security analysts receive thousands of alerts daily.

Many alerts require manual investigation and analysis.

CyberPilot AI reduces investigation time by automatically analyzing alerts and providing actionable insights.

---

## Target Users

- SOC Analysts
- Security Engineers
- Blue Team Professionals
- Cybersecurity Students

---

## MVP Goal

Input:
Security Alert

Output:
- Severity
- Attack Type
- MITRE ATT&CK Technique
- Explanation
- Remediation Steps

---

## Example

Input:

Multiple failed SSH login attempts from 192.168.1.50

Output:

Severity: Medium

Attack Type:
Brute Force Attack

MITRE ATT&CK:
T1110

Explanation:
Repeated authentication failures indicate a possible brute force attempt.

Recommendations:
1. Block source IP
2. Enable MFA
3. Review authentication logs

---

## Future Features

- Wazuh Integration
- Threat Intelligence Lookup
- Incident Report Generation
- Multi-Agent Investigation
- RAG Knowledge Base
- Dashboard Analytics
