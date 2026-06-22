# 🛡️ CyberPilot AI

AI-Powered SOC Analyst Copilot for Threat Detection, MITRE ATT&CK Mapping, IOC Extraction, Threat Scoring, and Incident Response.

---

## Overview

CyberPilot AI is an intelligent Security Operations Center (SOC) assistant designed to help analysts investigate security alerts faster and more effectively.

The platform leverages Google's Gemini AI to analyze alerts, identify attack techniques, map adversary behavior to the MITRE ATT&CK framework, extract Indicators of Compromise (IOCs), calculate risk scores, and provide remediation recommendations.

---

## Key Features

### Threat Detection

* AI-powered alert analysis
* Security event classification
* Severity assessment

### MITRE ATT&CK Mapping

* Maps alerts to ATT&CK techniques
* Identifies relevant MITRE IDs
* Provides attack context

### IOC Extraction

* Extracts IP addresses
* Detects domains
* Identifies URLs
* Highlights potential indicators

### Threat Intelligence Engine

* Internal IP identification
* IOC enrichment
* Local MITRE knowledge base

### Risk Scoring

* Automated threat scoring
* Severity classification
* Incident prioritization

### Incident Response Guidance

* Recommended remediation actions
* Containment suggestions
* Investigation guidance

### Executive Summary

* SOC-ready incident summaries
* Analyst-focused reporting

---

## Architecture

Security Alert
↓
CyberPilot AI
↓
Gemini AI Analysis
↓
MITRE Mapping
↓
IOC Extraction
↓
Threat Scoring
↓
Executive Summary
↓
Remediation Guidance

---

## Technology Stack

* Python
* Streamlit
* Google Gemini API
* MITRE ATT&CK Framework
* Regex-based IOC Extraction
* Threat Intelligence Logic

---

## Example Alert

Event ID: 4625
Source IP: 192.168.1.50
User: Administrator
Host: DC01
50 Failed Login Attempts

---

## Example Output

Severity: High

Attack Type: Brute Force Attack

MITRE ID: T1110

Risk Score: 8/10

Recommended Actions:

* Investigate source host
* Review authentication logs
* Enable account lockout policies
* Monitor for lateral movement

---

## Current Version

### v0.4

* SOC Dashboard
* Gemini Security Analysis
* MITRE ATT&CK Mapping
* IOC Extraction
* Threat Intelligence Engine
* Risk Scoring
* Executive Summary

---

## Future Roadmap

### v0.5

* Incident Report Generator
* Downloadable Reports

### v0.6

* PDF Report Export

### v0.7

* Multi-Alert Correlation

### v1.0

* Full AI SOC Analyst Platform
* Threat Hunting Assistant
* Security Knowledge Base
* Detection Engineering Support

---

## Author

Vamshi Kothmire

Cybersecurity Engineer | SOC Analyst | AI Security Enthusiast

---

## Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes only.
