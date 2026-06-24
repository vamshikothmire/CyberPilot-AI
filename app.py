import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import os
import re
from datetime import datetime
from io import BytesIO

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


# -----------------------
# IOC ENGINE
# -----------------------

def extract_iocs(text):
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

    users = re.findall(
        r"(?:User|Target User):\s*(.*)",
        text,
        re.IGNORECASE
    )

    hosts = re.findall(
        r"Host:\s*(.*)",
        text,
        re.IGNORECASE
    )

    return {
        "IPs": list(set(ips)),
        "Users": list(set(users)),
        "Hosts": list(set(hosts))
    }


# -----------------------
# LOCAL MITRE ENGINE
# -----------------------

MITRE_DB = {
    "powershell": {
        "id": "T1059.001",
        "technique": "PowerShell Execution"
    },
    "mimikatz": {
        "id": "T1003",
        "technique": "Credential Dumping"
    },
    "brute force": {
        "id": "T1110",
        "technique": "Brute Force"
    },
    "ransomware": {
        "id": "T1486",
        "technique": "Data Encrypted for Impact"
    },
    "encodedcommand": {
        "id": "T1027",
        "technique": "Obfuscated Files or Information"
    }
}

RISK_RULES = {
    "powershell": 8,
    "encodedcommand": 9,
    "mimikatz": 10,
    "brute force": 7,
    "brute-force": 7,
    "ransomware": 10,
    "credential dumping": 10
}
ATTACK_STAGES = {
    "brute force": "Initial Access",
    "powershell": "Execution",
    "encodedcommand": "Execution",
    "mimikatz": "Credential Access",
    "ransomware": "Impact"
}

def local_mitre_lookup(alert):
    alert = alert.lower()

    for keyword, data in MITRE_DB.items():
        if keyword in alert:
            return data

    return None


def calculate_risk(alert):
    alert = alert.lower().replace("-", " ")
    highest_score = 3

    for keyword, score in RISK_RULES.items():
        if keyword in alert:
            highest_score = max(highest_score, score)

    return highest_score


def correlate_attack_chain(alert):

    alert_lower = alert.lower()

    stages = []

    for keyword, stage in ATTACK_STAGES.items():

        if keyword in alert_lower:

            stages.append(stage)

    return list(dict.fromkeys(stages))


def build_timeline(stages):

    timeline = []

    counter = 1

    for stage in stages:

        timeline.append(
            f"Step {counter}: {stage}"
        )

        counter += 1

    return timeline
# -----------------------
# PDF ENGINE (v0.6)
# -----------------------

def generate_pdf_report(report_text):
    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()

    elements = []

    for line in report_text.split("\n"):
        elements.append(Paragraph(line, styles["BodyText"]))
        elements.append(Spacer(1, 4))

    doc.build(elements)

    pdf = buffer.getvalue()
    buffer.close()

    return pdf


# -----------------------
# CONFIG
# -----------------------

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    st.error("GEMINI_API_KEY not found in .env file")
    st.stop()

genai.configure(api_key=api_key)

model = genai.GenerativeModel("gemini-2.5-flash")

st.set_page_config(
    page_title="CyberPilot AI v0.6",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------
# SIDEBAR
# -----------------------

with st.sidebar:

    st.title("🛡️ CyberPilot AI v0.6")

    st.markdown("""
### Features

- AI SOC Analysis
- MITRE ATT&CK Mapping
- IOC Extraction
- Threat Intelligence
- Risk Scoring
- Executive Summary
- Incident Reports
- PDF Export
""")

    st.divider()

    example = st.selectbox(
        "Example Alert",
        [
            "None",
            """Event ID: 4104
PowerShell EncodedCommand detected
User: Administrator
Host: WIN-DC01""",
            """Event ID: 4625
50 failed login attempts detected
Source IP: 192.168.1.50
Target User: Administrator
Host: DC01""",
            """Process Creation:
mimikatz.exe

LSASS memory access detected

User: Administrator
Host: WIN-DC01""",
            """Mass file modifications detected
Shadow copies deleted
500 files encrypted in 2 minutes
Host: FILE-SERVER01"""
        ]
    )

# -----------------------
# MAIN
# -----------------------

st.title("🛡️ CyberPilot AI")
st.caption("AI-Powered SOC Analyst Copilot")

default_alert = "" if example == "None" else example

alert = st.text_area(
    "Enter Security Alert",
    value=default_alert,
    height=220
)

if st.button("Analyze Alert", use_container_width=True):

    if not alert.strip():
        st.warning("Please enter a security alert.")
        st.stop()

    prompt = f"""
You are a Senior SOC Analyst.

Analyze the alert.

Return EXACTLY:

Severity: <Critical/High/Medium/Low>
Attack Type: <Type>
MITRE Technique: <Technique>
MITRE ID: <ID>
Risk Score: <1-10>

Explanation:
<Explanation>

Remediation:
<Remediation>
        
Alert:
{alert}
"""

    with st.spinner("Analyzing alert..."):
        response = model.generate_content(prompt)
        result = response.text

    iocs = extract_iocs(alert)
    local_match = local_mitre_lookup(alert)
    local_risk = calculate_risk(alert)
    attack_chain = correlate_attack_chain(alert)
    timeline = build_timeline(attack_chain)

    def extract(pattern, text, default="Unknown"):
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else default

    severity = extract(r"Severity:\s*(.+)", result)
    attack_type = extract(r"Attack Type:\s*(.+)", result)
    mitre_id = extract(r"MITRE ID:\s*(.+)", result)
    if local_match:
        mitre_id = local_match["id"]

    report_text = f"""
CYBERPILOT AI INCIDENT REPORT

Generated:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Severity:
{severity}

Attack Type:
{attack_type}

MITRE ID:
{mitre_id}

Risk Score:
{local_risk}

INDICATORS OF COMPROMISE

IPs:
{", ".join(iocs["IPs"]) if iocs["IPs"] else "None"}

Users:
{", ".join(iocs["Users"]) if iocs["Users"] else "None"}

Hosts:
{", ".join(iocs["Hosts"]) if iocs["Hosts"] else "None"}

EXECUTIVE SUMMARY

Potential security incident analyzed by CyberPilot AI.

RECOMMENDED ACTIONS

Review logs.
Investigate affected systems.
Apply containment measures.
Perform threat hunting.
"""

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Severity", severity)
    col2.metric("MITRE ID", mitre_id)
    col3.metric("Attack Type", attack_type)
    col4.metric("Risk Score", local_risk)

    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
        "Incident Summary",
        "MITRE Mapping",
        "Remediation",
        "IOCs",
        "Executive Summary",
        "Incident Report",
        "Correlation",
        "Timeline"
    ])

    with tab1:
        st.markdown(result)

    with tab2:
        st.subheader("MITRE Mapping")

        if local_match:
            st.success("Local Detection Match")
            st.json(local_match)

        st.info(f"MITRE ID: {mitre_id}")

    with tab3:
        remediation_match = re.search(
            r"Remediation:(.*)",
            result,
            re.IGNORECASE | re.DOTALL
        )

        if remediation_match:
            st.markdown(remediation_match.group(1))

    with tab4:
        st.json(iocs)

    with tab5:

        st.write(f"Severity: {severity}")
        st.write(f"Risk Score: {local_risk}")
        st.write(f"Attack Type: {attack_type}")

        if local_risk >= 8:
            st.error("Immediate SOC investigation recommended.")
        elif local_risk >= 5:
            st.warning("Medium priority incident.")
        else:
            st.success("Low priority incident.")

    with tab6:

        st.text_area(
            "Generated Report",
            report_text,
            height=400
        )

        txt_col, pdf_col = st.columns(2)

        with txt_col:
            st.download_button(
                "📄 Download TXT Report",
                data=report_text,
                file_name="CyberPilot_Report.txt",
                mime="text/plain"
            )

        with pdf_col:
            pdf_data = generate_pdf_report(report_text)

            st.download_button(
                "📕 Download PDF Report",
                data=pdf_data,
                file_name="CyberPilot_Report.pdf",
                mime="application/pdf"
            )
    with tab7:

        st.subheader(
        "Attack Correlation Engine"
    )

    if attack_chain:

        st.success(
            "Multi-Stage Attack Detected"
        )

        for stage in attack_chain:

            st.write(
                f"• {stage}"
            )

    else:

        st.info(
            "No attack chain identified."
        )
    with tab8:

        st.subheader(
        "Incident Timeline"
    )

    if timeline:

        for event in timeline:

            st.write(event)

    else:

        st.info(
            "No timeline available."
        )
