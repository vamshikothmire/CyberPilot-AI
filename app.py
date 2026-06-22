import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import os
import re

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

# -----------------------
# PAGE CONFIG
# -----------------------

st.set_page_config(
    page_title="CyberPilot AI",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------
# SIDEBAR
# -----------------------

with st.sidebar:

    st.title("🛡️ CyberPilot AI")

    st.markdown("""
### AI-Powered SOC Analyst

#### Features

- Threat Detection
- MITRE ATT&CK Mapping
- Incident Analysis
- Remediation Guidance
- Risk Scoring
""")

    st.divider()

    st.subheader("Example Alerts")

    example = st.selectbox(
        "Choose Example Alert",
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

            """Mass file modifications detected
Shadow copies deleted
500 files encrypted in 2 minutes
Host: FILE-SERVER01""",

            """Process Creation:
mimikatz.exe

LSASS memory access detected

User: Administrator
Host: WIN-DC01"""
        ]
    )

# -----------------------
# HEADER
# -----------------------

st.title("🛡️ CyberPilot AI")

st.caption(
    "AI-Powered SOC Analyst Copilot for Threat Detection, MITRE ATT&CK Mapping, and Incident Response"
)

# -----------------------
# ALERT INPUT
# -----------------------

default_alert = ""

if example != "None":
    default_alert = example

alert = st.text_area(
    "Enter Security Alert",
    value=default_alert,
    height=220
)

# -----------------------
# ANALYZE BUTTON
# -----------------------

if st.button("Analyze Alert", use_container_width=True):

    if not alert.strip():
        st.warning("Please enter a security alert.")
        st.stop()

    prompt = f"""
You are a Senior SOC Analyst.

Analyze the security alert.

Return EXACTLY in this format:

Severity: <Critical/High/Medium/Low>

Attack Type: <Attack Type>

MITRE Technique: <Technique>

MITRE ID: <MITRE ID>

Risk Score: <1-10>

Explanation:
<Detailed explanation>

Remediation:
<Bulleted remediation steps>

Alert:
{alert}
"""

    with st.spinner("Analyzing security alert..."):

        response = model.generate_content(prompt)
        result = response.text

    st.success("Analysis Complete")

    # -----------------------
    # PARSING
    # -----------------------

    def extract(pattern, text, default="Undetermined"):
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else default

    severity = extract(
        r"Severity:\s*(.+)",
        result
    )

    attack_type = extract(
        r"Attack Type:\s*(.+)",
        result
    )

    mitre_id = extract(
        r"MITRE ID:\s*(.+)",
        result
    )

    risk_score = extract(
        r"Risk Score:\s*(.+)",
        result,
        "N/A"
    )

    # -----------------------
    # METRICS
    # -----------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Severity",
            severity
        )

    with col2:
        st.metric(
            "MITRE ID",
            mitre_id
        )

    with col3:
        st.metric(
            "Attack Type",
            attack_type
        )

    with col4:
        st.metric(
            "Risk Score",
            risk_score
        )

    # -----------------------
    # TABS
    # -----------------------

    tab1, tab2, tab3 = st.tabs(
        [
            "Incident Summary",
            "MITRE Mapping",
            "Remediation"
        ]
    )

    with tab1:

        st.subheader("Incident Analysis")

        st.write(f"**Severity:** {severity}")
        st.write(f"**Attack Type:** {attack_type}")
        st.write(f"**MITRE ID:** {mitre_id}")
        st.write(f"**Risk Score:** {risk_score}")

        st.divider()

        st.markdown(result)

    with tab2:

        st.subheader("MITRE ATT&CK Mapping")

        st.info(
            f"""
MITRE ID: {mitre_id}

Attack Type: {attack_type}
"""
        )

    with tab3:

        st.subheader("Remediation Guidance")

        remediation_match = re.search(
            r"Remediation:(.*)",
            result,
            re.IGNORECASE | re.DOTALL
        )

        if remediation_match:
            st.markdown(remediation_match.group(1))
        else:
            st.markdown(result)