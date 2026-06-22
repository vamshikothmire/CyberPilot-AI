import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

genai.configure(api_key=api_key)

model = genai.GenerativeModel("gemini-2.5-flash")

st.title("CyberPilot AI")
st.subheader("AI-Powered SOC Analyst Copilot")

alert = st.text_area(
    "Enter Security Alert",
    height=150
)

if st.button("Analyze Alert"):

    if not alert.strip():
        st.warning("Please enter a security alert.")
    else:

        prompt = f"""
You are a Senior SOC Analyst.

Analyze the security alert below.

Return:

1. Severity
2. Attack Type
3. MITRE ATT&CK Technique
4. Explanation
5. Remediation Steps

Alert:
{alert}
"""

        response = model.generate_content(prompt)

        st.markdown(response.text)