import streamlit as st
import requests
import json

st.set_page_config(page_title="UPM Security Analyst", layout="wide")

st.title("🛡️ AI-Powered Incident Response Dashboard")
st.write("University of Prince Mugrin - FC382 Project")


st.sidebar.header("Log Input")

sample_log = """[
  {
    "event_type": "brute_force",
    "description": "10 failed login attempts for admin from 192.168.1.5",
    "source_ip": "192.168.1.5",
    "severity": "high"
  }
]"""
log_input = st.sidebar.text_area("Paste Parsed JSON Logs:", value=sample_log, height=200)


if st.sidebar.button("Analyze Incident"):
    try:
        events = json.loads(log_input)

        with st.spinner("LLM is analyzing..."):
            response = requests.post(
                "http://127.0.0.1:8000/analyze", 
                json={"events": events}
            )
            
        if response.status_code == 200:
            analysis = response.json()["analysis"]
            

            st.header("Incident Analysis Report")
            
            col1, col2 = st.columns([1, 2])
            with col1:
                st.metric("Risk Level", analysis["overall_risk_level"].upper())
                st.write(f"**Confidence:** {analysis['confidence_score']}")
            
            with col2:
                st.subheader("📝 Executive Summary")
                st.info(analysis["executive_summary"])
            
            st.subheader("🎯 MITRE ATT&CK Mapping")
            st.write(", ".join(analysis["attack_patterns"]))
            
            st.subheader("🚀 Recommendations")
            for rec in analysis["recommendations"]:
                st.warning(f"**{rec['priority'].upper()}**: {rec['action']}")
        else:
            st.error(f"Backend Error: {response.status_code}")
            
    except Exception as e:
        st.error(f"Make sure you run 'main.py' first! Error: {e}")