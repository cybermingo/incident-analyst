import streamlit as st
import requests
import time

st.set_page_config(page_title="UPM Security Analyst", layout="wide")
st.title("🛡️ Live Incident Response Monitor")
st.write("Listening for network attacks...")

ui = st.empty()

while True:
    try:
        res = requests.get("http://127.0.0.1:8000/latest", timeout=10)
        data = res.json()
        history = data.get("history", [])

        with ui.container():
            if history:
                st.error(f"🚨 {len(history)} Attack Alerts Detected")

                latest = history[0]
                det = latest["details"]

                st.header(f"🔥 Latest Attack ({latest['timestamp']})")
                c1, c2 = st.columns([1, 2])
                with c1:
                    st.metric("Risk Level", det["overall_risk_level"].upper())
                    st.write(f"**Confidence:** {det['confidence_score']}")
                with c2:
                    st.subheader("📝 Executive Summary")
                    st.info(det["executive_summary"])

                st.subheader("🎯 MITRE ATT&CK Techniques")
                st.code("\n".join(det["attack_patterns"]))

                st.subheader("🚀 Recommendations")
                for rec in det["recommendations"]:
                    st.warning(f"{rec['priority'].upper()} – {rec['action']}")

                if len(history) > 1:
                    st.markdown("---")
                    st.subheader("📚 All Attack Alerts")
                    for incident in history[1:]:
                        d = incident["details"]
                        with st.expander(f"⚠️ {incident['timestamp']} – TYPE: {incident['type']}"):
                            st.write("### Executive Summary")
                            st.info(d["executive_summary"])
                            st.write("### MITRE ATT&CK Patterns")
                            st.code("\n".join(d["attack_patterns"]))
                            st.write("### Recommendations")
                            for rec in d["recommendations"]:
                                st.warning(f"{rec['priority'].upper()} – {rec['action']}")
            else:
                st.success("✅ System Secure. No attacks detected.")
    except Exception:
        with ui.container():
            st.warning("⏳ Waiting for backend connection...")
    time.sleep(2)
