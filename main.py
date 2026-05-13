# main.py
# GOAL: Entry point of the entire project
# Connects all modules and launches the Streamlit dashboard
# Run with: python -m streamlit run main.py

import streamlit as st
import json
import os
import sys

# Make sure Python can find our folders
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.ip_lookup             import lookup_ip
from core.threat_analyzer       import analyze_threat
from core.report_generator      import generate_report
from core.alert_system          import check_and_alert
from core.hash_generator        import hash_value
from core.hash_comparator       import compare_hashes
from ui.components.search_bar   import render_search_bar
from ui.components.threat_cards import render_threat_cards, render_empty_state
from ui.components.charts       import render_score_gauge, render_history_chart, render_risk_pie

# -------------------------------------------------------
# PAGE CONFIGURATION
# -------------------------------------------------------

st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------------------------------
# CUSTOM CSS
# -------------------------------------------------------

st.markdown("""
<style>
    .stApp {
        background-color: #0f172a;
        color: #e2e8f0;
    }
    [data-testid="stSidebar"] {
        background-color: #1e293b;
    }
    [data-testid="stMetric"] {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
    }
    .stTextInput > div > div > input {
        background-color: #1e293b;
        color: #e2e8f0;
        border: 1px solid #334155;
        border-radius: 8px;
    }
    .stButton > button {
        background-color: #3b82f6;
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
    }
    .stButton > button:hover {
        background-color: #2563eb;
    }
    hr { border-color: #334155; }
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------
# HELPER: Save search to history
# -------------------------------------------------------

def save_to_history(analysis, history_path="data/history.json"):
    os.makedirs("data", exist_ok=True)

    if os.path.exists(history_path):
        with open(history_path, "r") as f:
            history = json.load(f)
    else:
        history = []

    history.append({
        "ip":         analysis["ip"],
        "score":      analysis["score"],
        "risk_level": analysis["risk_level"],
        "country":    analysis["country"],
    })

    history = history[-50:]

    with open(history_path, "w") as f:
        json.dump(history, f, indent=2)

# -------------------------------------------------------
# SIDEBAR
# -------------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ Threat Intel")
    st.markdown("---")

    # Navigation
    page = st.radio(
        "Navigate",
        ["🔍 IP Lookup", "🔐 Hash Tools", "📋 Reports"],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("**Risk Scale**")
    st.markdown("🟢 **0** — Safe")
    st.markdown("🔵 **1–24** — Low Risk")
    st.markdown("🟠 **25–49** — Suspicious")
    st.markdown("🔴 **50–74** — High Risk")
    st.markdown("🚨 **75–100** — Dangerous")
    st.markdown("---")
    st.markdown("**Quick Test IPs**")
    st.code("8.8.8.8        (Google DNS)")
    st.code("1.1.1.1        (Cloudflare)")
    st.code("185.220.101.1  (Known malicious)")
    st.markdown("---")

    if st.button("🗑️ Clear History"):
        if os.path.exists("data/history.json"):
            os.remove("data/history.json")
            st.success("History cleared!")

# -------------------------------------------------------
# PAGE 1: IP LOOKUP
# -------------------------------------------------------

if page == "🔍 IP Lookup":
    st.markdown("# 🛡️ Threat Intelligence Dashboard")
    st.markdown("*Real-time IP reputation analysis powered by AbuseIPDB*")
    st.markdown("---")

    searched_ip = render_search_bar()

    if searched_ip:
        with st.spinner(f"Looking up {searched_ip}..."):
            # Step 1: Fetch raw data from API
            raw_data = lookup_ip(searched_ip)

            # Step 2: Analyze and classify
            analysis = analyze_threat(raw_data)

            # Step 3: Check if it needs an alert
            check_and_alert(analysis)

            # Step 4: Save to history
            save_to_history(analysis)

        # Step 5: Display results
        results_col, gauge_col = st.columns([3, 1])
        with results_col:
            render_threat_cards(analysis)
        with gauge_col:
            st.markdown("<br><br>", unsafe_allow_html=True)
            render_score_gauge(analysis["score"])

        # Step 6: Report download button
        st.markdown("---")
        report_text = generate_report(analysis)
        st.download_button(
            label="📥 Download Report",
            data=report_text,
            file_name=f"report_{analysis['ip'].replace('.', '_')}.txt",
            mime="text/plain"
        )

    else:
        render_empty_state()

    # Charts always visible at the bottom
    st.markdown("---")
    st.markdown("### 📊 Dashboard Analytics")
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        render_history_chart()
    with chart_col2:
        render_risk_pie()

# -------------------------------------------------------
# PAGE 2: HASH TOOLS
# -------------------------------------------------------

elif page == "🔐 Hash Tools":
    st.markdown("# 🔐 Hash Generator & Comparator")
    st.markdown("*Generate and compare cryptographic hashes*")
    st.markdown("---")

    # Hash Generator section
    st.markdown("### Generate Hash")
    hash_input = st.text_input("Enter text to hash", placeholder="e.g. hello123")
    hash_algo  = st.selectbox("Algorithm", ["md5", "sha1", "sha256", "sha512"])

    if st.button("Generate"):
        if hash_input.strip():
            result = hash_value(hash_input.strip(), hash_algo)
            st.success(f"**{hash_algo.upper()} Hash:**")
            st.code(result, language=None)
        else:
            st.warning("Please enter some text first.")

    st.markdown("---")

    # Hash Comparator section
    st.markdown("### Compare Two Hashes (Avalanche Effect)")
    st.markdown("See how a tiny change in input creates a completely different hash.")

    col1, col2 = st.columns(2)
    with col1:
        text1 = st.text_input("First input",  placeholder="e.g. hello")
    with col2:
        text2 = st.text_input("Second input", placeholder="e.g. hello!")

    if st.button("Compare"):
        if text1.strip() and text2.strip():
            comparison = compare_hashes(text1.strip(), text2.strip(), hash_algo)
            st.markdown(f"**Input 1:** `{text1}`")
            st.code(comparison["hash1"], language=None)
            st.markdown(f"**Input 2:** `{text2}`")
            st.code(comparison["hash2"], language=None)
            st.info(f"🔢 Bits different: **{comparison['bits_different']}** out of 256")
        else:
            st.warning("Please enter both inputs.")

# -------------------------------------------------------
# PAGE 3: REPORTS
# -------------------------------------------------------

elif page == "📋 Reports":
    st.markdown("# 📋 Search History & Reports")
    st.markdown("---")

    history_path = "data/history.json"

    if not os.path.exists(history_path):
        st.info("No search history yet. Go to IP Lookup and search some IPs first.")
    else:
        with open(history_path, "r") as f:
            history = json.load(f)

        if not history:
            st.info("No search history yet.")
        else:
            st.markdown(f"**Total searches:** {len(history)}")
            st.markdown("---")

            # Show history as a table
            st.dataframe(
                data=history,
                use_container_width=True,
                column_config={
                    "ip":         st.column_config.TextColumn("IP Address"),
                    "score":      st.column_config.NumberColumn("Abuse Score", format="%d / 100"),
                    "risk_level": st.column_config.TextColumn("Risk Level"),
                    "country":    st.column_config.TextColumn("Country"),
                }
            )

            # Flagged IPs section
            flagged_path = "data/flagged_ips.json"
            if os.path.exists(flagged_path):
                with open(flagged_path, "r") as f:
                    flagged = json.load(f)

                if flagged:
                    st.markdown("---")
                    st.markdown("### 🚨 Flagged IPs")
                    st.markdown("These IPs triggered automatic alerts due to high abuse scores.")
                    for ip in flagged:
                        st.error(f"🚨 {ip}")