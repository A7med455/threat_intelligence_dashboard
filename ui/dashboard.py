# ui/dashboard.py
# GOAL: Main dashboard — wires all UI components together

import streamlit as st
import json
import os
import sys

# Add parent folder to path so Python finds all folders
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "ui", "components"))

# File paths
HISTORY_PATH = os.path.join(PROJECT_ROOT, "data", "history.json")

# SIMPLE IMPORTS - no __init__.py needed
from core.ip_lookup import lookup_ip
from core.threat_analyzer import analyze_threat
from searchbar import render_search_bar
from threatcards import render_threat_cards, render_empty_state
from charts import render_score_gauge, render_history_chart, render_risk_pie

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
# CUSTOM CSS STYLING
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
    hr {
        border-color: #334155;
    }
</style>
""", unsafe_allow_html=True)


# -------------------------------------------------------
# HELPER: Save search to history
# -------------------------------------------------------

def save_to_history(analysis):
    """Appends a search result to the history file."""
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)

    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH, "r") as f:
            history = json.load(f)
    else:
        history = []

    history.append({
        "ip": analysis["ip"],
        "score": analysis["score"],
        "risk_level": analysis["risk_level"],
        "country": analysis["country"],
    })

    history = history[-50:]

    with open(HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=2)


# -------------------------------------------------------
# SIDEBAR
# -------------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ Threat Intel")
    st.markdown("---")
    st.markdown("**About this tool**")
    st.markdown(
        "This dashboard looks up IP addresses against the "
        "AbuseIPDB database and classifies their threat level."
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
        if os.path.exists(HISTORY_PATH):
            os.remove(HISTORY_PATH)
            st.success("History cleared!")
        else:
            st.info("No history to clear.")


# -------------------------------------------------------
# MAIN CONTENT
# -------------------------------------------------------

st.markdown("# 🛡️ Threat Intelligence Dashboard")
st.markdown("*Real-time IP reputation analysis powered by AbuseIPDB*")
st.markdown("---")

searched_ip = render_search_bar()

if searched_ip:
    with st.spinner(f"Looking up {searched_ip}..."):
        raw_data = lookup_ip(searched_ip)
        analysis = analyze_threat(raw_data)
        save_to_history(analysis)

    results_col, gauge_col = st.columns([3, 1])

    with results_col:
        render_threat_cards(analysis)

    with gauge_col:
        st.markdown("<br><br>", unsafe_allow_html=True)
        render_score_gauge(analysis["score"])

else:
    render_empty_state()


# -------------------------------------------------------
# CHARTS SECTION
# -------------------------------------------------------

st.markdown("---")
st.markdown("### 📊 Dashboard Analytics")

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    render_history_chart()

with chart_col2:
    render_risk_pie()