import streamlit as st
import json
import os
import sys

# Add parent folder to path so we can import from core/ and ui/components/
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.ip_lookup import check_ip, save_history, save_dangerous
from core.threat_analyzer import analyze_threat
from ui.components.searchbar   import render_search_bar
from ui.components.threatcards import render_threat_cards, render_empty_state
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
# CUSTOM CSS STYLING
# -------------------------------------------------------

st.markdown("""
<style>
    /* Dark background */
    .stApp {
        background-color: #0f172a;
        color: #e2e8f0;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #1e293b;
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
    }

    /* Input field */
    .stTextInput > div > div > input {
        background-color: #1e293b;
        color: #e2e8f0;
        border: 1px solid #334155;
        border-radius: 8px;
    }

    /* Button */
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

    /* Code blocks */
    .stCode {
        background-color: #1e293b !important;
    }

    /* Divider */
    hr {
        border-color: #334155;
    }
</style>
""", unsafe_allow_html=True)


# -------------------------------------------------------
# HELPER: Save search to history
# -------------------------------------------------------

def save_to_history(analysis, history_path="data/history.json"):
    """Appends a search result to the history file."""
    os.makedirs("data", exist_ok=True)

    # Load existing history
    if os.path.exists(history_path):
        with open(history_path, "r") as f:
            history = json.load(f)
    else:
        history = []

    # Add new entry (only save key fields)
    history.append({
        "ip":         analysis["ip"],
        "score":      analysis["score"],
        "risk_level": analysis["risk_level"],
        "country":    analysis["country"],
    })

    # Keep only last 50 searches
    history = history[-50:]

    with open(history_path, "w") as f:
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

    # Clear history button
    if st.button("🗑️ Clear History"):
        if os.path.exists("data/history.json"):
            os.remove("data/history.json")
            st.success("History cleared!")


# -------------------------------------------------------
# MAIN CONTENT
# -------------------------------------------------------

# Header
st.markdown("# 🛡️ Threat Intelligence Dashboard")
st.markdown("*Real-time IP reputation analysis powered by AbuseIPDB*")
st.markdown("---")

# Search bar — returns an IP string if user clicked search, else None
searched_ip = render_search_bar()

# If user searched an IP
if searched_ip:
    with st.spinner(f"Looking up {searched_ip}..."):
        # Step 1: Get raw data from API (or fallback to sample data)
        raw_data = lookup_ip(searched_ip)

        # Step 2: Analyze and classify the threat
        analysis = analyze_threat(raw_data)

        # Step 3: Save to history
        save_to_history(analysis)

    # Step 4: Show results
    # Top row: cards + gauge side by side
    results_col, gauge_col = st.columns([3, 1])

    with results_col:
        render_threat_cards(analysis)

    with gauge_col:
        st.markdown("<br><br>", unsafe_allow_html=True)
        render_score_gauge(analysis["score"])

else:
    # No search yet — show placeholder
    render_empty_state()

# -------------------------------------------------------
# CHARTS SECTION — always visible at the bottom
# -------------------------------------------------------

st.markdown("---")
st.markdown("### 📊 Dashboard Analytics")

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    render_history_chart()

with chart_col2:
    render_risk_pie()