# ui/dashboard.py
# GOAL: Main dashboard — wires all UI components together

import streamlit as st
import json
import os
import sys

# Add parent folder to path so Python finds all folders
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# File paths
HISTORY_PATH = os.path.join(PROJECT_ROOT, "data", "history.json")
FLAGGED_PATH = os.path.join(PROJECT_ROOT, "data", "flagged_ips.json")

# IMPORTS
from core.ip_lookup import lookup_ip
from core.threat_analyzer import analyze_threat
from core.password_checker import check_strength
from core.caesar_cipher import encrypt, decrypt, brute_force_decrypt
from core.report_generator import generate_txt_report, generate_json_report, generate_csv_report
from core.alert_system import check_and_alert, get_all_flagged, clear_flagged, remove_flag
from ui.components.searchbar import render_search_bar
from ui.components.threatcards import render_threat_cards, render_empty_state
from ui.components.charts import render_score_gauge, render_history_chart, render_risk_pie

# -------------------------------------------------------
# PAGE CONFIGURATION
# -------------------------------------------------------

st.set_page_config(
    page_title="Cyber Security Toolkit",
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
    .flagged-ip {
        background-color: #7f1d1d;
        border-radius: 8px;
        padding: 10px;
        margin: 5px 0;
    }
</style>
""", unsafe_allow_html=True)


# -------------------------------------------------------
# HELPER: Save search to history AND check alert
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
    st.markdown("## 🛡️ Cyber Toolkit")
    st.markdown("---")
    st.markdown("**About**")
    st.markdown(
        "This toolkit combines:\n"
        "- IP reputation checking\n"
        "- Password strength analysis\n"
        "- Caesar cipher encryption\n"
        "- Report generation\n"
        "- Alert system for dangerous IPs"
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
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🗑️ Clear History", use_container_width=True):
            if os.path.exists(HISTORY_PATH):
                os.remove(HISTORY_PATH)
                st.success("History cleared!")
            else:
                st.info("No history to clear.")
    
    with col2:
        if st.button("🚨 Clear Alerts", use_container_width=True):
            clear_flagged()
            st.success("All alerts cleared!")


# -------------------------------------------------------
# MAIN CONTENT WITH TABS
# -------------------------------------------------------

st.markdown("# 🛡️ Cyber Security Toolkit")
st.markdown("*IP Threat Intelligence | Password Checker | Caesar Cipher | Reports & Alerts*")
st.markdown("---")

# Create tabs for each tool
tab1, tab2, tab3, tab4 = st.tabs(["🔍 IP Threat Lookup", "🔐 Password Checker", "🔒 Caesar Cipher", "📋 Reports & Alerts"])

# ============================================================
# TAB 1: IP THREAT LOOKUP
# ============================================================

with tab1:
    st.markdown("### 🔍 IP Threat Lookup")
    st.markdown("Enter an IP address to check its abuse reputation and threat level.")
    
    searched_ip = render_search_bar()
    
    if searched_ip:
        with st.spinner(f"Looking up {searched_ip}..."):
            raw_data = lookup_ip(searched_ip)
            analysis = analyze_threat(raw_data)
            save_to_history(analysis)
            
            # Check alert system
            alert_result = check_and_alert(raw_data)
            if alert_result["alert_triggered"]:
                st.error(f"🚨 {alert_result['message']}")
        
        results_col, gauge_col = st.columns([3, 1])
        
        with results_col:
            render_threat_cards(analysis)
            
            # Report generation buttons
            st.markdown("---")
            st.markdown("### 📄 Generate Report")
            col_r1, col_r2, col_r3 = st.columns(3)
            
            with col_r1:
                if st.button("📝 TXT Report", use_container_width=True):
                    report_path = generate_txt_report(analysis)
                    st.success(f"Report saved to: {report_path}")
            
            with col_r2:
                if st.button("📊 JSON Report", use_container_width=True):
                    report_path = generate_json_report(analysis)
                    st.success(f"Report saved to: {report_path}")
            
            with col_r3:
                if st.button("📑 Full Report (TXT+JSON)", use_container_width=True):
                    paths = save_full_report(analysis)
                    st.success(f"TXT: {paths['txt']}")
                    st.success(f"JSON: {paths['json']}")
        
        with gauge_col:
            st.markdown("<br><br>", unsafe_allow_html=True)
            render_score_gauge(analysis["score"])
    
    else:
        render_empty_state()
    
    # Charts section
    st.markdown("---")
    st.markdown("### 📊 Dashboard Analytics")
    
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        render_history_chart()
    
    with chart_col2:
        render_risk_pie()

# ============================================================
# TAB 2: PASSWORD STRENGTH CHECKER
# ============================================================

with tab2:
    st.markdown("### 🔐 Password Strength Checker")
    st.markdown("Check how strong your password is and get tips to improve it.")
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        password = st.text_input(
            "Enter your password:", 
            type="password", 
            placeholder="Type a password to check...",
            key="password_input"
        )
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("✅ Check Strength", use_container_width=True):
            if password:
                result = check_strength(password)
                
                if result['strength'] == "Strong":
                    st.success(f"### 💪 STRONG PASSWORD")
                    st.success(f"Score: {result['score']}/{result['max_score']}")
                elif result['strength'] == "Medium":
                    st.warning(f"### ⚠️ MEDIUM PASSWORD")
                    st.warning(f"Score: {result['score']}/{result['max_score']}")
                else:
                    st.error(f"### ❌ WEAK PASSWORD")
                    st.error(f"Score: {result['score']}/{result['max_score']}")
                
                st.progress(result['score'] / result['max_score'])
                
                st.markdown("---")
                st.markdown("**Feedback & Tips:**")
                for fb in result['feedback']:
                    if "✅" in fb:
                        st.success(fb)
                    elif "⚠️" in fb:
                        st.warning(fb)
                    else:
                        st.info(fb)
            else:
                st.warning("Please enter a password first.")
    
    with st.expander("📝 Tips for a Strong Password"):
        st.markdown("""
        **What makes a password strong?**
        - ✅ **Length:** At least 12 characters
        - ✅ **Uppercase letters:** A, B, C...
        - ✅ **Lowercase letters:** a, b, c...
        - ✅ **Numbers:** 0, 1, 2, 3...
        - ✅ **Special characters:** !@#$%^&*()
        """)

# ============================================================
# TAB 3: CAESAR CIPHER TOOL
# ============================================================

with tab3:
    st.markdown("### 🔒 Caesar Cipher Tool")
    st.markdown("Encrypt or decrypt messages using the Caesar cipher method.")
    st.markdown("---")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        cipher_text = st.text_area(
            "Enter your message:", 
            placeholder="Type something here...", 
            key="cipher_input",
            height=100
        )
    
    with col2:
        cipher_key = st.slider("Shift Key (1-25):", 1, 25, 3)
    
    btn_col1, btn_col2 = st.columns(2)
    
    with btn_col1:
        if st.button("🔒 Encrypt", use_container_width=True):
            if cipher_text:
                encrypted = encrypt(cipher_text, cipher_key)
                st.code(encrypted, language="text")
                st.success(f"Encrypted with key {cipher_key}")
            else:
                st.warning("Enter a message first.")
    
    with btn_col2:
        if st.button("🔓 Decrypt", use_container_width=True):
            if cipher_text:
                decrypted = decrypt(cipher_text, cipher_key)
                st.code(decrypted, language="text")
                st.success(f"Decrypted with key {cipher_key}")
            else:
                st.warning("Enter a message first.")
    
    with st.expander("🔍 Brute Force Attack"):
        if st.button("Try All 25 Keys"):
            if cipher_text:
                results = brute_force_decrypt(cipher_text)
                for r in results:
                    if "the" in r['text'].lower() or "hello" in r['text'].lower():
                        st.markdown(f"✅ **Key {r['key']:2d}:** `{r['text']}`")
                    else:
                        st.markdown(f"   Key {r['key']:2d}: `{r['text']}`")
            else:
                st.warning("Enter a message first.")

# ============================================================
# TAB 4: REPORTS & ALERTS
# ============================================================

with tab4:
    st.markdown("### 📋 Reports & Alert System")
    st.markdown("View flagged dangerous IPs and generate batch reports.")
    st.markdown("---")
    
    # Alert System Section
    st.markdown("#### 🚨 Flagged Dangerous IPs")
    flagged_ips = get_all_flagged()
    
    if flagged_ips:
        st.markdown(f"**Total flagged IPs:** {len(flagged_ips)}")
        
        for ip_data in flagged_ips:
            with st.container():
                st.markdown(f"""
                <div class="flagged-ip">
                    <strong>🚨 {ip_data['ip']}</strong><br>
                    Score: {ip_data['score']}/100 | Severity: {ip_data['severity']}<br>
                    Country: {ip_data['country']} | ISP: {ip_data['isp']}<br>
                    Flagged at: {ip_data['flagged_at']}
                </div>
                """, unsafe_allow_html=True)
                
                col1, col2 = st.columns([1, 5])
                with col1:
                    if st.button(f"Remove", key=f"remove_{ip_data['ip']}"):
                        remove_flag(ip_data['ip'])
                        st.rerun()
                st.markdown("---")
    else:
        st.info("No flagged IPs yet. Search for a dangerous IP (score >= 75) and it will appear here automatically!")
    
    st.markdown("---")
    
    # Batch Report Generation
    st.markdown("#### 📊 Generate Batch Report")
    st.markdown("Generate a CSV report of all searched IPs from history.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📈 Generate CSV Report", use_container_width=True):
            if os.path.exists(HISTORY_PATH):
                with open(HISTORY_PATH, "r") as f:
                    history = json.load(f)
                
                if history:
                    # Convert history to format needed for CSV
                    history_for_csv = []
                    for entry in history:
                        history_for_csv.append({
                            "ip": entry.get("ip", "Unknown"),
                            "score": entry.get("score", 0),
                            "risk_level": entry.get("risk_level", "Unknown"),
                            "country": entry.get("country", "Unknown"),
                            "isp": entry.get("isp", "Unknown"),
                            "reports": entry.get("reports", 0),
                            "recommendation": entry.get("recommendation", "N/A")
                        })
                    
                    csv_path = generate_csv_report(history_for_csv)
                    st.success(f"✅ CSV Report saved to: {csv_path}")
                    
                    # Provide download link
                    with open(csv_path, "r") as f:
                        csv_data = f.read()
                    st.download_button(
                        label="📥 Download CSV Report",
                        data=csv_data,
                        file_name=os.path.basename(csv_path),
                        mime="text/csv"
                    )
                else:
                    st.warning("No history found. Search some IPs first!")
            else:
                st.warning("No history file found. Search some IPs first!")
    
    with col2:
        if st.button("📋 Export Flagged IPs (JSON)", use_container_width=True):
            if flagged_ips:
                import tempfile
                temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
                json.dump(flagged_ips, temp_file, indent=4)
                temp_file.close()
                
                with open(temp_file.name, 'r') as f:
                    json_data = f.read()
                
                st.download_button(
                    label="📥 Download Flagged IPs JSON",
                    data=json_data,
                    file_name="flagged_ips_export.json",
                    mime="application/json"
                )
                st.success("Ready to download!")
            else:
                st.warning("No flagged IPs to export!")
    
    # Alert threshold info
    st.markdown("---")
    st.markdown("#### ℹ️ How the Alert System Works")
    st.markdown("""
    - Any IP with **abuse score >= 75** is automatically flagged as **Dangerous**
    - Flagged IPs appear in this tab
    - You can remove individual IPs or clear all alerts
    - The alert system helps you track malicious IPs over time
    """)

# ============================================================
# FOOTER
# ============================================================

st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #64748b; font-size: 12px;'>"
    "🛡️ Cyber Security Toolkit | IP Threat Intelligence | Password Checker | Caesar Cipher | Alerts & Reports"
    "</p>", 
    unsafe_allow_html=True
)