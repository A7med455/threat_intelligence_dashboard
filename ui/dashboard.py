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

# IMPORTS
from core.ip_lookup import lookup_ip
from core.threat_analyzer import analyze_threat
from core.password_checker import check_strength
from core.caesar_cipher import encrypt, decrypt, brute_force_decrypt
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
    .hash-box {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 15px;
        font-family: monospace;
        word-break: break-all;
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
# SIDEBAR (only for navigation and info)
# -------------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ Cyber Toolkit")
    st.markdown("---")
    st.markdown("**About**")
    st.markdown(
        "This toolkit combines:\n"
        "- IP reputation checking\n"
        "- Password strength analysis\n"
        "- Caesar cipher encryption"
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
        if os.path.exists(HISTORY_PATH):
            os.remove(HISTORY_PATH)
            st.success("History cleared!")
        else:
            st.info("No history to clear.")


# -------------------------------------------------------
# MAIN CONTENT WITH TABS
# -------------------------------------------------------

st.markdown("# 🛡️ Cyber Security Toolkit")
st.markdown("*IP Threat Intelligence | Password Strength Checker | Caesar Cipher*")
st.markdown("---")

# Create tabs for each tool
tab1, tab2, tab3 = st.tabs(["🔍 IP Threat Lookup", "🔐 Password Strength Checker", "🔒 Caesar Cipher Tool"])

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
        
        results_col, gauge_col = st.columns([3, 1])
        
        with results_col:
            render_threat_cards(analysis)
        
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
                
                # Display strength with color
                if result['strength'] == "Strong":
                    st.success(f"### 💪 STRONG PASSWORD")
                    st.success(f"Score: {result['score']}/{result['max_score']}")
                elif result['strength'] == "Medium":
                    st.warning(f"### ⚠️ MEDIUM PASSWORD")
                    st.warning(f"Score: {result['score']}/{result['max_score']}")
                else:
                    st.error(f"### ❌ WEAK PASSWORD")
                    st.error(f"Score: {result['score']}/{result['max_score']}")
                
                # Progress bar
                st.progress(result['score'] / result['max_score'])
                
                # Feedback
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
    
    # Password tips
    with st.expander("📝 Tips for a Strong Password"):
        st.markdown("""
        **What makes a password strong?**
        
        - ✅ **Length:** At least 12 characters
        - ✅ **Uppercase letters:** A, B, C...
        - ✅ **Lowercase letters:** a, b, c...
        - ✅ **Numbers:** 0, 1, 2, 3...
        - ✅ **Special characters:** !@#$%^&*()
        
        **Examples of strong passwords:**
        - `MyD0g!sGr3at!2024`
        - `C0ffee$M0rning!`
        - `Blue$ky!Sun$hine`
        
        **Never use:**
        - ❌ `password`
        - ❌ `123456`
        - ❌ `qwerty`
        - ❌ Your name or birthday
        """)

# ============================================================
# TAB 3: CAESAR CIPHER TOOL
# ============================================================

with tab3:
    st.markdown("### 🔒 Caesar Cipher Tool")
    st.markdown("Encrypt or decrypt messages using the Caesar cipher method (shifts letters by a key).")
    st.markdown("---")
    
    # Input area
    col1, col2 = st.columns([3, 1])
    
    with col1:
        cipher_text = st.text_area(
            "Enter your message:", 
            placeholder="Type something here... e.g., Hello World", 
            key="cipher_input",
            height=100
        )
    
    with col2:
        st.markdown("**Settings**")
        cipher_key = st.slider("Shift Key (1-25):", 1, 25, 3)
        st.caption(f"Key {cipher_key} means A → {chr(65 + cipher_key)}")
    
    # Action buttons
    btn_col1, btn_col2 = st.columns(2)
    
    with btn_col1:
        if st.button("🔒 Encrypt", use_container_width=True, key="encrypt_btn"):
            if cipher_text:
                encrypted = encrypt(cipher_text, cipher_key)
                st.markdown("**🔐 Encrypted Result:**")
                st.code(encrypted, language="text")
                st.success(f"✅ Encrypted with key {cipher_key}")
            else:
                st.warning("⚠️ Please enter a message first.")
    
    with btn_col2:
        if st.button("🔓 Decrypt", use_container_width=True, key="decrypt_btn"):
            if cipher_text:
                decrypted = decrypt(cipher_text, cipher_key)
                st.markdown("**🔓 Decrypted Result:**")
                st.code(decrypted, language="text")
                st.success(f"✅ Decrypted with key {cipher_key}")
            else:
                st.warning("⚠️ Please enter a message first.")
    
    # Brute force attack section
    st.markdown("---")
    with st.expander("🔍 Brute Force Attack - Why Caesar Cipher is NOT secure"):
        st.markdown("""
        **The Problem with Caesar Cipher:**  
        A brute force attack tries all 25 possible keys and finds the message instantly!
        
        This demonstrates why modern encryption (like AES) is needed for real security.
        """)
        
        if st.button("🚀 Try All 25 Keys (Brute Force)", use_container_width=True):
            if cipher_text:
                results = brute_force_decrypt(cipher_text)
                st.markdown("**All possible decryptions:**")
                
                found = False
                for r in results:
                    # Highlight likely English text
                    if "the" in r['text'].lower() or "and" in r['text'].lower() or "hello" in r['text'].lower() or "world" in r['text'].lower():
                        st.markdown(f"✅ **Key {r['key']:2d}:** `{r['text']}` ← Likely correct!")
                        found = True
                    else:
                        st.markdown(f"   Key {r['key']:2d}: `{r['text']}`")
                
                if not found:
                    st.info("No obvious English text found. The message might be encrypted or not in English.")
            else:
                st.warning("⚠️ Please enter an encrypted message above first.")
        
        st.caption("💡 Notice how quickly you can find the original message! This is why Caesar cipher is only used for learning, not real security.")

# ============================================================
# FOOTER
# ============================================================

st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #64748b; font-size: 12px;'>"
    "🛡️ Cyber Security Toolkit | IP Threat Intelligence | Password Checker | Caesar Cipher"
    "</p>", 
    unsafe_allow_html=True
)