# ui/components/threat_cards.py
# GOAL: Display the threat analysis results as clean visual cards
# Takes the analyzed data from threat_analyzer.py and shows it nicely

import streamlit as st

def render_threat_cards(analysis):
    """
    analysis is the dictionary returned by threat_analyzer.analyze_threat()
    It contains: ip, score, reports, country, isp, domain,
                 risk_level, color, emoji, recommendation
    """

    st.markdown("---")
    st.markdown("### 📊 Threat Analysis Results")

    # --- Top row: 4 metric cards ---
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="🌐 IP Address",
            value=analysis["ip"]
        )

    with col2:
        st.metric(
            label="⚡ Abuse Score",
            value=f"{analysis['score']} / 100",
            delta=None
        )

    with col3:
        st.metric(
            label="📋 Total Reports",
            value=f"{analysis['reports']:,}"
        )

    with col4:
        st.metric(
            label="🌍 Country",
            value=analysis["country"]
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Risk level banner ---
    score = analysis["score"]

    # Choose background color for the banner based on risk
    if score == 0:
        banner_color = "#166534"    # dark green
        text_color   = "#bbf7d0"    # light green text
    elif score < 25:
        banner_color = "#1e3a5f"    # dark blue
        text_color   = "#bfdbfe"
    elif score < 50:
        banner_color = "#7c2d12"    # dark orange
        text_color   = "#fed7aa"
    elif score < 75:
        banner_color = "#7f1d1d"    # dark red
        text_color   = "#fecaca"
    else:
        banner_color = "#450a0a"    # very dark red
        text_color   = "#fca5a5"

    st.markdown(
        f"""
        <div style="
            background-color: {banner_color};
            border-radius: 12px;
            padding: 20px 28px;
            margin-bottom: 16px;
        ">
            <h2 style="color: {text_color}; margin: 0 0 6px 0;">
                {analysis['emoji']} {analysis['risk_level']}
            </h2>
            <p style="color: {text_color}; margin: 0; font-size: 15px; opacity: 0.9;">
                {analysis['recommendation']}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # --- Detail row: ISP and Domain ---
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**🏢 ISP / Organization**")
        st.code(analysis["isp"], language=None)

    with col_b:
        st.markdown("**🔗 Domain**")
        st.code(analysis["domain"] if analysis["domain"] != "N/A" else "No domain found", language=None)

    st.markdown("---")


def render_empty_state():
    """
    Shows a placeholder message when no IP has been searched yet.
    """
    st.markdown("<br>", unsafe_allow_html=True)
    st.info("👆 Enter an IP address above and click Search to see threat analysis results.")


# --- TEST ---
if __name__ == "__main__":
    st.set_page_config(page_title="Cards Test", layout="wide")
    st.title("Threat Cards Component Test")

    # Simulate a dangerous IP result
    fake_analysis = {
        "ip":             "185.220.101.1",
        "score":          95,
        "reports":        1200,
        "country":        "DE",
        "isp":            "Tor Network",
        "domain":         "N/A",
        "risk_level":     "Dangerous",
        "color":          "darkred",
        "emoji":          "🚨",
        "recommendation": "Extremely dangerous IP. Block immediately.",
    }

    render_threat_cards(fake_analysis)