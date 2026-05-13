# ui/components/charts.py
# GOAL: Create visual charts for the dashboard
# Shows abuse score gauge, history bar chart, and risk distribution pie chart

import streamlit as st
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import json
import os

# -------------------------------------------------------
# CHART 1: Abuse Score Gauge
# Shows the score as a colored arc from 0 to 100
# -------------------------------------------------------

def render_score_gauge(score):
    """
    Draws a semicircular gauge showing the abuse score.
    Green = safe, Red = dangerous.
    """
    st.markdown("#### 🎯 Abuse Score Gauge")

    fig, ax = plt.subplots(figsize=(5, 3), subplot_kw=dict(aspect="equal"))
    fig.patch.set_facecolor("#0f172a")   # dark background
    ax.set_facecolor("#0f172a")

    # Draw background arc (full gray semicircle)
    theta = np.linspace(np.pi, 0, 200)
    ax.plot(np.cos(theta), np.sin(theta), color="#334155", linewidth=18, solid_capstyle="round")

    # Color based on score
    if score == 0:        arc_color = "#22c55e"
    elif score < 25:      arc_color = "#3b82f6"
    elif score < 50:      arc_color = "#f97316"
    elif score < 75:      arc_color = "#ef4444"
    else:                 arc_color = "#7f1d1d"

    # Draw colored arc up to the score value
    filled_angle = np.pi - (score / 100) * np.pi
    theta_filled = np.linspace(np.pi, filled_angle, 200)
    ax.plot(np.cos(theta_filled), np.sin(theta_filled),
            color=arc_color, linewidth=18, solid_capstyle="round")

    # Score text in the center
    ax.text(0, -0.15, str(score), ha="center", va="center",
            fontsize=36, fontweight="bold", color="white")
    ax.text(0, -0.45, "/ 100", ha="center", va="center",
            fontsize=13, color="#94a3b8")

    ax.set_xlim(-1.3, 1.3)
    ax.set_ylim(-0.6, 1.2)
    ax.axis("off")

    st.pyplot(fig)
    plt.close()


# -------------------------------------------------------
# CHART 2: Search History Bar Chart
# Shows the last N searches and their scores
# -------------------------------------------------------

def render_history_chart(history_path="data/history.json"):
    """
    Reads the search history file and draws a bar chart
    showing abuse scores for each previously searched IP.
    """
    st.markdown("#### 📈 Search History — Abuse Scores")

    # Load history
    if not os.path.exists(history_path):
        st.info("No search history yet. Search some IPs to see them here.")
        return

    with open(history_path, "r") as f:
        history = json.load(f)

    if not history:
        st.info("No search history yet.")
        return

    # Only show last 8 searches
    recent = history[-8:]
    ips    = [entry["ip"]    for entry in recent]
    scores = [entry["score"] for entry in recent]
    colors = []

    for s in scores:
        if s == 0:       colors.append("#22c55e")
        elif s < 25:     colors.append("#3b82f6")
        elif s < 50:     colors.append("#f97316")
        elif s < 75:     colors.append("#ef4444")
        else:            colors.append("#7f1d1d")

    fig, ax = plt.subplots(figsize=(8, 3.5))
    fig.patch.set_facecolor("#0f172a")
    ax.set_facecolor("#0f172a")

    bars = ax.bar(ips, scores, color=colors, edgecolor="#1e293b", linewidth=0.8, width=0.6)

    # Score labels on top of each bar
    for bar, score in zip(bars, scores):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 1.5,
                str(score),
                ha="center", va="bottom",
                color="white", fontsize=9)

    ax.set_ylim(0, 110)
    ax.set_ylabel("Abuse Score", color="#94a3b8", fontsize=10)
    ax.set_xlabel("IP Address",  color="#94a3b8", fontsize=10)
    ax.tick_params(colors="#94a3b8", labelsize=8)
    ax.spines["bottom"].set_color("#334155")
    ax.spines["left"].set_color("#334155")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_facecolor("#0f172a")

    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()

    st.pyplot(fig)
    plt.close()


# -------------------------------------------------------
# CHART 3: Risk Distribution Pie Chart
# Shows breakdown of all searches by risk category
# -------------------------------------------------------

def render_risk_pie(history_path="data/history.json"):
    """
    Reads history and shows a pie chart of how many IPs
    fell into each risk category.
    """
    st.markdown("#### 🥧 Risk Distribution")

    if not os.path.exists(history_path):
        st.info("No data yet.")
        return

    with open(history_path, "r") as f:
        history = json.load(f)

    if not history:
        st.info("No data yet.")
        return

    # Count each category
    counts = {"Safe": 0, "Low Risk": 0, "Suspicious": 0, "High Risk": 0, "Dangerous": 0}

    for entry in history:
        score = entry.get("score", 0)
        if score == 0:       counts["Safe"]      += 1
        elif score < 25:     counts["Low Risk"]  += 1
        elif score < 50:     counts["Suspicious"] += 1
        elif score < 75:     counts["High Risk"]  += 1
        else:                counts["Dangerous"]  += 1

    # Remove empty categories
    labels = [k for k, v in counts.items() if v > 0]
    values = [v for v in counts.values()   if v > 0]
    colors = {
        "Safe":       "#22c55e",
        "Low Risk":   "#3b82f6",
        "Suspicious": "#f97316",
        "High Risk":  "#ef4444",
        "Dangerous":  "#7f1d1d"
    }
    pie_colors = [colors[l] for l in labels]

    fig, ax = plt.subplots(figsize=(4, 4))
    fig.patch.set_facecolor("#0f172a")
    ax.set_facecolor("#0f172a")

    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        colors=pie_colors,
        autopct="%1.0f%%",
        startangle=140,
        textprops={"color": "white", "fontsize": 9},
        wedgeprops={"edgecolor": "#0f172a", "linewidth": 2}
    )

    for at in autotexts:
        at.set_color("white")
        at.set_fontsize(8)

    ax.set_title("All Searched IPs by Risk", color="#94a3b8", fontsize=10, pad=10)
    plt.tight_layout()

    st.pyplot(fig)
    plt.close()


# --- TEST ---
if __name__ == "__main__":
    st.set_page_config(page_title="Charts Test", layout="wide")
    st.title("Charts Component Test")

    col1, col2 = st.columns(2)
    with col1:
        render_score_gauge(75)
    with col2:
        render_score_gauge(0)