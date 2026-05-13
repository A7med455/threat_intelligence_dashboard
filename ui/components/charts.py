# ui/components/charts.py
# GOAL: Create visual charts for the dashboard

import streamlit as st
import matplotlib.pyplot as plt
import numpy as np
import json
import os

# Get the project root (where data folder is)
def get_history_path():
    """Returns the correct path to history.json"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(current_dir))
    return os.path.join(project_root, "data", "history.json")

# -------------------------------------------------------
# CHART 1: Abuse Score Gauge
# -------------------------------------------------------

def render_score_gauge(score):
    st.markdown("#### 🎯 Abuse Score Gauge")

    fig, ax = plt.subplots(figsize=(5, 3), subplot_kw=dict(aspect="equal"))
    fig.patch.set_facecolor("#0f172a")
    ax.set_facecolor("#0f172a")

    theta = np.linspace(np.pi, 0, 200)
    ax.plot(np.cos(theta), np.sin(theta), color="#334155", linewidth=18, solid_capstyle="round")

    if score == 0:
        arc_color = "#22c55e"
    elif score < 25:
        arc_color = "#3b82f6"
    elif score < 50:
        arc_color = "#f97316"
    elif score < 75:
        arc_color = "#ef4444"
    else:
        arc_color = "#7f1d1d"

    filled_angle = np.pi - (score / 100) * np.pi
    theta_filled = np.linspace(np.pi, filled_angle, 200)
    ax.plot(np.cos(theta_filled), np.sin(theta_filled),
            color=arc_color, linewidth=18, solid_capstyle="round")

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
# -------------------------------------------------------

def render_history_chart():
    st.markdown("#### 📈 Search History — Abuse Scores")

    history_path = get_history_path()

    if not os.path.exists(history_path):
        st.info("No search history yet. Search some IPs to see them here.")
        return

    with open(history_path, "r") as f:
        history = json.load(f)

    if not history:
        st.info("No search history yet.")
        return

    recent = history[-8:]
    ips = [entry["ip"] for entry in recent]
    scores = [entry["score"] for entry in recent]
    colors = []

    for s in scores:
        if s == 0:
            colors.append("#22c55e")
        elif s < 25:
            colors.append("#3b82f6")
        elif s < 50:
            colors.append("#f97316")
        elif s < 75:
            colors.append("#ef4444")
        else:
            colors.append("#7f1d1d")

    fig, ax = plt.subplots(figsize=(8, 3.5))
    fig.patch.set_facecolor("#0f172a")
    ax.set_facecolor("#0f172a")

    bars = ax.bar(ips, scores, color=colors, edgecolor="#1e293b", linewidth=0.8, width=0.6)

    for bar, score in zip(bars, scores):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 1.5,
                str(score),
                ha="center", va="bottom",
                color="white", fontsize=9)

    ax.set_ylim(0, 110)
    ax.set_ylabel("Abuse Score", color="#94a3b8", fontsize=10)
    ax.set_xlabel("IP Address", color="#94a3b8", fontsize=10)
    ax.tick_params(colors="#94a3b8", labelsize=8)
    ax.spines["bottom"].set_color("#334155")
    ax.spines["left"].set_color("#334155")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()

    st.pyplot(fig)
    plt.close()


# -------------------------------------------------------
# CHART 3: Risk Distribution Pie Chart
# -------------------------------------------------------

def render_risk_pie():
    st.markdown("#### 🥧 Risk Distribution")

    history_path = get_history_path()

    if not os.path.exists(history_path):
        st.info("No data yet.")
        return

    with open(history_path, "r") as f:
        history = json.load(f)

    if not history:
        st.info("No data yet.")
        return

    counts = {"Safe": 0, "Low Risk": 0, "Suspicious": 0, "High Risk": 0, "Dangerous": 0}

    for entry in history:
        score = entry.get("score", 0)
        if score == 0:
            counts["Safe"] += 1
        elif score < 25:
            counts["Low Risk"] += 1
        elif score < 50:
            counts["Suspicious"] += 1
        elif score < 75:
            counts["High Risk"] += 1
        else:
            counts["Dangerous"] += 1

    labels = [k for k, v in counts.items() if v > 0]
    values = [v for v in counts.values() if v > 0]
    colors = {
        "Safe": "#22c55e",
        "Low Risk": "#3b82f6",
        "Suspicious": "#f97316",
        "High Risk": "#ef4444",
        "Dangerous": "#7f1d1d"
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