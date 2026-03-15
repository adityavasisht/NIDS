import os
import time

import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="NIDS Monitor", layout="wide")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
    html, body, [class*="css"] {
        font-family: 'Rajdhani', sans-serif;
        background-color: #0a0e17;
        color: #c9d1e3;
    }
    .stApp { background-color: #0a0e17; }
    h1, h2, h3 { font-family: 'Share Tech Mono', monospace !important; }
    .metric-card {
        background: linear-gradient(135deg, #111827, #1a2236);
        border: 1px solid #1e2d45;
        border-radius: 8px;
        padding: 16px 20px;
        text-align: center;
    }
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        font-family: 'Share Tech Mono', monospace;
    }
    .metric-label {
        font-size: 0.78rem;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: #5a6a8a;
        margin-top: 4px;
    }
    .metric-total   .metric-value { color: #60a5fa; }
    .metric-normal  .metric-value { color: #22d3a0; }
    .metric-anomaly .metric-value { color: #f87171; }
    .section-header {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.72rem;
        letter-spacing: 0.2em;
        text-transform: uppercase;
        color: #3b5275;
        border-bottom: 1px solid #1e2d45;
        padding-bottom: 6px;
        margin: 22px 0 12px 0;
    }
    .threat-banner {
        background: linear-gradient(135deg, #2d0a0a, #3d1010);
        border: 1px solid #7f1d1d;
        border-left: 4px solid #ef4444;
        border-radius: 6px;
        padding: 10px 16px;
        margin-bottom: 8px;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.82rem;
        color: #fca5a5;
    }
    .stButton > button {
        background: #7f1d1d !important;
        color: #fca5a5 !important;
        border: 1px solid #ef4444 !important;
        border-radius: 4px !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.75rem !important;
        padding: 4px 12px !important;
        height: auto !important;
    }
    .stButton > button:hover { background: #991b1b !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style="display:flex;align-items:center;gap:16px;margin-bottom:24px;
            padding-bottom:16px;border-bottom:1px solid #1e2d45;">
    <div style="font-family:'Share Tech Mono',monospace;font-size:1.6rem;
                color:#60a5fa;letter-spacing:0.1em;">⬡ NIDS</div>
    <div>
        <div style="font-size:1.1rem;font-weight:700;color:#c9d1e3;
                    letter-spacing:0.05em;">Network Intrusion Detection System</div>
        <div style="font-size:0.7rem;letter-spacing:0.2em;color:#3b5275;
                    text-transform:uppercase;">Live Traffic Monitor · ML Ensemble + Heuristics Active</div>
    </div>
</div>
""", unsafe_allow_html=True)


def block_ip(ip: str):
    try:
        requests.post(f"http://127.0.0.1:4000/api/block?ip={ip}", timeout=2)
        st.toast(f"🛑 Blocked {ip}", icon="🛑")
    except Exception:
        st.toast("Server unreachable", icon="⚠️")


def style_status(val):
    if val == "anomaly":
        return "background-color:#450a0a;color:#fca5a5;font-weight:bold"
    return "background-color:#052e1c;color:#6ee7b7"


def style_method(val):
    if val == "heuristic":
        return "color:#fbbf24;font-weight:bold"
    return "color:#818cf8"


ui = st.empty()

while True:
    if os.path.exists("live_traffic.csv"):
        try:
            df = pd.read_csv("live_traffic.csv").tail(5000)  # raised from 300

            # Handle both old (4-col) and new (6-col) log formats
            if "Confidence" not in df.columns:
                df["Confidence"] = "-"
                df["Method"] = "ml"

            if not df.empty:
                normal_df  = df[df["Status"] == "normal"]
                anomaly_df = df[df["Status"] == "anomaly"]
                threat_pct = round(len(anomaly_df) / len(df) * 100, 1) if len(df) else 0

                with ui.container():
                    # ── Metrics ───────────────────────────────────────────
                    c1, c2, c3, c4 = st.columns(4)
                    with c1:
                        st.markdown(f"""
                        <div class="metric-card metric-total">
                            <div class="metric-value">{len(df)}</div>
                            <div class="metric-label">Total Scanned</div>
                        </div>""", unsafe_allow_html=True)
                    with c2:
                        st.markdown(f"""
                        <div class="metric-card metric-normal">
                            <div class="metric-value">{len(normal_df)}</div>
                            <div class="metric-label">Normal Traffic</div>
                        </div>""", unsafe_allow_html=True)
                    with c3:
                        st.markdown(f"""
                        <div class="metric-card metric-anomaly">
                            <div class="metric-value">{len(anomaly_df)}</div>
                            <div class="metric-label">Anomalies / Attacks</div>
                        </div>""", unsafe_allow_html=True)
                    with c4:
                        status_color = "#f87171" if threat_pct > 10 else "#22d3a0"
                        status_text  = "⚠ ALERT"  if threat_pct > 10 else "● SECURE"
                        st.markdown(f"""
                        <div class="metric-card" style="background:linear-gradient(135deg,#111827,#1a2236);
                             border:1px solid #1e2d45;border-radius:8px;padding:16px 20px;text-align:center;">
                            <div class="metric-value" style="color:{status_color};font-size:1.3rem;">
                                {status_text}
                            </div>
                            <div class="metric-label">Threat Rate: {threat_pct}%</div>
                        </div>""", unsafe_allow_html=True)

                    # ── Active threat banners ─────────────────────────────
                    if not anomaly_df.empty:
                        st.markdown(
                            '<div class="section-header">⚠ Active Intrusions Detected</div>',
                            unsafe_allow_html=True
                        )
                        for ip in anomaly_df["Source_IP"].unique()[-5:]:
                            ip_rows   = anomaly_df[anomaly_df["Source_IP"] == ip]
                            count     = len(ip_rows)
                            last_seen = ip_rows["Time"].iloc[-1]
                            col_info, col_btn = st.columns([5, 1])
                            with col_info:
                                st.markdown(f"""
                                <div class="threat-banner">
                                    🔴 <strong>{ip}</strong>
                                    &nbsp;·&nbsp; {count} malicious packet(s)
                                    &nbsp;·&nbsp; Last: {last_seen}
                                </div>""", unsafe_allow_html=True)
                            with col_btn:
                                st.write("")
                                if st.button("BLOCK", key=f"block_{ip}"):
                                    block_ip(ip)

                    # ── Traffic feed tabs ─────────────────────────────────
                    st.markdown(
                        '<div class="section-header">📡 Traffic Feed</div>',
                        unsafe_allow_html=True
                    )

                    tab_all, tab_normal, tab_anomaly = st.tabs([
                        f"ALL ({len(df)})",
                        f"✓ NORMAL ({len(normal_df)})",
                        f"✗ ANOMALY ({len(anomaly_df)})",
                    ])

                    display_cols = ["Time", "Source_IP", "Protocol", "Status", "Confidence", "Method"]

                    with tab_all:
                        view = df[display_cols].tail(50).iloc[::-1]
                        st.dataframe(
                            view.style
                                .applymap(style_status, subset=["Status"])
                                .applymap(style_method, subset=["Method"]),
                            use_container_width=True, hide_index=True,
                        )

                    with tab_normal:
                        if not normal_df.empty:
                            view = normal_df[display_cols].tail(50).iloc[::-1]
                            st.dataframe(
                                view.style
                                    .applymap(style_status, subset=["Status"])
                                    .applymap(style_method, subset=["Method"]),
                                use_container_width=True, hide_index=True,
                            )
                        else:
                            st.info("No normal traffic recorded yet.")

                    with tab_anomaly:
                        if not anomaly_df.empty:
                            view = anomaly_df[display_cols].tail(50).iloc[::-1]
                            st.dataframe(
                                view.style
                                    .applymap(style_status, subset=["Status"])
                                    .applymap(style_method, subset=["Method"]),
                                use_container_width=True, hide_index=True,
                            )
                        else:
                            st.success("✓ No anomalies detected.")

            else:
                ui.info("⏳ Waiting for first packet…")

        except Exception:
            pass

    time.sleep(1)