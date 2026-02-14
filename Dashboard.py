import streamlit as st
import pandas as pd
import plotly.express as px
import time

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="SOC Threat Dashboard",
    layout="wide",
    page_icon="🛡️"
)

# ---------------- DARK SOC STYLE ----------------
st.markdown("""
<style>
.main { background-color: #0E1117; }
h1, h2, h3 { color: white; }
[data-testid="stMetricValue"] { font-size: 32px; }
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------
st.title("🛡️ Security Operations Center Dashboard")
st.caption("Real-time Threat Monitoring & Security Analytics")

file_path = "security_events.csv"

# ---------------- LOAD DATA ----------------
def load_data():
    df = pd.read_csv(
        file_path,
        names=["timestamp", "event_type", "ip", "username", "severity", "score"]
    )
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

try:
    df = load_data()

    # ---------------- SECURITY OVERVIEW ----------------
    st.subheader("📊 Security Overview")

    total_events = len(df)
    critical = (df["severity"] == "CRITICAL").sum()
    medium = (df["severity"] == "MEDIUM").sum()
    low = (df["severity"] == "LOW").sum()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🚨 Total Events", total_events)
    c2.metric("🔥 Critical", critical)
    c3.metric("⚠️ Medium", medium)
    c4.metric("🟢 Low", low)

    st.divider()

    # ---------------- TOP ATTACKER + PIE CHART ----------------
    colA, colB = st.columns([1, 2])

    with colA:
        st.subheader("🎯 Top Attacker")

        if not df.empty:
            top_ip = df["ip"].value_counts().index[0]
            attack_count = df["ip"].value_counts().iloc[0]

            st.success(f"IP: {top_ip}")
            st.write(f"Attack Count: {attack_count}")
        else:
            st.info("No data available")

    with colB:
        st.subheader("⚠️ Event Distribution")

        if not df.empty:
            fig = px.pie(df, names="event_type", hole=0.5)
            st.plotly_chart(fig, width="stretch")

    st.divider()

    # ---------------- CHARTS ----------------
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📈 Threat Score Distribution")

        if not df.empty:
            fig2 = px.histogram(df, x="score", nbins=10)
            st.plotly_chart(fig2, width="stretch")

    with col2:
        st.subheader("🌍 Top Attacking IPs")

        if not df.empty:
            top_ips = df["ip"].value_counts().head(5)
            fig3 = px.bar(x=top_ips.index, y=top_ips.values)
            st.plotly_chart(fig3, width="stretch")

    st.divider()

    # ---------------- RECENT EVENTS TABLE ----------------
    st.subheader("📝 Recent Security Events")

    df_sorted = df.sort_values("timestamp", ascending=False)

    # color severity text
    def color_severity(val):
        colors = {
            "CRITICAL": "color:red",
            "MEDIUM": "color:orange",
            "LOW": "color:green"
        }
        return colors.get(val, "")

    if not df_sorted.empty:
        styled_df = df_sorted.style.map(color_severity, subset=["severity"])
        st.dataframe(styled_df, width="stretch")
    else:
        st.info("No events found")

except FileNotFoundError:
    st.error("security_events.csv not found. Run Log Analyzer first.")

# ---------------- AUTO REFRESH ----------------
time.sleep(5)
st.rerun()
