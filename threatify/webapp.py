import streamlit as st
import pandas as pd

from scanner.process import scan_processes
from scanner.startup import check_startup
from scanner.network import scan_network
from scanner.file import monitor_files

from core.detector import calculate_threat_score, get_risk_level
from core.aggregator import aggregate_by_process


# ─────────────────────────
# PAGE CONFIG
# ─────────────────────────
st.set_page_config(page_title="Threatify", layout="wide")

# ─────────────────────────
# SESSION STATE
# ─────────────────────────
if "results" not in st.session_state:
    st.session_state.results = None

# ─────────────────────────
# STYLING
# ─────────────────────────
st.markdown("""
<style>
.main { background-color: #0b0f17; }
.block-container { padding-top: 2rem; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────
# HEADER
# ─────────────────────────
st.title("Threatify")
st.caption("Behavioral Threat Detection System")

# ─────────────────────────
# SIDEBAR
# ─────────────────────────
st.sidebar.title("Threatify")

route = st.sidebar.radio(
    "Navigation",
    ["Full Scan", "Processes", "Startup", "Network", "Files"]
)

st.sidebar.markdown("---")
st.sidebar.caption("v0.2.0")


# ─────────────────────────
# HELPERS
# ─────────────────────────
def alerts_to_df(alerts):
    if not alerts:
        return pd.DataFrame()

    flat = []
    for a in alerts:
        data = a.get("data", {})
        flat.append({
            "Type": a.get("type"),
            "Severity": a.get("severity"),
            "Confidence": a.get("confidence"),
            "Reason": a.get("reason"),
            **data
        })

    return pd.DataFrame(flat)


def process_map_to_df(process_map):
    rows = []

    for pid, info in process_map.items():
        process_name = "unknown"

        for a in info["alerts"]:
            data = a.get("data", {})
            if "process" in data:
                process_name = data["process"]
                break

        rows.append({
            "PID": pid,
            "Process": process_name,
            "Risk": info["risk"],
            "Score": info["score"],
            "Alerts": len(info["alerts"])
        })

    df = pd.DataFrame(rows)

    if not df.empty:
        df = df.sort_values(by="Score", ascending=False)

    return df


def show_table(title, alerts):
    st.subheader(title)

    df = alerts_to_df(alerts)

    if not df.empty:
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No issues detected")


def show_score(score, risk):
    st.subheader("Threat Assessment")

    col1, col2 = st.columns(2)

    col1.metric("Threat Score", f"{score}/100")

    if risk == "CRITICAL":
        col2.error(risk)
    elif risk == "HIGH":
        col2.error(risk)
    elif risk == "MEDIUM":
        col2.warning(risk)
    else:
        col2.success(risk)


def summarize(alerts):
    counts = {}
    for a in alerts:
        t = a.get("type", "unknown")
        counts[t] = counts.get(t, 0) + 1
    return counts


# ─────────────────────────
# FULL SCAN
# ─────────────────────────
if route == "Full Scan":
    st.header("System Scan")

    if st.button("Run Full Scan"):
        with st.spinner("Analyzing system..."):

            process = scan_processes()
            startup = check_startup()
            network = scan_network()
            files = monitor_files(duration=5)

            process_map = aggregate_by_process(process, startup, network, files)

            score = calculate_threat_score(process, startup, network, files)
            risk = get_risk_level(score)

            st.session_state.results = {
                "process": process,
                "startup": startup,
                "network": network,
                "files": files,
                "process_map": process_map,
                "score": score,
                "risk": risk
            }

    results = st.session_state.results

    if results:
        process = results["process"]
        startup = results["startup"]
        network = results["network"]
        files = results["files"]
        process_map = results["process_map"]
        score = results["score"]
        risk = results["risk"]

        # ───── Overview ─────
        st.subheader("Overview")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Processes", len(process))
        col2.metric("Startup", len(startup))
        col3.metric("Network", len(network))
        col4.metric("Files", len(files))

        # ───── Process Ranking (NEW) ─────
        st.subheader("Process Threat Ranking")

        df_proc = process_map_to_df(process_map)

        if not df_proc.empty:
            st.dataframe(df_proc, use_container_width=True)

            st.bar_chart(
                df_proc.set_index("Process")["Score"]
            )
        else:
            st.info("No risky processes detected")

        # ───── Charts ─────
        st.subheader("Alert Distribution")

        df = pd.DataFrame({
            "Category": ["Process", "Startup", "Network", "Files"],
            "Alerts": [len(process), len(startup), len(network), len(files)]
        }).set_index("Category")

        col1, col2 = st.columns(2)
        col1.bar_chart(df)
        col2.line_chart(df)

        # ───── Tables ─────
        st.divider()

        show_table("Processes", process)
        show_table("Startup", startup)
        show_table("Network", network)
        show_table("Files", files)

        st.divider()

        # ───── Score ─────
        show_score(score, risk)


# ─────────────────────────
# MODULE PAGES
# ─────────────────────────
elif route == "Processes":
    st.header("Process Analysis")

    if st.button("Run Analysis"):
        show_table("Processes", scan_processes())

elif route == "Startup":
    st.header("Startup Analysis")

    if st.button("Run Analysis"):
        show_table("Startup", check_startup())

elif route == "Network":
    st.header("Network Analysis")

    if st.button("Run Analysis"):
        show_table("Network", scan_network())

elif route == "Files":
    st.header("File Monitoring")

    duration = st.slider("Duration (seconds)", 5, 300, 60)

    if st.button("Start Monitoring"):
        show_table("Files", monitor_files(duration=duration))