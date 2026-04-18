import streamlit as st
import pandas as pd
import time

from scanner.process import scan_processes
from scanner.startup import check_startup
from scanner.network import scan_network
from scanner.file import monitor_files

from core.detector import calculate_threat_score, get_risk_level
from core.aggregator import aggregate_by_process


# ─────────────────────────
# CONFIG
# ─────────────────────────
st.set_page_config(page_title="Threatify", layout="wide")

st.title("Threatify")
st.caption("Behavioral Threat Detection System")


# ─────────────────────────
# STATE
# ─────────────────────────
if "results" not in st.session_state:
    st.session_state.results = None

if "has_scanned" not in st.session_state:
    st.session_state.has_scanned = False


# ─────────────────────────
# SIDEBAR (KEEP THIS)
# ─────────────────────────
st.sidebar.title("Threatify")

page = st.sidebar.radio(
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


# ─────────────────────────
# SCAN ENGINE
# ─────────────────────────
def run_scan():
    process = scan_processes()
    startup = check_startup()
    network = scan_network()
    files = monitor_files(duration=5)

    process_map = aggregate_by_process(process, startup, network, files)

    score = calculate_threat_score(process, startup, network, files)
    risk = get_risk_level(score)

    return {
        "process": process,
        "startup": startup,
        "network": network,
        "files": files,
        "process_map": process_map,
        "score": score,
        "risk": risk
    }


# ─────────────────────────
# FULL SCAN (AUTO)
# ─────────────────────────
if page == "Full Scan":
    st.header("System Scan")

    if not st.session_state.has_scanned:
        placeholder = st.empty()

        for i in [3, 2, 1]:
            placeholder.info(f"Starting scan in {i}...")
            time.sleep(1)

        placeholder.info("Scanning system...")

        results = run_scan()

        st.session_state.results = results
        st.session_state.has_scanned = True

        placeholder.success("Scan complete")

    results = st.session_state.results

    if results:
        process = results["process"]
        startup = results["startup"]
        network = results["network"]
        files = results["files"]
        process_map = results["process_map"]
        score = results["score"]
        risk = results["risk"]

        # ───── STATUS ─────
        st.subheader("Threat Status")

        col1, col2 = st.columns(2)
        col1.metric("Score", f"{score}/100")

        if risk == "CRITICAL":
            col2.error(risk)
        elif risk == "HIGH":
            col2.error(risk)
        elif risk == "MEDIUM":
            col2.warning(risk)
        else:
            col2.success(risk)

        # ───── OVERVIEW ─────
        st.subheader("Overview")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Processes", len(process))
        col2.metric("Startup", len(startup))
        col3.metric("Network", len(network))
        col4.metric("Files", len(files))

        # ───── PROCESS RANKING (MAIN)
        st.subheader("Top Processes")

        df_proc = process_map_to_df(process_map)

        if not df_proc.empty:
            st.dataframe(df_proc, use_container_width=True)
        else:
            st.info("No risky processes detected")

        # ───── SINGLE CLEAN CHART
        st.subheader("Activity Overview")

        df = pd.DataFrame({
            "Category": ["Processes", "Startup", "Network", "Files"],
            "Alerts": [len(process), len(startup), len(network), len(files)]
        }).set_index("Category")

        st.bar_chart(df)

        # ───── DETAILS
        with st.expander("Show Details"):
            st.write("Processes", process)
            st.write("Startup", startup)
            st.write("Network", network)
            st.write("Files", files)

    if st.button("Run Scan Again"):
        st.session_state.has_scanned = False
        st.rerun()


# ─────────────────────────
# MODULE PAGES
# ─────────────────────────
elif page == "Processes":
    st.header("Process Analysis")

    if st.button("Run Analysis"):
        st.dataframe(alerts_to_df(scan_processes()))


elif page == "Startup":
    st.header("Startup Analysis")

    if st.button("Run Analysis"):
        st.dataframe(alerts_to_df(check_startup()))


elif page == "Network":
    st.header("Network Analysis")

    if st.button("Run Analysis"):
        st.dataframe(alerts_to_df(scan_network()))


elif page == "Files":
    st.header("File Monitoring")

    duration = st.slider("Duration (seconds)", 5, 300, 60)

    if st.button("Start Monitoring"):
        st.dataframe(alerts_to_df(monitor_files(duration=duration)))