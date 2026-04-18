import streamlit as st
import pandas as pd

from scanner.process import scan_processes
from scanner.startup import check_startup
from scanner.network import scan_network
from scanner.file import monitor_files
from core.detector import calculate_threat_score, get_risk_level

# ─────────────────────────
# PAGE CONFIG
# ─────────────────────────
st.set_page_config(
    page_title="Threatify",
    layout="wide"
)

# ─────────────────────────
# CUSTOM STYLING (SUBTLE)
# ─────────────────────────
st.markdown("""
<style>
    .main {
        background-color: #0b0f17;
    }

    h1, h2, h3 {
        font-weight: 600;
        letter-spacing: 0.5px;
    }

    .block-container {
        padding-top: 2rem;
    }

    .stButton>button {
        background-color: #1f2937;
        color: white;
        border-radius: 8px;
        border: 1px solid #374151;
    }

    .stButton>button:hover {
        background-color: #111827;
    }

    .metric-card {
        padding: 15px;
        border-radius: 10px;
        background: #111827;
        border: 1px solid #1f2937;
    }
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
st.sidebar.caption("v0.1.0")

# ─────────────────────────
# HELPERS
# ─────────────────────────
def show_table(title, data):
    st.subheader(title)

    if data:
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info(f"No issues detected")

def show_score(score, risk):
    st.subheader("Threat Assessment")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Threat Score", f"{score}/100")

    with col2:
        if risk == "CRITICAL":
            st.error(risk)
        elif risk == "HIGH":
            st.error(risk)
        elif risk == "MEDIUM":
            st.warning(risk)
        else:
            st.success(risk)

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

            score = calculate_threat_score(process, startup, network, files)
            risk = get_risk_level(score)

        # ───── Summary Cards ─────
        st.subheader("Overview")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Processes", len(process))
        col2.metric("Startup", len(startup))
        col3.metric("Network", len(network))
        col4.metric("Files", len(files))

        # ───── Charts ─────
        st.subheader("Activity Distribution")

        data = pd.DataFrame({
            "Category": ["Processes", "Startup", "Network", "Files"],
            "Alerts": [len(process), len(startup), len(network), len(files)]
        })

        col1, col2 = st.columns(2)

        with col1:
            st.bar_chart(data.set_index("Category"))

        with col2:
            st.area_chart(data.set_index("Category"))

        # ───── Results ─────
        st.divider()

        show_table("Processes", process)
        show_table("Startup", startup)
        show_table("Network", network)
        show_table("Files", files)

        st.divider()

        # ───── Score ─────
        show_score(score, risk)

# ─────────────────────────
# PROCESSES
# ─────────────────────────
elif route == "Processes":
    st.header("Process Analysis")

    if st.button("Run Analysis"):
        data = scan_processes()
        show_table("Processes", data)

# ─────────────────────────
# STARTUP
# ─────────────────────────
elif route == "Startup":
    st.header("Startup Analysis")

    if st.button("Run Analysis"):
        data = check_startup()
        show_table("Startup", data)

# ─────────────────────────
# NETWORK
# ─────────────────────────
elif route == "Network":
    st.header("Network Analysis")

    if st.button("Run Analysis"):
        data = scan_network()
        show_table("Network", data)

# ─────────────────────────
# FILES
# ─────────────────────────
elif route == "Files":
    st.header("File Monitoring")

    duration = st.slider("Duration (seconds)", 5, 60, 10)

    if st.button("Start Monitoring"):
        data = monitor_files(duration=duration)
        show_table("Files", data)