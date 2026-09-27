"""
Quantum_NIDS_AI — Intelligent Network Intrusion Detection System
================================================================

Streamlit application layer for the existing NIDS-ML project.

Every figure shown in this interface is read from a real project artifact
(models/, results/, data/processed/) or computed live by the trained model.
Where an artifact is missing, the page says so instead of showing a number.

Run:
    streamlit run src/dashboard.py
    (or: python app.py)

Pipeline modules used:
    data_access          - artifact loading
    auth                 - login / account creation
    quantum_theme        - design system
    explainability_realtime - live capture, preprocessing, classification
"""

import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

import auth
import data_access as da
import quantum_theme as qt

st.set_page_config(
    page_title="Quantum_NIDS_AI",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ======================================================================
# Session state
# ======================================================================
def init_state():
    defaults = {
        "authenticated": False,
        "user_name": "",
        "user_email": "",
        "page": "Overview",
        "monitoring": False,
        "session_detections": None,     # DataFrame of this session's classifications
        "session_runs": 0,
        "session_packets": 0,
        "last_run_latency": None,
        "last_run_packets": 0,
        "last_run_mode": None,
        "auth_message": None,
        "settings": da.load_settings(),
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


# ======================================================================
# Login
# ======================================================================
def render_login():
    left, right = st.columns([1.15, 1], gap="large")

    with left:
        st.markdown(
            """
<div class="q-reveal" style="padding-top:2rem;">
  <div class="q-eyebrow">AI-powered cybersecurity</div>
  <div style="font-size:1.05rem;font-weight:800;letter-spacing:-0.02em;margin-bottom:2.2rem;">
    QUANTUM<br><span style="color:#3ED6DA;">NIDS AI</span>
  </div>
  <h1 class="q-display">Detect threats<br>before they<br>escalate.</h1>
  <p class="q-lede">
    Quantum_NIDS_AI analyses network traffic with a trained machine learning
    model, flags suspicious flows as they arrive, and shows which features
    drove every decision.
  </p>
</div>
""",
            unsafe_allow_html=True,
        )

        # Real statistics only — read from the project's own artifacts.
        stats = []
        comparison = da.available_models()
        if comparison is not None and "Accuracy" in comparison.columns:
            best = comparison.sort_values("Accuracy", ascending=False).iloc[0]
            stats.append((f"{float(best['Accuracy']) * 100:.1f}%", "Detection accuracy",
                          f"{best['Model']} on held-out test set"))
        profile = da.dataset_profile()
        if profile:
            stats.append((f"{profile['rows']:,}", "Flows analysed",
                          f"{profile['features']} selected features"))
        history = da.detection_history()
        if history is not None:
            attacks = int((history["Label"].astype(str).str.upper() == "ATTACK").sum())
            stats.append((f"{attacks:,}", "Threats logged", "Across all detection runs"))

        if stats:
            qt.metric_row(stats)

    with right:
        st.markdown('<div style="padding-top:3.5rem;"></div>', unsafe_allow_html=True)
        tab_in, tab_new = st.tabs(["Sign in", "Create account"])

        with tab_in:
            email = st.text_input("Email", key="login_email", placeholder="analyst@example.com")
            password = st.text_input("Password", key="login_password", type="password")
            if st.button("Sign in", key="do_signin", type="primary", use_container_width=True):
                ok, message, name = auth.authenticate(email, password)
                if ok:
                    st.session_state.authenticated = True
                    st.session_state.user_name = name
                    st.session_state.user_email = email.strip().lower()
                    st.rerun()
                else:
                    st.session_state.auth_message = ("error", message)

            if auth.user_count() == 0:
                st.markdown(
                    '<p style="color:#5F6979;font-size:0.82rem;margin-top:0.8rem;">'
                    "No accounts exist yet. Create the first one to get in.</p>",
                    unsafe_allow_html=True,
                )

        with tab_new:
            name_in = st.text_input("Name", key="reg_name")
            email_in = st.text_input("Email", key="reg_email")
            pw_in = st.text_input("Password", key="reg_pw", type="password",
                                  help="At least 8 characters. Stored as a PBKDF2 hash.")
            pw2_in = st.text_input("Confirm password", key="reg_pw2", type="password")
            if st.button("Create account", key="do_register", type="primary", use_container_width=True):
                ok, message = auth.create_account(name_in, email_in, pw_in, pw2_in)
                st.session_state.auth_message = ("success" if ok else "error", message)

        message = st.session_state.get("auth_message")
        if message:
            kind, text = message
            (st.success if kind == "success" else st.error)(text)
            st.session_state.auth_message = None

    qt.footer()



def _image(target, path, caption=None):
    """Render a pipeline-generated plot, tolerant of Streamlit version differences."""
    try:
        target.image(str(path), caption=caption, width="stretch")
    except TypeError:
        target.image(str(path), caption=caption, use_container_width=True)


# ======================================================================
# Overview
# ======================================================================
def render_overview():
    qt.hero(
        "AI cybersecurity platform",
        ["Intelligent network", "intrusion detection."],
        "Detect suspicious network activity using machine learning, live "
        "classification, and explainable AI — every number below is read from "
        "this project's trained model and logged results.",
    )

    col_a, col_b, _ = st.columns([1, 1, 2])
    with col_a:
        if st.button("Start monitoring", key="ov_monitor", type="primary", use_container_width=True):
            st.session_state.page = "Live"
            st.rerun()
    with col_b:
        if st.button("View analytics", key="ov_analytics", use_container_width=True):
            st.session_state.page = "Analytics"
            st.rerun()

    st.markdown('<div style="height:2.6rem;"></div>', unsafe_allow_html=True)

    # ---- Editorial metric band, real values only -----------------------
    profile = da.dataset_profile()
    history = da.detection_history()
    comparison = da.available_models()

    metrics = []
    if history is not None:
        metrics.append((f"{len(history):,}", "Flows classified", "Logged detection runs"))
        attacks = int((history["Label"].astype(str).str.upper() == "ATTACK").sum())
        metrics.append((f"{attacks:,}", "Threats detected",
                        f"{attacks / len(history) * 100:.1f}% of classified traffic"))
    else:
        metrics.append(("—", "Flows classified", "No detection runs logged yet"))
        metrics.append(("—", "Threats detected", "Run live monitoring to populate"))

    if comparison is not None and "Accuracy" in comparison.columns:
        best = comparison.sort_values("Accuracy", ascending=False).iloc[0]
        metrics.append((f"{float(best['Accuracy']) * 100:.1f}%", "Model accuracy", str(best["Model"])))
        if "Recall" in comparison.columns:
            metrics.append((f"{float(best['Recall']) * 100:.1f}%", "Attack recall",
                            "True positive rate on test set"))
    else:
        metrics.append(("—", "Model accuracy", "model_comparison.csv not found"))

    qt.metric_row(metrics)

    # ---- Dataset ------------------------------------------------------
    if profile and profile["distribution"]:
        qt.section("Training data", f"{profile['source']} · {profile['features']} features")
        dist = profile["distribution"]
        fig = go.Figure(
            go.Bar(
                x=list(dist.values()),
                y=list(dist.keys()),
                orientation="h",
                marker_color=[qt.OK if k == "BENIGN" else qt.THREAT for k in dist],
                text=[f"{v:,}" for v in dist.values()],
                textposition="outside",
            )
        )
        qt.plotly_layout(fig, height=220)
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    # ---- Pipeline -----------------------------------------------------
    qt.section("How detection works")
    qt.pipeline([
        ("Network traffic", "Live interface or flow records"),
        ("Packet capture", "Scapy sniffing, batched"),
        ("Feature extraction", "Flow statistics per packet"),
        ("Preprocessing", "Aligned to the trained feature set"),
        ("ML model", da.best_model_name() or "models/best_model.pkl"),
        ("Threat classification", "Benign or attack, with confidence"),
        ("Explainable AI", "SHAP attribution per feature"),
        ("Security response", "Logged to results/ for review"),
    ])

    # ---- Readiness ----------------------------------------------------
    status = da.pipeline_status()
    missing = [k for k, ready in status.items() if not ready]
    if missing:
        qt.section("Pipeline state")
        readable = {
            "cleaned_data": "data/processed/cleaned_data.csv — run data_preprocessing.py",
            "selected_features": "data/processed/selected_features.csv — run feature_selection.py",
            "model": "models/best_model.pkl — run model_training.py",
            "comparison": "results/model_comparison.csv — run model_training.py",
            "shap": "results/shap_feature_importance.csv — run explainability_realtime.py",
            "history": "results/realtime_predictions.csv — populated by live monitoring",
        }
        qt.unavailable(
            "Some artifacts aren't on disk yet",
            "Pages that depend on them stay empty rather than showing placeholder numbers:<br>"
            + "<br>".join(f"<code>{readable[m]}</code>" for m in missing),
        )


# ======================================================================
# Performance
# ======================================================================
def render_performance():
    qt.hero(
        "Model intelligence",
        ["How well the model", "separates attack", "from benign."],
        "Metrics below come from results/model_comparison.csv, written by "
        "model_training.py when the models were evaluated on the held-out test set.",
    )

    comparison = da.available_models()
    if comparison is None:
        qt.unavailable(
            "No evaluation results on disk",
            "Run <code>python src/model_training.py</code> to train and evaluate the "
            "models. This page reads <code>results/model_comparison.csv</code> and "
            "shows nothing until that file exists.",
        )
        return

    names = comparison["Model"].astype(str).tolist()
    default_name = da.best_model_name()
    selected = st.selectbox("Model", names,
                            index=names.index(default_name) if default_name in names else 0)
    row = da.model_row(selected)

    qt.section(selected, "Held-out test set")
    metric_cells = []
    for col, label in [("Accuracy", "Accuracy"), ("Precision", "Precision"),
                       ("Recall", "Recall"), ("F1-Score", "F1"), ("ROC-AUC", "ROC-AUC")]:
        if row is not None and col in row.index and pd.notna(row[col]):
            metric_cells.append((f"{float(row[col]) * 100:.2f}%", label, None))
    if "Train Time (s)" in comparison.columns and row is not None and pd.notna(row["Train Time (s)"]):
        metric_cells.append((f"{float(row['Train Time (s)']):.1f}s", "Train time", None))
    if metric_cells:
        qt.metric_row(metric_cells)

    # ---- Comparison across every model actually trained ---------------
    if len(comparison) > 1:
        qt.section("Model comparison", f"{len(comparison)} models trained")
        metric_choice = st.radio(
            "Metric",
            [c for c in ["F1-Score", "Accuracy", "Precision", "Recall", "ROC-AUC"]
             if c in comparison.columns],
            horizontal=True,
            label_visibility="collapsed",
        )
        ranked = comparison.sort_values(metric_choice, ascending=True)
        fig = go.Figure(
            go.Bar(
                x=(ranked[metric_choice] * 100).round(2),
                y=ranked["Model"].astype(str),
                orientation="h",
                marker_color=[qt.ACCENT if m == selected else "#2A3245"
                              for m in ranked["Model"].astype(str)],
                text=[f"{v * 100:.2f}" for v in ranked[metric_choice]],
                textposition="outside",
            )
        )
        qt.plotly_layout(fig, height=90 + 56 * len(ranked), title=f"{metric_choice} (%)")
        fig.update_layout(showlegend=False)
        fig.update_xaxes(range=[0, 108])
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        with st.expander("Full evaluation table"):
            st.dataframe(comparison, use_container_width=True, hide_index=True)

    # ---- Real plots written by the pipeline ---------------------------
    cm_path = da.model_plot(selected, "confusion_matrix")
    roc_path = da.model_plot(selected, "roc_curve")
    if cm_path or roc_path:
        qt.section("Evaluation plots", "Generated by model_training.py")
        c1, c2 = st.columns(2)
        if cm_path:
            _image(c1, cm_path, f"Confusion matrix — {selected}")
        if roc_path:
            _image(c2, roc_path, f"ROC curve — {selected}")


# ======================================================================
# Live monitoring
# ======================================================================
def _run_detection_batch(packet_count: int, interface: str, timeout: int):
    """
    Run the project's flow-based real-time detector.

    The detector writes every prediction to:
        results/realtime_predictions.csv

    Returns:
        (DataFrame, mode, elapsed_seconds)
        or
        (None, error_message, None)
    """

    started = time.perf_counter()

    try:
        from realtime_detection import RealtimeDetector
    except Exception as exc:
        return (
            None,
            f"Could not import realtime_detection: {exc}",
            None
        )

    try:
        detector = RealtimeDetector()

        # ----------------------------------------------------------
        # Check whether Scapy/Npcap capture is actually available.
        # ----------------------------------------------------------

        try:
            from scapy.all import conf

            if conf.use_pcap:
                capture_available = True
            else:
                capture_available = False

        except Exception:
            capture_available = False

        if not capture_available:
            return (
                None,
                "Live packet capture is unavailable because "
                "the required packet-capture provider is not installed. "
                "The trained model and flow detector are working, but "
                "live interface capture is currently disabled.",
                None
            )

        # ----------------------------------------------------------
        # Start actual packet capture.
        # ----------------------------------------------------------

        detector.start_capture(
            interface=interface or None,
            packet_count=packet_count,
            timeout=timeout
        )

        elapsed = time.perf_counter() - started

        # ----------------------------------------------------------
        # Read the records generated by the detector.
        # ----------------------------------------------------------

        da.refresh_history()

        history = da.detection_history()

        if history is None or history.empty:
            return (
                None,
                "No detection records were generated.",
                elapsed
            )

        # Use only the most recent records from this run.
        results = history.tail(packet_count).copy()

        return (
            results,
            "Live capture",
            elapsed
        )

    except PermissionError:
        return (
            None,
            "Packet capture needs administrator privileges.",
            None
        )

    except KeyboardInterrupt:
        return (
            None,
            "Packet capture stopped by user.",
            None
        )

    except Exception as exc:
        return (
            None,
            f"Detection run failed: {exc}",
            None
        )

def render_live():
    qt.hero(
        "Live detection",
        ["Real-time", "network intelligence."],
        "Capture traffic from the interface, classify each flow with the trained "
        "model, and watch threats appear as they are detected.",
    )

    settings = st.session_state.settings
    c1, c2, c3 = st.columns([1, 1, 2])
    with c1:
        start = st.button(
            "Capture next batch" if st.session_state.monitoring else "Start monitoring",
            key="live_start", type="primary", use_container_width=True,
        )
    with c2:
        stop = st.button("Stop monitoring", key="live_stop", use_container_width=True,
                         disabled=not st.session_state.monitoring)
    with c3:
        batch = st.slider("Packets per run", 10, 500,
                          int(settings.get("packets_per_run", 50)), 10)

    if stop:
        st.session_state.monitoring = False
        st.rerun()

    if start:
        st.session_state.monitoring = True
        with st.spinner("Capturing and classifying traffic…"):
            results, mode, elapsed = _run_detection_batch(
                batch,
                settings.get("network_interface", ""),
                int(settings.get("capture_timeout", 30)),
            )
        if results is None:
            st.session_state.monitoring = False
            qt.unavailable("Monitoring could not start", mode)
        else:
            existing = st.session_state.session_detections
            st.session_state.session_detections = (
                results if existing is None else pd.concat([existing, results], ignore_index=True)
            )
            st.session_state.session_runs += 1
            st.session_state.session_packets += len(results)
            st.session_state.last_run_packets = len(results)
            st.session_state.last_run_latency = elapsed
            st.session_state.last_run_mode = mode
            st.rerun()

    # ---- Live metrics, measured from the run that just happened -------
    detections = st.session_state.session_detections
    threshold = float(settings.get("detection_threshold", 0.85))

    if detections is not None and len(detections):
        elapsed = st.session_state.last_run_latency or 0.0
        run_packets = st.session_state.get("last_run_packets") or 0
        attacks = int((detections["Label"].astype(str).str.upper() == "ATTACK").sum())
        per_packet_ms = (elapsed / max(run_packets, 1)) * 1000
        rate = run_packets / elapsed if elapsed else 0

        qt.section("Session metrics",
                   f"{st.session_state.session_runs} run(s) · {st.session_state.last_run_mode}")
        qt.metric_row([
            (f"{rate:,.0f}", "Flows / second", "Throughput of the last run"),
            (f"{attacks:,}", "Threats this session", f"of {len(detections):,} classified"),
            (f"{per_packet_ms:.2f} ms", "Classification latency", "Per flow, measured"),
            (f"{detections['Confidence'].mean():.2%}", "Mean confidence", "Model probability"),
        ])

        # ---- Threat feed ---------------------------------------------
        qt.section("Threat feed", f"Confidence below {threshold:.0%} is flagged for review")
        feed = detections.copy().sort_values("Timestamp", ascending=False).head(25)
        rows = []
        for _, r in feed.iterrows():
            ts = pd.to_datetime(r["Timestamp"]).strftime("%H:%M:%S")
            label = str(r.get("Label", ""))
            conf = float(r.get("Confidence", 0))
            review = "" if conf >= threshold else ' <span style="color:#D99A3F;">review</span>'
            rows.append(
                f'<tr style="border-bottom:1px solid #1C2230;">'
                f'<td style="padding:0.62rem 0.6rem;color:#9CA3AF;">{ts}</td>'
                f'<td style="padding:0.62rem 0.6rem;">{r.get("src_ip", "—")}</td>'
                f'<td style="padding:0.62rem 0.6rem;">{r.get("dst_ip", "—")}</td>'
                f'<td style="padding:0.62rem 0.6rem;">{qt.badge(label)}</td>'
                f'<td style="padding:0.62rem 0.6rem;text-align:right;">{conf:.1%}{review}</td>'
                f"</tr>"
            )
        header = (
            '<tr style="border-bottom:1px solid #1C2230;">'
            + "".join(
                f'<th style="padding:0.5rem 0.6rem;text-align:{"right" if h == "Confidence" else "left"};'
                f'font-size:0.68rem;letter-spacing:0.14em;text-transform:uppercase;color:#9CA3AF;'
                f'font-weight:600;">{h}</th>'
                for h in ["Time", "Source", "Destination", "Classification", "Confidence"]
            )
            + "</tr>"
        )
        st.markdown(
            '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;'
            f'font-size:0.88rem;">{header}{"".join(rows)}</table></div>',
            unsafe_allow_html=True,
        )

        # ---- Traffic visualisation -----------------------------------
        qt.section("Network traffic", "Classified flows over the session")
        chart_df = detections.copy()
        chart_df["Timestamp"] = pd.to_datetime(chart_df["Timestamp"], errors="coerce")
        chart_df = chart_df.dropna(subset=["Timestamp"])
        if len(chart_df) > 1:
            grouped = (
                chart_df.set_index("Timestamp")
                .groupby([pd.Grouper(freq="1s"), "Label"])
                .size()
                .reset_index(name="Flows")
            )
            fig = px.line(grouped, x="Timestamp", y="Flows", color="Label",
                          color_discrete_map={"BENIGN": qt.OK, "ATTACK": qt.THREAT})
            qt.plotly_layout(fig, height=300)
            fig.update_traces(line=dict(width=2))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

            attack_share = (chart_df["Label"].astype(str).str.upper() == "ATTACK").mean()
            st.markdown(
                f'<p style="color:#9CA3AF;font-size:0.88rem;">'
                f"{attack_share:.1%} of the flows classified this session were labelled "
                f"ATTACK by the model.</p>",
                unsafe_allow_html=True,
            )
    else:
        qt.unavailable(
            "No traffic classified in this session",
            "Start monitoring to capture a batch of flows and classify them with "
            "<code>models/best_model.pkl</code>. Live capture needs Scapy and elevated "
            "privileges; without them the project's own simulation path is used and is "
            "labelled as such.",
        )


# ======================================================================
# Explainability
# ======================================================================
def render_explain():
    qt.hero(
        "Model explainability",
        ["Why did the model", "make this decision?"],
        "Understand which network features moved the model toward an attack "
        "classification, globally and for a single flow.",
    )

    importance, source = da.feature_importance(top_n=15)
    if importance is None:
        qt.unavailable(
            "No attribution data on disk",
            "Run <code>python src/explainability_realtime.py</code> to produce "
            "<code>results/shap_feature_importance.csv</code>, or "
            "<code>python src/feature_selection.py</code> for model-based importance. "
            "This page shows no attribution values until one of those exists.",
        )
        return

    qt.section("Global feature importance", source)
    ranked = importance.sort_values("Value", ascending=True)
    fig = go.Figure(
        go.Bar(
            x=ranked["Value"],
            y=ranked["Feature"].astype(str),
            orientation="h",
            marker_color=qt.ACCENT,
        )
    )
    qt.plotly_layout(fig, height=100 + 30 * len(ranked))
    fig.update_layout(showlegend=False)
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    shap_summary = da.plot_path("shap_summary*.png", "shap_bar*.png")
    if shap_summary:
        with st.expander("SHAP summary plot"):
            _image(st, shap_summary)

    # ---- Individual prediction ---------------------------------------
    qt.section("Explain one flow", "Per-feature attribution from the trained model")
    model = da.load_best_model()
    features = da.selected_feature_names()
    dataset = da._read_csv(da.SELECTED_FEATURES)

    if model is None or dataset is None or not features:
        qt.unavailable(
            "Individual explanation needs the trained model and dataset",
            "Both <code>models/best_model.pkl</code> and "
            "<code>data/processed/selected_features.csv</code> must exist.",
        )
        return

    max_idx = len(dataset) - 1
    col_a, col_b = st.columns([1, 2])
    with col_a:
        idx = st.number_input("Flow index", min_value=0, max_value=int(max_idx), value=0, step=1)
    with col_b:
        st.markdown('<div style="height:1.85rem;"></div>', unsafe_allow_html=True)
        generate = st.button("Generate explanation", type="primary")

    if generate:
        instance = dataset.iloc[[int(idx)]][features]
        try:
            prediction = int(model.predict(instance)[0])
            proba = model.predict_proba(instance)[0]
        except Exception as exc:  # noqa: BLE001
            qt.unavailable("The model could not score this flow", str(exc))
            return

        label = da.CLASS_LABELS.get(prediction, str(prediction))
        qt.metric_row([
            (qt.badge(label), "Model decision", f"Flow #{int(idx)}"),
            (f"{float(np.max(proba)):.2%}", "Confidence", "Predicted class probability"),
        ])

        contributions = None
        try:
            import shap
            explainer = shap.TreeExplainer(model)
            values = explainer.shap_values(instance)
            arr = np.array(values)
            if arr.ndim == 3:
                arr = arr[0, :, 1] if arr.shape[-1] > 1 else arr[0, :, 0]
            elif arr.ndim == 2:
                arr = arr[0]
            contributions = pd.DataFrame({"Feature": features, "SHAP": arr})
            method = "SHAP values for this flow"
        except Exception:
            contributions = None

        if contributions is None and hasattr(model, "feature_importances_"):
            contributions = pd.DataFrame({
                "Feature": features,
                "SHAP": model.feature_importances_,
            })
            method = "Model feature importance (SHAP unavailable for this model)"

        if contributions is None:
            qt.unavailable(
                "No attribution available for this model type",
                "The trained estimator supports neither a SHAP tree explainer nor "
                "<code>feature_importances_</code>.",
            )
            return

        contributions["abs"] = contributions["SHAP"].abs()
        top = contributions.sort_values("abs", ascending=False).head(12).sort_values("SHAP")
        fig = go.Figure(
            go.Bar(
                x=top["SHAP"],
                y=top["Feature"],
                orientation="h",
                marker_color=[qt.THREAT if v > 0 else qt.CYAN for v in top["SHAP"]],
            )
        )
        qt.plotly_layout(fig, height=120 + 30 * len(top), title=method)
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        st.markdown(
            '<p style="color:#9CA3AF;font-size:0.86rem;">Bars to the right push the '
            "model toward ATTACK; bars to the left push it toward BENIGN. Length is "
            "the size of the contribution.</p>",
            unsafe_allow_html=True,
        )


# ======================================================================
# Analytics
# ======================================================================
def render_analytics():
    qt.hero(
        "Threat intelligence",
        ["Understand the", "threat landscape."],
        "Every detection this system has logged to results/realtime_predictions.csv, "
        "filtered by date.",
    )

    history = da.detection_history()
    if history is None:
        qt.unavailable(
            "No detection history yet",
            "History is written by live monitoring and by "
            "<code>python src/explainability_realtime.py</code>. Until "
            "<code>results/realtime_predictions.csv</code> exists, this page has "
            "nothing real to show.",
        )
        return

    history = history.dropna(subset=["Timestamp"])
    if history.empty:
        qt.unavailable("Detection history has no usable timestamps",
                       "Re-run detection to write fresh records.")
        return

    first = history["Timestamp"].min().date()
    last = history["Timestamp"].max().date()
    c1, c2 = st.columns(2)
    start_date = c1.date_input("From", value=first, min_value=first, max_value=last)
    end_date = c2.date_input("To", value=last, min_value=first, max_value=last)

    mask = (history["Timestamp"].dt.date >= start_date) & (history["Timestamp"].dt.date <= end_date)
    window = history[mask]
    if window.empty:
        qt.unavailable("No detections in that window", "Widen the date range.")
        return

    labels = window["Label"].astype(str).str.upper()
    attacks = int((labels == "ATTACK").sum())
    qt.metric_row([
        (f"{len(window):,}", "Flows classified", f"{start_date} to {end_date}"),
        (f"{attacks:,}", "Threats", f"{attacks / len(window) * 100:.1f}% of traffic"),
        (f"{window['Confidence'].mean():.1%}", "Mean confidence", "Across the window"),
        (f"{window['Timestamp'].dt.date.nunique()}", "Active days", "With logged detections"),
    ])

    qt.section("Classification distribution")
    counts = labels.value_counts()
    c1, c2 = st.columns([1, 1.4])
    with c1:
        fig = go.Figure(
            go.Pie(
                labels=counts.index.tolist(),
                values=counts.values.tolist(),
                hole=0.62,
                marker=dict(colors=[qt.OK if l == "BENIGN" else qt.THREAT for l in counts.index]),
                textinfo="percent",
            )
        )
        qt.plotly_layout(fig, height=300)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with c2:
        trend = (
            window.set_index("Timestamp")
            .assign(Label=labels.values)
            .groupby([pd.Grouper(freq="1h"), "Label"])
            .size()
            .reset_index(name="Flows")
        )
        fig = px.area(trend, x="Timestamp", y="Flows", color="Label",
                      color_discrete_map={"BENIGN": qt.OK, "ATTACK": qt.THREAT})
        qt.plotly_layout(fig, height=300, title="Detections per hour")
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    if "Attack_Probability" in window.columns:
        qt.section("Attack probability distribution", "Model output across all logged flows")
        fig = px.histogram(window, x="Attack_Probability", nbins=40,
                           color_discrete_sequence=[qt.ACCENT])
        qt.plotly_layout(fig, height=280)
        fig.update_layout(bargap=0.04, showlegend=False)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with st.expander("Detection records"):
        st.dataframe(window.sort_values("Timestamp", ascending=False),
                     use_container_width=True, hide_index=True)


# ======================================================================
# Settings
# ======================================================================
def render_settings():
    qt.hero(
        "System configuration",
        ["Tune detection", "and monitoring."],
        "Settings are written to config/settings.json and read by the live "
        "monitoring page on every run.",
    )

    settings = dict(st.session_state.settings)

    qt.section("Detection")
    settings["detection_threshold"] = st.slider(
        "Confidence threshold", 0.0, 1.0, float(settings.get("detection_threshold", 0.85)), 0.01,
        help="Classifications below this confidence are flagged for analyst review.",
    )

    qt.section("Model")
    comparison = da.available_models()
    if comparison is not None:
        options = ["Best model (automatic)"] + comparison["Model"].astype(str).tolist()
        current = settings.get("preferred_model") or "Best model (automatic)"
        choice = st.selectbox("Preferred model", options,
                              index=options.index(current) if current in options else 0)
        settings["preferred_model"] = "" if choice.startswith("Best model") else choice
        st.markdown(
            f'<p style="color:#5F6979;font-size:0.84rem;">Detection currently loads '
            f"<code>models/best_model.pkl</code>"
            + (f" — {da.best_model_name()}." if da.best_model_name() else ".")
            + "</p>",
            unsafe_allow_html=True,
        )
    else:
        qt.unavailable("No trained models found",
                       "Run <code>python src/model_training.py</code> first.")

    qt.section("Network")
    c1, c2 = st.columns(2)
    settings["network_interface"] = c1.text_input(
        "Capture interface", value=settings.get("network_interface", ""),
        placeholder="eth0 / Wi-Fi — blank for default",
    )
    settings["capture_timeout"] = c2.number_input(
        "Capture timeout (seconds)", 5, 300, int(settings.get("capture_timeout", 30)), 5)
    settings["packets_per_run"] = st.number_input(
        "Packets per detection run", 10, 1000, int(settings.get("packets_per_run", 50)), 10)

    qt.section("Alerts")
    settings["email_alerts"] = st.checkbox(
        "Email me when a threat is detected", value=bool(settings.get("email_alerts", False)))
    if settings["email_alerts"]:
        settings["alert_email"] = st.text_input("Alert address",
                                                value=settings.get("alert_email", ""))
        st.markdown(
            '<p style="color:#9CA3AF;font-size:0.84rem;">The preference is saved, but no '
            "SMTP server is configured in this project, so no mail is sent yet.</p>",
            unsafe_allow_html=True,
        )

    st.markdown('<div style="height:1.6rem;"></div>', unsafe_allow_html=True)
    if st.button("Save settings", type="primary"):
        if da.save_settings(settings):
            st.session_state.settings = settings
            st.success("Settings saved to config/settings.json.")
        else:
            st.error("Couldn't write config/settings.json. Check directory permissions.")


# ======================================================================
# Router
# ======================================================================
PAGES = {
    "Overview": render_overview,
    "Performance": render_performance,
    "Live": render_live,
    "Explain": render_explain,
    "Analytics": render_analytics,
    "Settings": render_settings,
}


def main():
    qt.inject_theme()
    init_state()

    if not st.session_state.authenticated:
        render_login()
        return

    chosen = qt.nav_bar(
        active=st.session_state.page,
        monitoring=st.session_state.monitoring,
        user=st.session_state.user_name or st.session_state.user_email,
    )

    if chosen == "__logout__":
        for key in ("authenticated", "user_name", "user_email", "session_detections",
                    "session_runs", "session_packets", "monitoring"):
            st.session_state.pop(key, None)
        st.rerun()

    if chosen != st.session_state.page:
        st.session_state.page = chosen
        st.rerun()

    PAGES.get(st.session_state.page, render_overview)()
    qt.footer()


if __name__ == "__main__":
    main()
