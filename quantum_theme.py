"""
Quantum_NIDS_AI — Design System
===============================

Dark editorial futurism for the Intelligent Network Intrusion Detection System.

This module owns *presentation only*. It contains no data, no metrics and no
model logic — every value rendered by these helpers is passed in by the caller
from real project artifacts.

Exports:
    inject_theme()      -> global CSS (fonts, tokens, Streamlit overrides)
    top_nav()           -> sticky product navigation, returns active page
    hero()              -> editorial page hero
    metric_row()        -> editorial metric band (no Streamlit metric cards)
    section()           -> section heading with hairline rule
    badge()             -> threat-class badge markup
    pipeline()          -> system pipeline visual
    plotly_layout()     -> consistent chart styling
    unavailable()       -> honest "data not available" state
    footer()
"""

import streamlit as st

# ----------------------------------------------------------------------
# Tokens
# ----------------------------------------------------------------------
BG = "#07090F"
SURFACE = "#0B0E15"
SURFACE_2 = "#10141D"
LINE = "#1C2230"
TEXT = "#F5F5F5"
MUTED = "#9CA3AF"
ACCENT = "#6D5BF5"      # electric indigo
CYAN = "#3ED6DA"        # cyber teal
THREAT = "#E4614F"      # restrained red
WARN = "#D99A3F"
OK = "#4BB98A"

PLOT_SEQUENCE = [ACCENT, CYAN, OK, WARN, THREAT, "#8E7BFF", "#6FE3E6"]


def inject_theme() -> None:
    """Inject the global stylesheet. Call once, at the top of the app."""
    st.markdown(
        f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@300;400;500;600;700;800&display=swap');

:root {{
  --q-bg: {BG};
  --q-surface: {SURFACE};
  --q-surface-2: {SURFACE_2};
  --q-line: {LINE};
  --q-text: {TEXT};
  --q-muted: {MUTED};
  --q-accent: {ACCENT};
  --q-cyan: {CYAN};
  --q-threat: {THREAT};
  --q-warn: {WARN};
  --q-ok: {OK};
}}

html, body, [class*="css"], .stApp {{
  font-family: 'Manrope', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--q-bg);
  color: var(--q-text);
}}

.stApp {{ background: var(--q-bg); }}

/* Hide default Streamlit chrome */
#MainMenu, footer, header[data-testid="stHeader"] {{ display: none; }}
[data-testid="stSidebar"] {{ display: none; }}
[data-testid="stSidebarCollapsedControl"] {{ display: none; }}
[data-testid="stDecoration"] {{ display: none; }}

.block-container {{
  padding-top: 5.5rem;
  padding-bottom: 4rem;
  max-width: 1180px;
}}

/* ---------------- Typography ---------------- */
.q-eyebrow {{
  font-size: 0.72rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--q-muted);
  font-weight: 600;
  margin-bottom: 1.1rem;
}}
.q-display {{
  font-size: clamp(2.4rem, 6vw, 4.6rem);
  line-height: 0.98;
  letter-spacing: -0.035em;
  font-weight: 800;
  margin: 0 0 1.4rem 0;
  color: var(--q-text);
}}
.q-display .q-dim {{ color: #4A5266; }}
.q-lede {{
  font-size: 1.05rem;
  line-height: 1.65;
  color: var(--q-muted);
  max-width: 62ch;
  margin-bottom: 2rem;
}}
.q-section-title {{
  font-size: 0.78rem;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--q-muted);
  font-weight: 600;
  padding-bottom: 0.9rem;
  border-bottom: 1px solid var(--q-line);
  margin: 3.4rem 0 2rem 0;
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}}
.q-section-title span.q-note {{
  letter-spacing: 0;
  text-transform: none;
  font-weight: 400;
  color: #5F6979;
}}

/* ---------------- Navigation ---------------- */
.q-nav {{
  position: fixed;
  top: 0; left: 0; right: 0;
  z-index: 999;
  height: 62px;
  display: flex;
  align-items: center;
  padding: 0 clamp(1rem, 4vw, 3rem);
  background: rgba(7, 9, 15, 0.72);
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border-bottom: 1px solid var(--q-line);
}}
.q-nav-brand {{
  font-weight: 800;
  letter-spacing: -0.02em;
  font-size: 0.98rem;
}}
.q-nav-brand .q-ai {{ color: var(--q-cyan); }}
.q-nav-status {{
  margin-left: auto;
  font-size: 0.74rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--q-muted);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}}
.q-dot {{
  width: 7px; height: 7px; border-radius: 50%;
  display: inline-block;
}}
.q-dot-live {{ background: var(--q-ok); box-shadow: 0 0 0 3px rgba(75,185,138,0.16); }}
.q-dot-idle {{ background: #4A5266; }}

/* Nav links rendered as Streamlit buttons inside the fixed bar */
div[data-testid="stHorizontalBlock"].q-navbar {{ }}

/* ---------------- Metrics (editorial) ---------------- */
.q-metric-value {{
  font-size: clamp(1.9rem, 3.6vw, 2.9rem);
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1;
}}
.q-metric-label {{
  margin-top: 0.55rem;
  font-size: 0.7rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--q-muted);
  font-weight: 600;
}}
.q-metric-sub {{
  margin-top: 0.3rem;
  font-size: 0.78rem;
  color: #5F6979;
}}
.q-metric-band {{
  display: grid;
  gap: 1px;
  background: var(--q-line);
  border-top: 1px solid var(--q-line);
  border-bottom: 1px solid var(--q-line);
}}
.q-metric-cell {{
  background: var(--q-bg);
  padding: 1.7rem 1.4rem;
}}

/* ---------------- Cards / surfaces ---------------- */
.q-panel {{
  background: var(--q-surface);
  border: 1px solid var(--q-line);
  border-radius: 6px;
  padding: 1.6rem 1.7rem;
}}
.q-panel-title {{
  font-size: 0.92rem;
  font-weight: 700;
  margin-bottom: 0.4rem;
}}

/* ---------------- Badges ---------------- */
.q-badge {{
  display: inline-block;
  font-size: 0.68rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-weight: 700;
  padding: 0.22rem 0.6rem;
  border-radius: 3px;
  border: 1px solid;
}}
.q-badge-benign {{ color: var(--q-ok); border-color: rgba(75,185,138,0.4); background: rgba(75,185,138,0.08); }}
.q-badge-attack {{ color: var(--q-threat); border-color: rgba(228,97,79,0.45); background: rgba(228,97,79,0.09); }}
.q-badge-neutral {{ color: var(--q-muted); border-color: var(--q-line); background: var(--q-surface-2); }}

/* ---------------- Pipeline ---------------- */
.q-pipe {{ display: grid; gap: 1px; background: var(--q-line); border: 1px solid var(--q-line); border-radius: 6px; overflow: hidden; }}
.q-pipe-step {{
  background: var(--q-surface);
  padding: 1.1rem 1.3rem;
  display: flex; align-items: baseline; gap: 1rem;
}}
.q-pipe-idx {{ color: var(--q-accent); font-weight: 700; font-size: 0.78rem; min-width: 1.8rem; }}
.q-pipe-name {{ font-weight: 600; font-size: 0.95rem; }}
.q-pipe-desc {{ color: var(--q-muted); font-size: 0.82rem; margin-left: auto; text-align: right; }}

/* ---------------- Notices ---------------- */
.q-unavailable {{
  border: 1px dashed var(--q-line);
  border-radius: 6px;
  padding: 1.6rem;
  color: var(--q-muted);
  font-size: 0.9rem;
  line-height: 1.6;
  background: rgba(16,20,29,0.5);
}}
.q-unavailable strong {{ color: var(--q-text); font-weight: 600; }}
.q-unavailable code {{
  background: var(--q-surface-2); padding: 0.1rem 0.36rem;
  border-radius: 3px; color: var(--q-cyan); font-size: 0.82rem;
}}

/* ---------------- Streamlit control overrides ---------------- */
.stButton > button {{
  background: transparent;
  color: var(--q-text);
  border: 1px solid var(--q-line);
  border-radius: 4px;
  font-family: 'Manrope', sans-serif;
  font-weight: 600;
  font-size: 0.8rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  padding: 0.55rem 1.1rem;
  transition: border-color 140ms ease, color 140ms ease, background 140ms ease;
}}
.stButton > button:hover {{
  border-color: var(--q-accent);
  color: #FFFFFF;
  background: rgba(109,91,245,0.10);
}}
.stButton > button:focus-visible {{
  outline: 2px solid var(--q-cyan);
  outline-offset: 2px;
}}
.stButton > button[kind="primary"] {{
  background: var(--q-accent);
  border-color: var(--q-accent);
  color: #FFFFFF;
}}
.stButton > button[kind="primary"]:hover {{ background: #7E6EFF; border-color: #7E6EFF; }}
.stButton > button:disabled {{ opacity: 0.38; }}

.stTextInput input, .stNumberInput input, .stDateInput input, .stTextArea textarea {{
  background: var(--q-surface-2);
  border: 1px solid var(--q-line);
  color: var(--q-text);
  border-radius: 4px;
}}
.stTextInput input:focus, .stNumberInput input:focus {{
  border-color: var(--q-accent);
  box-shadow: none;
}}
.stTextInput label, .stNumberInput label, .stSelectbox label,
.stSlider label, .stDateInput label, .stCheckbox label {{
  font-size: 0.72rem !important;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--q-muted) !important;
  font-weight: 600 !important;
}}
div[data-baseweb="select"] > div {{
  background: var(--q-surface-2);
  border-color: var(--q-line);
  border-radius: 4px;
}}
.stSlider [data-baseweb="slider"] div[role="slider"] {{ background: var(--q-accent); }}

.stTabs [data-baseweb="tab-list"] {{
  gap: 1.6rem;
  border-bottom: 1px solid var(--q-line);
  background: transparent;
}}
.stTabs [data-baseweb="tab"] {{
  background: transparent;
  color: var(--q-muted);
  font-size: 0.76rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  font-weight: 700;
  padding: 0.6rem 0;
}}
.stTabs [aria-selected="true"] {{ color: var(--q-text); }}
.stTabs [data-baseweb="tab-highlight"] {{ background: var(--q-accent); }}

[data-testid="stDataFrame"] {{ border: 1px solid var(--q-line); border-radius: 6px; }}
[data-testid="stMetricValue"] {{ font-weight: 700; letter-spacing: -0.02em; }}

hr {{ border-color: var(--q-line); }}

/* ---------------- Footer ---------------- */
.q-footer {{
  margin-top: 5rem;
  padding-top: 2rem;
  border-top: 1px solid var(--q-line);
  display: flex;
  flex-wrap: wrap;
  gap: 1.2rem;
  justify-content: space-between;
  color: #5F6979;
  font-size: 0.8rem;
}}
.q-footer b {{ color: var(--q-text); font-weight: 700; letter-spacing: -0.01em; }}

/* ---------------- Motion (single, restrained reveal) ---------------- */
@media (prefers-reduced-motion: no-preference) {{
  .q-reveal {{ animation: qFade 420ms ease-out both; }}
  @keyframes qFade {{ from {{ opacity: 0; transform: translateY(6px); }} to {{ opacity: 1; transform: none; }} }}
}}

/* ---------------- Responsive ---------------- */
@media (max-width: 860px) {{
  .block-container {{ padding-top: 5rem; }}
  .q-pipe-desc {{ display: none; }}
  .q-nav-status {{ font-size: 0.66rem; }}
}}
</style>
""",
        unsafe_allow_html=True,
    )


# ----------------------------------------------------------------------
# Components
# ----------------------------------------------------------------------
NAV_PAGES = ["Overview", "Performance", "Live", "Explain", "Analytics", "Settings"]


def nav_bar(active: str, monitoring: bool, user: str) -> str:
    """Render the sticky brand bar plus in-page nav buttons.

    Returns the page the user selected (or `active` if unchanged).
    """
    status_dot = "q-dot-live" if monitoring else "q-dot-idle"
    status_text = "Monitoring" if monitoring else "Idle"
    st.markdown(
        f"""
<div class="q-nav">
  <div class="q-nav-brand">QUANTUM_NIDS<span class="q-ai">_AI</span></div>
  <div class="q-nav-status">
    <span class="q-dot {status_dot}"></span>{status_text} &nbsp;·&nbsp; {user}
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    cols = st.columns([1, 1, 1, 1, 1, 1, 1.4])
    chosen = active
    for i, page in enumerate(NAV_PAGES):
        with cols[i]:
            kind = "primary" if page == active else "secondary"
            if st.button(page, key=f"nav_{page}", type=kind, use_container_width=True):
                chosen = page
    with cols[6]:
        if st.button("Sign out", key="nav_logout", use_container_width=True):
            chosen = "__logout__"
    return chosen


def hero(eyebrow: str, lines, lede: str) -> None:
    """Editorial page hero. `lines` is a list of headline lines."""
    body = "<br>".join(lines)
    st.markdown(
        f"""
<div class="q-reveal">
  <div class="q-eyebrow">{eyebrow}</div>
  <h1 class="q-display">{body}</h1>
  <p class="q-lede">{lede}</p>
</div>
""",
        unsafe_allow_html=True,
    )


def metric_row(metrics) -> None:
    """Editorial metric band.

    metrics: list of (value, label, sub) tuples. `value` may be the string
    'N/A' when the underlying artifact is missing — never substitute a number.
    """
    n = max(len(metrics), 1)
    cells = "".join(
        f'<div class="q-metric-cell">'
        f'<div class="q-metric-value">{v}</div>'
        f'<div class="q-metric-label">{lab}</div>'
        + (f'<div class="q-metric-sub">{sub}</div>' if sub else "")
        + "</div>"
        for v, lab, sub in metrics
    )
    st.markdown(
        f'<div class="q-metric-band q-reveal" '
        f'style="grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));">{cells}</div>',
        unsafe_allow_html=True,
    )


def section(title: str, note: str = "") -> None:
    note_html = f'<span style="letter-spacing:0;text-transform:none;font-weight:400;color:#5F6979;">{note}</span>' if note else ""
    st.markdown(
        f'<div class="q-section-title">{title}{note_html}</div>',
        unsafe_allow_html=True,
    )


def badge(label: str) -> str:
    """Return badge markup for a model class label."""
    key = str(label).strip().upper()
    if key in ("BENIGN", "0", "NORMAL"):
        cls = "q-badge-benign"
    elif key in ("ATTACK", "1"):
        cls = "q-badge-attack"
    else:
        cls = "q-badge-neutral"
    return f'<span class="q-badge {cls}">{label}</span>'


def pipeline(steps) -> None:
    """steps: list of (name, description)."""
    rows = "".join(
        f'<div class="q-pipe-step">'
        f'<div class="q-pipe-idx">{i:02d}</div>'
        f'<div class="q-pipe-name">{name}</div>'
        f'<div class="q-pipe-desc">{desc}</div>'
        f"</div>"
        for i, (name, desc) in enumerate(steps, 1)
    )
    st.markdown(f'<div class="q-pipe">{rows}</div>', unsafe_allow_html=True)


def unavailable(what: str, how: str) -> None:
    """Honest empty state — shown instead of fabricating values."""
    st.markdown(
        f'<div class="q-unavailable"><strong>{what}</strong><br>{how}</div>',
        unsafe_allow_html=True,
    )


def plotly_layout(fig, height: int = 380, title: str = ""):
    """Apply the Quantum chart style to a Plotly figure without touching data."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Manrope, sans-serif", color=MUTED, size=12),
        title=dict(text=title, font=dict(color=TEXT, size=15), x=0, xanchor="left"),
        height=height,
        margin=dict(l=8, r=8, t=48 if title else 18, b=8),
        legend=dict(bgcolor="rgba(0,0,0,0)", orientation="h", y=-0.18, x=0),
        colorway=PLOT_SEQUENCE,
        hoverlabel=dict(bgcolor=SURFACE_2, bordercolor=LINE,
                        font=dict(family="Manrope, sans-serif", color=TEXT)),
    )
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor=LINE,
                     tickfont=dict(color=MUTED))
    fig.update_yaxes(showgrid=True, gridcolor=LINE, zeroline=False,
                     linecolor="rgba(0,0,0,0)", tickfont=dict(color=MUTED))
    return fig


def footer() -> None:
    st.markdown(
        """
<div class="q-footer">
  <div><b>QUANTUM_NIDS_AI</b><br>AI-powered network intrusion detection.</div>
  <div>Machine learning · Real-time monitoring · Explainable security intelligence</div>
</div>
""",
        unsafe_allow_html=True,
    )
