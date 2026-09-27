# Quantum_NIDS_AI

Intelligent Network Intrusion Detection System — AI & Cybersecurity.

## What changed

Only the UI layer was rewritten. The ML pipeline (`data_preprocessing.py`,
`feature_selection.py`, `model_training.py`, `explainability_realtime.py`,
`realtime_detection.py`, `shap_explainability.py`, `utils.py`) is untouched.

| File | Status |
|---|---|
| `src/dashboard.py` | **Replaced.** Sidebar removed, top navigation, login gate, six redesigned pages, all values read from real artifacts. |
| `src/quantum_theme.py` | **New.** Design system: tokens, navigation, editorial metrics, chart styling. |
| `src/auth.py` | **New.** PBKDF2-SHA256 (240k iterations, per-user salt) → `config/users.json`. No plaintext passwords. |
| `src/data_access.py` | **New.** Single gateway to `models/`, `results/`, `data/processed/`. Returns real data or `None` — never a substitute value. |
| `app.py` | **New.** Root launcher. |

Every fabricated number from the old dashboard is gone: the hardcoded
`12,456` packets, the invented model table, the random detection rows, the
fixed attack distribution. Where an artifact is missing, the page states which
script produces it instead of rendering a placeholder figure.

## Install and run

```bash
pip install -r requirements.txt

# produce the artifacts the dashboard reads
python src/data_preprocessing.py
python src/feature_selection.py
python src/model_training.py
python src/explainability_realtime.py

# start the app
python app.py          # or: streamlit run src/dashboard.py
```

Open http://localhost:8501, create the first account on the **Create account**
tab, then sign in.

## Where each page gets its numbers

| Page | Source |
|---|---|
| Overview | `results/model_comparison.csv`, `results/realtime_predictions.csv`, `data/processed/selected_features.csv` |
| Performance | `results/model_comparison.csv` + `results/plots/confusion_matrix_*.png`, `roc_curve_*.png` |
| Live | `models/best_model.pkl` scoring flows captured by `explainability_realtime.capture_live_packets()`; throughput and latency are measured on the run, not assumed |
| Explain | `results/shap_feature_importance.csv`, falling back to `results/feature_importance.csv` — the page names whichever it used. Per-flow attribution uses `shap.TreeExplainer` on the loaded model |
| Analytics | `results/realtime_predictions.csv` |
| Settings | `config/settings.json` (written on save, read by Live on every run) |

Classes are the project's own binary encoding: `0 = BENIGN`, `1 = ATTACK`. No
extra attack categories were invented — the pipeline does not produce them.

## Live capture

`capture_live_packets()` uses Scapy and needs administrator/root privileges. If
Scapy is unavailable, the project's existing simulation path runs instead and
the UI labels the session **Simulation**, so simulated runs are never presented
as live traffic.

## Tested

Login, account creation, navigation across all six pages, two consecutive
capture-and-classify runs (100 flows classified, appended to
`results/realtime_predictions.csv`), per-flow SHAP explanation, settings save,
logout — all with no exceptions, both with a fully populated project and with
an empty one.
