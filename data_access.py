"""
Quantum_NIDS_AI — Data Access
=============================

Single gateway between the UI and the real project artifacts produced by the
existing pipeline:

    data_preprocessing.py  -> data/processed/cleaned_data.csv
    feature_selection.py   -> data/processed/selected_features.csv
                              results/feature_importance.csv
    model_training.py      -> models/best_model.pkl
                              results/model_comparison.csv
                              results/plots/confusion_matrix_*.png
                              results/plots/roc_curve_*.png
    explainability_realtime.py -> results/shap_feature_importance.csv
                                  results/plots/shap_*.png
                                  results/realtime_predictions.csv

Contract: every function returns real data or None. Nothing here invents,
estimates or pads a value. The UI renders an explicit "unavailable" state
whenever None comes back.
"""

import json
from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
MODELS_DIR = PROJECT_ROOT / "models"
RESULTS_DIR = PROJECT_ROOT / "results"
PLOTS_DIR = RESULTS_DIR / "plots"
DATA_DIR = PROJECT_ROOT / "data" / "processed"
CONFIG_DIR = PROJECT_ROOT / "config"
LOGS_DIR = PROJECT_ROOT / "logs"

BEST_MODEL = MODELS_DIR / "best_model.pkl"
MODEL_COMPARISON = RESULTS_DIR / "model_comparison.csv"
FEATURE_IMPORTANCE = RESULTS_DIR / "feature_importance.csv"
SHAP_IMPORTANCE = RESULTS_DIR / "shap_feature_importance.csv"
REALTIME_CSV = RESULTS_DIR / "realtime_predictions.csv"
SELECTED_FEATURES = DATA_DIR / "selected_features.csv"
CLEANED_DATA = DATA_DIR / "cleaned_data.csv"
SETTINGS_FILE = CONFIG_DIR / "settings.json"

# Class encoding used throughout the pipeline (data_preprocessing.Binary_Label)
CLASS_LABELS = {0: "BENIGN", 1: "ATTACK"}


# ----------------------------------------------------------------------
# Model artifacts
# ----------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def load_best_model():
    """Load models/best_model.pkl, or None if training hasn't been run."""
    if not BEST_MODEL.exists():
        return None
    try:
        import joblib
        return joblib.load(BEST_MODEL)
    except Exception:
        return None


def available_models() -> Optional[pd.DataFrame]:
    """Evaluation results for every model the project actually trained."""
    df = _read_csv(MODEL_COMPARISON)
    if df is None or df.empty or "Model" not in df.columns:
        return None
    return df


def best_model_name() -> Optional[str]:
    df = available_models()
    if df is None:
        return None
    sort_col = "F1-Score" if "F1-Score" in df.columns else df.columns[1]
    return str(df.sort_values(sort_col, ascending=False).iloc[0]["Model"])


def model_row(name: str) -> Optional[pd.Series]:
    df = available_models()
    if df is None:
        return None
    match = df[df["Model"].astype(str) == str(name)]
    return None if match.empty else match.iloc[0]


def plot_path(*candidates: str) -> Optional[Path]:
    """Return the first matching plot produced by the pipeline."""
    if not PLOTS_DIR.exists():
        return None
    for pattern in candidates:
        hits = sorted(PLOTS_DIR.glob(pattern))
        if hits:
            return hits[0]
    return None


def model_plot(model_name: str, kind: str) -> Optional[Path]:
    slug = model_name.replace(" ", "_").lower()
    return plot_path(f"{kind}_{slug}.png")


# ----------------------------------------------------------------------
# Dataset artifacts
# ----------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def _read_csv(path_str) -> Optional[pd.DataFrame]:
    path = Path(path_str)
    if not path.exists():
        return None
    try:
        return pd.read_csv(path)
    except Exception:
        return None


def selected_feature_names() -> Optional[List[str]]:
    """Feature columns the trained model expects, from the real dataset."""
    df = _read_csv(SELECTED_FEATURES)
    if df is None:
        return None
    return [c for c in df.columns if c not in ("Label", "label", "Class", "class")]


def dataset_profile() -> Optional[dict]:
    """Shape and class balance of the training dataset actually on disk."""
    df = _read_csv(SELECTED_FEATURES)
    source = "selected_features.csv"
    if df is None:
        df = _read_csv(CLEANED_DATA)
        source = "cleaned_data.csv"
    if df is None:
        return None

    label_col = next((c for c in ("Label", "label", "Class", "class") if c in df.columns), None)
    profile = {
        "source": source,
        "rows": int(len(df)),
        "features": int(len(df.columns) - (1 if label_col else 0)),
        "distribution": None,
    }
    if label_col:
        counts = df[label_col].value_counts().sort_index()
        profile["distribution"] = {
            CLASS_LABELS.get(k, str(k)): int(v) for k, v in counts.items()
        }
    return profile


def feature_importance(top_n: int = 15) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    """Global feature importance.

    Prefers real SHAP output; falls back to the model-based importance written
    by feature_selection.py. The second return value names the actual source so
    the UI never claims SHAP when SHAP wasn't run.
    """
    shap_df = _read_csv(SHAP_IMPORTANCE)
    if shap_df is not None and {"Feature", "Mean_Absolute_SHAP"} <= set(shap_df.columns):
        out = shap_df.sort_values("Mean_Absolute_SHAP", ascending=False).head(top_n)
        return out.rename(columns={"Mean_Absolute_SHAP": "Value"}), "SHAP (mean |value|)"

    imp_df = _read_csv(FEATURE_IMPORTANCE)
    if imp_df is not None and {"Feature", "Importance"} <= set(imp_df.columns):
        out = imp_df.sort_values("Importance", ascending=False).head(top_n)
        return out.rename(columns={"Importance": "Value"}), "Random Forest impurity importance"

    return None, None


# ----------------------------------------------------------------------
# Detection history
# ----------------------------------------------------------------------
def detection_history() -> Optional[pd.DataFrame]:
    """Every classification the project has logged to realtime_predictions.csv."""
    df = _read_csv(REALTIME_CSV)
    if df is None or df.empty:
        return None
    if "Timestamp" in df.columns:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    if "Label" not in df.columns and "Prediction" in df.columns:
        df["Label"] = df["Prediction"].map(CLASS_LABELS).fillna(df["Prediction"].astype(str))
    return df


def refresh_history() -> None:
    """Drop cached CSV reads so a new monitoring run shows immediately."""
    _read_csv.clear()


# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------
DEFAULT_SETTINGS = {
    "detection_threshold": 0.85,
    "network_interface": "",
    "packets_per_run": 50,
    "capture_timeout": 30,
    "email_alerts": False,
    "alert_email": "",
    "preferred_model": "",
}


def load_settings() -> dict:
    settings = dict(DEFAULT_SETTINGS)
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                settings.update(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass
    return settings


def save_settings(settings: dict) -> bool:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
        return True
    except OSError:
        return False


# ----------------------------------------------------------------------
# Pipeline readiness — drives every "unavailable" state in the UI
# ----------------------------------------------------------------------
def pipeline_status() -> dict:
    return {
        "cleaned_data": CLEANED_DATA.exists(),
        "selected_features": SELECTED_FEATURES.exists(),
        "model": BEST_MODEL.exists(),
        "comparison": MODEL_COMPARISON.exists(),
        "shap": SHAP_IMPORTANCE.exists(),
        "history": REALTIME_CSV.exists(),
    }
