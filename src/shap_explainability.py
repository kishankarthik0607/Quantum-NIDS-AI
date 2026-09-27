"""
SHAP Explainability Module for QUANTUM_NIDS_AI

Provides:
- SHAP TreeExplainer for the trained Random Forest model
- Global feature importance
- Local prediction explanations
- Summary plots
- Bar plots
- Waterfall plots
- Dependence plots
- Dashboard-ready explanation data
"""

from pathlib import Path
import logging
import joblib

import numpy as np
import pandas as pd
import shap
import matplotlib.pyplot as plt


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).parent.parent

MODEL_PATH = BASE_DIR / "models" / "best_model.pkl"
DATA_PATH = BASE_DIR / "data" / "processed" / "selected_features.csv"

RESULTS_DIR = BASE_DIR / "results"
PLOTS_DIR = RESULTS_DIR / "plots"
LOGS_DIR = BASE_DIR / "logs"

PLOTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "explainability.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


# ============================================================
# SHAP EXPLAINER
# ============================================================

class SHAPExplainer:
    """
    SHAP explainability wrapper for the trained NIDS model.
    """

    def __init__(
        self,
        model,
        X_train,
        X_test=None,
        feature_names=None
    ):

        self.model = model
        self.X_train = X_train
        self.X_test = X_test

        if feature_names is not None:
            self.feature_names = list(feature_names)
        elif isinstance(X_train, pd.DataFrame):
            self.feature_names = list(X_train.columns)
        else:
            self.feature_names = [
                f"Feature_{i}"
                for i in range(X_train.shape[1])
            ]

        self.explainer = None
        self.shap_values = None

    # ========================================================
    # CREATE EXPLAINER
    # ========================================================

    def create_explainer(self, explainer_type="tree"):

        logger.info(
            f"Creating {explainer_type} SHAP explainer"
        )

        if explainer_type != "tree":
            raise ValueError(
                "This implementation uses TreeExplainer "
                "for the trained Random Forest model."
            )

        try:

            self.explainer = shap.TreeExplainer(
                self.model
            )

            logger.info(
                "✓ SHAP TreeExplainer created successfully"
            )

            return self.explainer

        except Exception as e:

            logger.error(
                f"Error creating SHAP explainer: {e}"
            )

            raise

    # ========================================================
    # CALCULATE SHAP VALUES
    # ========================================================

    def calculate_shap_values(self, X=None):

        if X is None:
            X = self.X_test

        if X is None:
            raise ValueError(
                "No data supplied for SHAP calculation."
            )

        logger.info(
            f"Calculating SHAP values for {len(X)} samples"
        )

        if self.explainer is None:
            self.create_explainer()

        self.shap_values = self.explainer.shap_values(X)

        logger.info(
            "✓ SHAP values calculated successfully"
        )

        return self.shap_values

    # ========================================================
    # GET ATTACK SHAP VALUES
    # ========================================================

    def _get_attack_shap_values(self):

        if self.shap_values is None:
            raise ValueError(
                "SHAP values have not been calculated yet."
            )

        values = self.shap_values

        # Older SHAP versions:
        # list[class_0], list[class_1]
        if isinstance(values, list):

            if len(values) > 1:
                return np.asarray(values[1])

            return np.asarray(values[0])

        values = np.asarray(values)

        # Newer SHAP versions can return:
        # samples x features x classes
        if values.ndim == 3:

            if values.shape[-1] > 1:
                return values[:, :, 1]

            return values[:, :, 0]

        return values

    # ========================================================
    # SUMMARY PLOT
    # ========================================================

    def plot_summary(
        self,
        plot_type="dot",
        max_display=20,
        save_path=None
    ):

        logger.info(
            f"Creating SHAP summary plot ({plot_type})"
        )

        if self.shap_values is None:
            self.calculate_shap_values()

        X = self.X_test

        if X is None:
            X = self.X_train

        values = self._get_attack_shap_values()

        plt.figure(figsize=(12, 8))

        shap.summary_plot(
            values,
            X,
            feature_names=self.feature_names,
            plot_type=plot_type,
            max_display=max_display,
            show=False
        )

        plt.tight_layout()

        if save_path is None:
            save_path = (
                PLOTS_DIR /
                "shap_summary.png"
            )

        plt.savefig(
            save_path,
            dpi=300,
            bbox_inches="tight"
        )

        plt.close()

        logger.info(
            f"✓ Saved SHAP summary plot to: {save_path}"
        )

        return save_path

    # ========================================================
    # BAR PLOT
    # ========================================================

    def plot_bar(
        self,
        max_display=20,
        save_path=None
    ):

        logger.info(
            "Creating SHAP global bar plot"
        )

        if self.shap_values is None:
            self.calculate_shap_values()

        X = self.X_test

        if X is None:
            X = self.X_train

        values = self._get_attack_shap_values()

        plt.figure(figsize=(12, 8))

        shap.summary_plot(
            values,
            X,
            feature_names=self.feature_names,
            plot_type="bar",
            max_display=max_display,
            show=False
        )

        plt.tight_layout()

        if save_path is None:
            save_path = (
                PLOTS_DIR /
                "shap_feature_importance.png"
            )

        plt.savefig(
            save_path,
            dpi=300,
            bbox_inches="tight"
        )

        plt.close()

        logger.info(
            f"✓ Saved SHAP bar plot to: {save_path}"
        )

        return save_path

    # ========================================================
    # WATERFALL PLOT
    # ========================================================

    def plot_waterfall(
        self,
        instance_index=0,
        max_display=20,
        save_path=None
    ):

        logger.info(
            f"Creating waterfall plot for "
            f"instance {instance_index}"
        )

        if self.shap_values is None:
            self.calculate_shap_values()

        values = self._get_attack_shap_values()

        if instance_index >= len(values):
            raise IndexError(
                "Instance index is outside the available data."
            )

        X = self.X_test

        if X is None:
            X = self.X_train

        base_value = self.explainer.expected_value

        if isinstance(base_value, (list, np.ndarray)):

            base_value = np.asarray(
                base_value
            ).flatten()

            if len(base_value) > 1:
                base_value = base_value[1]
            else:
                base_value = base_value[0]

        explanation = shap.Explanation(
            values=values[instance_index],
            base_values=base_value,
            data=X.iloc[instance_index].values
            if isinstance(X, pd.DataFrame)
            else X[instance_index],
            feature_names=self.feature_names
        )

        plt.figure(figsize=(12, 8))

        shap.plots.waterfall(
            explanation,
            max_display=max_display,
            show=False
        )

        plt.tight_layout()

        if save_path is None:
            save_path = (
                PLOTS_DIR /
                f"shap_waterfall_{instance_index}.png"
            )

        plt.savefig(
            save_path,
            dpi=300,
            bbox_inches="tight"
        )

        plt.close()

        logger.info(
            f"✓ Saved waterfall plot to: {save_path}"
        )

        return save_path

    # ========================================================
    # DEPENDENCE PLOT
    # ========================================================

    def plot_dependence(
        self,
        feature_name,
        interaction_feature="auto",
        save_path=None
    ):

        logger.info(
            f"Creating dependence plot for "
            f"{feature_name}"
        )

        if self.shap_values is None:
            self.calculate_shap_values()

        X = self.X_test

        if X is None:
            X = self.X_train

        values = self._get_attack_shap_values()

        plt.figure(figsize=(10, 7))

        shap.dependence_plot(
            feature_name,
            values,
            X,
            interaction_index=interaction_feature,
            show=False
        )

        plt.tight_layout()

        safe_name = str(
            feature_name
        ).replace("/", "_").replace(" ", "_")

        if save_path is None:
            save_path = (
                PLOTS_DIR /
                f"shap_dependence_{safe_name}.png"
            )

        plt.savefig(
            save_path,
            dpi=300,
            bbox_inches="tight"
        )

        plt.close()

        logger.info(
            f"✓ Saved dependence plot to: {save_path}"
        )

        return save_path

    # ========================================================
    # SINGLE PREDICTION EXPLANATION
    # ========================================================

    def explain_prediction(
        self,
        instance,
        return_dict=True
    ):

        logger.info(
            "Explaining single prediction"
        )

        if self.explainer is None:
            self.create_explainer()

        if isinstance(instance, pd.Series):

            instance_df = instance.to_frame().T

        elif isinstance(instance, pd.DataFrame):

            instance_df = instance

        else:

            instance_df = pd.DataFrame(
                [instance],
                columns=self.feature_names
            )

        shap_values = self.explainer.shap_values(
            instance_df
        )

        if isinstance(shap_values, list):

            values = np.asarray(
                shap_values[1]
                if len(shap_values) > 1
                else shap_values[0]
            )[0]

        else:

            values = np.asarray(
                shap_values
            )

            if values.ndim == 3:

                values = values[0, :, 1]

            elif values.ndim == 2:

                values = values[0]

        prediction = self.model.predict(
            instance_df
        )[0]

        probability = None

        if hasattr(self.model, "predict_proba"):

            probability = float(
                self.model.predict_proba(
                    instance_df
                )[0][1]
            )

        explanation = pd.DataFrame({
            "feature": self.feature_names,
            "value": instance_df.iloc[0].values,
            "shap_value": values
        })

        explanation["abs_shap"] = (
            explanation["shap_value"]
            .abs()
        )

        explanation = explanation.sort_values(
            "abs_shap",
            ascending=False
        ).reset_index(drop=True)

        if return_dict:

            return {
                "prediction": int(prediction),
                "prediction_label": (
                    "ATTACK"
                    if prediction == 1
                    else "BENIGN"
                ),
                "attack_probability": probability,
                "features": explanation.to_dict(
                    orient="records"
                )
            }

        return explanation

    # ========================================================
    # TOP FEATURES
    # ========================================================

    def get_top_features(
        self,
        instance_index=0,
        top_n=10
    ):

        if self.shap_values is None:
            self.calculate_shap_values()

        values = self._get_attack_shap_values()

        if instance_index >= len(values):
            raise IndexError(
                "Instance index is outside the available data."
            )

        feature_values = values[
            instance_index
        ]

        ranking = pd.DataFrame({
            "feature": self.feature_names,
            "shap_value": feature_values
        })

        ranking["abs_shap"] = (
            ranking["shap_value"].abs()
        )

        ranking = ranking.sort_values(
            "abs_shap",
            ascending=False
        ).head(top_n)

        return ranking.to_dict(
            orient="records"
        )

    # ========================================================
    # GLOBAL IMPORTANCE
    # ========================================================

    def generate_global_importance(self):

        logger.info(
            "Generating global SHAP feature importance"
        )

        if self.shap_values is None:
            self.calculate_shap_values()

        values = self._get_attack_shap_values()

        importance = np.mean(
            np.abs(values),
            axis=0
        )

        result = pd.DataFrame({
            "feature": self.feature_names,
            "mean_abs_shap": importance
        })

        result = result.sort_values(
            "mean_abs_shap",
            ascending=False
        ).reset_index(drop=True)

        output_path = (
            RESULTS_DIR /
            "shap_global_importance.csv"
        )

        result.to_csv(
            output_path,
            index=False
        )

        logger.info(
            f"✓ Saved global SHAP importance to: "
            f"{output_path}"
        )

        return result

    # ========================================================
    # SAVE EXPLAINER
    # ========================================================

    def save_explainer(
        self,
        filepath=None
    ):

        if filepath is None:

            filepath = (
                BASE_DIR /
                "models" /
                "shap_explainer.pkl"
            )

        filepath = Path(filepath)

        filepath.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        joblib.dump(
            self.explainer,
            filepath
        )

        logger.info(
            f"✓ SHAP explainer saved to: {filepath}"
        )

        return filepath

    # ========================================================
    # LOAD EXPLAINER
    # ========================================================

    def load_explainer(
        self,
        filepath=None
    ):

        if filepath is None:

            filepath = (
                BASE_DIR /
                "models" /
                "shap_explainer.pkl"
            )

        self.explainer = joblib.load(
            filepath
        )

        logger.info(
            f"✓ SHAP explainer loaded from: "
            f"{filepath}"
        )

        return self.explainer

    # ========================================================
    # DASHBOARD FORMAT
    # ========================================================

    def explain_for_dashboard(
        self,
        instance
    ):

        explanation = self.explain_prediction(
            instance,
            return_dict=True
        )

        top_features = sorted(
            explanation["features"],
            key=lambda x: abs(
                x["shap_value"]
            ),
            reverse=True
        )[:10]

        return {
            "prediction": explanation[
                "prediction_label"
            ],
            "prediction_code": explanation[
                "prediction"
            ],
            "attack_probability": explanation[
                "attack_probability"
            ],
            "top_features": top_features
        }


# ============================================================
# STANDALONE TEST
# ============================================================

def main():

    logger.info("=" * 60)
    logger.info("QUANTUM_NIDS_AI SHAP EXPLAINABILITY")
    logger.info("=" * 60)

    logger.info(
        f"Loading model from: {MODEL_PATH}"
    )

    if not MODEL_PATH.exists():

        logger.error(
            "Best model not found."
        )

        return

    if not DATA_PATH.exists():

        logger.error(
            "Selected feature dataset not found."
        )

        return

    # --------------------------------------------------------
    # Load model
    # --------------------------------------------------------

    model = joblib.load(
        MODEL_PATH
    )

    logger.info(
        "✓ Random Forest model loaded"
    )

    # --------------------------------------------------------
    # Load selected features
    # --------------------------------------------------------

    df = pd.read_csv(
        DATA_PATH
    )

    if "Label" not in df.columns:

        raise ValueError(
            "Label column not found in selected feature dataset."
        )

    X = df.drop(
        columns=["Label"]
    )

    y = df["Label"]

    logger.info(
        f"✓ Dataset loaded: {X.shape}"
    )

    # --------------------------------------------------------
    # Use a small sample for SHAP
    # --------------------------------------------------------

    sample_size = min(
        500,
        len(X)
    )

    X_sample = X.sample(
        n=sample_size,
        random_state=42
    )

    logger.info(
        f"Using {sample_size} samples for SHAP analysis"
    )

    # --------------------------------------------------------
    # Create explainer
    # --------------------------------------------------------

    explainer = SHAPExplainer(
        model=model,
        X_train=X_sample,
        X_test=X_sample,
        feature_names=list(X.columns)
    )

    explainer.create_explainer()

    # --------------------------------------------------------
    # Calculate SHAP
    # --------------------------------------------------------

    explainer.calculate_shap_values()

    # --------------------------------------------------------
    # Generate global importance
    # --------------------------------------------------------

    explainer.generate_global_importance()

    # --------------------------------------------------------
    # Generate plots
    # --------------------------------------------------------

    explainer.plot_summary(
        plot_type="dot",
        max_display=20
    )

    explainer.plot_bar(
        max_display=20
    )

    explainer.plot_waterfall(
        instance_index=0,
        max_display=20
    )

    # --------------------------------------------------------
    # Save explainer
    # --------------------------------------------------------

    explainer.save_explainer()

    # --------------------------------------------------------
    # Print example explanation
    # --------------------------------------------------------

    explanation = explainer.explain_prediction(
        X_sample.iloc[0]
    )

    logger.info("")
    logger.info(
        "Example Prediction:"
    )

    logger.info(
        f"  Prediction: "
        f"{explanation['prediction_label']}"
    )

    if explanation["attack_probability"] is not None:

        logger.info(
            f"  Attack Probability: "
            f"{explanation['attack_probability']:.4f}"
        )

    logger.info("")
    logger.info(
        "Top Contributing Features:"
    )

    for item in explanation["features"][:10]:

        logger.info(
            f"  {item['feature']}: "
            f"{item['shap_value']:.6f}"
        )

    logger.info("")
    logger.info("=" * 60)
    logger.info(
        "✓ SHAP EXPLAINABILITY COMPLETED SUCCESSFULLY"
    )
    logger.info("=" * 60)


if __name__ == "__main__":
    main()