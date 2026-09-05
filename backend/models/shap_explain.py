"""
ACIS-Core — SHAP Explainability Module
"""
import numpy as np


class SHAPExplainer:
    def __init__(self):
        self.explainer = None
        self.feature_names = []
        self.is_fitted = False

    def fit(self, model, X_background, feature_names: list):
        """Fit SHAP TreeExplainer; falls back gracefully if shap not installed."""
        self.feature_names = list(feature_names)
        try:
            import shap
            self.explainer = shap.TreeExplainer(model)
            self.is_fitted = True
        except Exception:
            self.is_fitted = False

    def explain(self, X, top_n: int = 8):
        """Return list of {feature, shap_value} dicts for the given samples."""
        if self.is_fitted and self.explainer is not None:
            try:
                import shap
                shap_vals = self.explainer.shap_values(X)
                if isinstance(shap_vals, list):
                    shap_vals = shap_vals[1]
                mean_abs = np.abs(shap_vals).mean(axis=0)
                pairs = sorted(zip(self.feature_names, mean_abs), key=lambda x: -x[1])
                return [{"feature": n, "shap_value": round(float(v), 4)} for n, v in pairs[:top_n]]
            except Exception:
                pass
        # Fallback: return empty list
        return []