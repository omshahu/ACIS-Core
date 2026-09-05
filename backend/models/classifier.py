"""
ACIS-Core — Simple Threat Classifier (Random Forest)
"""
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import numpy as np


class ThreatClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []

    def train(self, X, y):
        self.feature_names = list(X.columns) if hasattr(X, "columns") else [f"f{i}" for i in range(X.shape[1])]
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        self.is_trained = True

    def predict(self, X):
        X_scaled = self.scaler.transform(X)
        preds = self.model.predict(X_scaled)
        proba = self.model.predict_proba(X_scaled)
        return preds, proba

    def predict_proba(self, X):
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)

    def get_metrics(self, X, y):
        if not self.is_trained:
            return {}
        X_scaled = self.scaler.transform(X)
        y_pred = self.model.predict(X_scaled)
        return {
            "accuracy":  round(accuracy_score(y, y_pred) * 100, 2),
            "precision": round(precision_score(y, y_pred, zero_division=0) * 100, 2),
            "recall":    round(recall_score(y, y_pred, zero_division=0) * 100, 2),
            "f1_score":  round(f1_score(y, y_pred, zero_division=0) * 100, 2),
        }

    def get_feature_importance(self):
        if not self.is_trained:
            return []
        pairs = zip(self.feature_names, self.model.feature_importances_)
        return [
            {"feature": n, "importance": round(float(v), 4)}
            for n, v in sorted(pairs, key=lambda x: -x[1])[:10]
        ]