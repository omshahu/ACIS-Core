"""
ACIS-Core — Autoencoder Anomaly Detector (PCA-based)
"""
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import numpy as np


class AutoencoderDetector:
    def __init__(self, n_components: int = 8, threshold_percentile: int = 95):
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=n_components)
        self.threshold = None
        self.is_trained = False
        self.threshold_percentile = threshold_percentile

    def train(self, X):
        X_scaled = self.scaler.fit_transform(X)
        encoded = self.pca.fit_transform(X_scaled)
        decoded = self.pca.inverse_transform(encoded)
        errors = np.mean((X_scaled - decoded) ** 2, axis=1)
        self.threshold = float(np.percentile(errors, self.threshold_percentile))
        self.is_trained = True

    def predict(self, X):
        """Returns (is_anomaly array, reconstruction_error array)."""
        X_scaled = self.scaler.transform(X)
        encoded = self.pca.transform(X_scaled)
        decoded = self.pca.inverse_transform(encoded)
        errors = np.mean((X_scaled - decoded) ** 2, axis=1)
        return errors > self.threshold, errors

    def score_single(self, x_row):
        """Score a single sample row (numpy array)."""
        _, errors = self.predict(x_row.reshape(1, -1))
        return float(errors[0])