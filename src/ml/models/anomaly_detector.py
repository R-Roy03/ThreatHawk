"""
Anomaly Detector - ML model to find unusual system behavior.

How it works:
1. First it LEARNS what "normal" looks like (training)
2. Then it FLAGS anything that deviates from normal

Uses Isolation Forest algorithm:
- Good at finding outliers
- Works without labeled data
- Industry standard for anomaly detection

Example:
- Normal CPU: 10-40%
- Suddenly 95%? ANOMALY!
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from pathlib import Path
import pickle

from src.utils.logger import get_logger

logger = get_logger(__name__)

MODEL_DIR = Path(__file__).resolve().parent.parent / "saved_models"
MODEL_PATH = MODEL_DIR / "anomaly_model.pkl"


class AnomalyDetector:
    """
    Detects unusual system behavior using ML.

    Usage:
        detector = AnomalyDetector()
        detector.train(training_data)
        is_anomaly, score = detector.predict(new_data)
    """

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
        )
        self.is_trained = False

    def train(self, data: list[dict]) -> bool:
        """
        Train the model on normal system behavior.

        data = list of metrics like:
        [
            {"cpu": 15, "memory": 45, "disk": 30, "processes": 120},
            {"cpu": 22, "memory": 50, "disk": 31, "processes": 125},
        ]
        """
        if len(data) < 10:
            logger.warning("Need at least 10 samples to train")
            return False

        # Convert to numpy array
        features = self._extract_features(data)

        # Train the model
        self.model.fit(features)
        self.is_trained = True

        # Save model to disk
        self._save_model()

        logger.info(f"Model trained on {len(data)} samples")
        return True

    def predict(self, metric: dict) -> tuple[bool, float]:
        """
        Check if a system metric is anomalous.

        Returns:
            (is_anomaly, anomaly_score)
            is_anomaly = True if unusual behavior
            anomaly_score = 0.0 (normal) to 1.0 (very unusual)
        """
        if not self.is_trained:
            self._load_model()
            if not self.is_trained:
                return False, 0.0

        features = self._extract_features([metric])

        # Predict: 1 = normal, -1 = anomaly
        prediction = self.model.predict(features)[0]

        # Get anomaly score (lower = more anomalous)
        raw_score = self.model.score_samples(features)[0]

        # Convert to 0-1 range (1 = most anomalous)
        anomaly_score = max(0.0, min(1.0, -raw_score))
        anomaly_score = round(anomaly_score, 3)

        is_anomaly = prediction == -1

        if is_anomaly:
            logger.warning(f"ANOMALY detected! Score: {anomaly_score}")

        return is_anomaly, anomaly_score

    def _extract_features(self, data: list[dict]) -> np.ndarray:
        """Convert dict data to numpy array for ML model."""
        features = []

        for item in data:
            row = [
                item.get("cpu_percent", item.get("cpu", 0)),
                item.get("memory_percent", item.get("memory", 0)),
                item.get("disk_percent", item.get("disk", 0)),
                item.get("active_processes", item.get("processes", 0)),
            ]
            features.append(row)

        return np.array(features)

    def _save_model(self):
        """Save trained model to disk."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)

        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)

        logger.info(f"Model saved to {MODEL_PATH}")

    def _load_model(self):
        """Load model from disk if exists."""
        if MODEL_PATH.exists():
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            self.is_trained = True
            logger.info("Model loaded from disk")
        else:
            logger.info("No saved model found")