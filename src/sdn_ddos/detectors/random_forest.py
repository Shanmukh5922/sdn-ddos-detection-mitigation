from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split


@dataclass
class RandomForestDetector:
    """Random forest detector for SDN traffic classification."""

    n_estimators: int = 200
    random_state: int = 42
    model: RandomForestClassifier | None = None
    feature_columns: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.model = RandomForestClassifier(n_estimators=self.n_estimators, random_state=self.random_state)

    def prepare_dataset(self, records: Iterable[Mapping[str, Any]], target_col: str = "label") -> tuple[pd.DataFrame, pd.Series]:
        frame = pd.DataFrame(records)
        if frame.empty:
            raise ValueError("Record set is empty.")

        if target_col not in frame.columns:
            raise KeyError(f"Target column '{target_col}' is missing from the dataset.")

        for column in ["timestamp"]:
            if column in frame.columns:
                frame = frame.drop(columns=[column])

        for column in ["source_ip_distribution", "protocol_distribution"]:
            if column in frame.columns:
                frame[column] = frame[column].apply(lambda value: len(value) if isinstance(value, dict) else 0)

        feature_columns = [col for col in frame.columns if col != target_col]
        self.feature_columns = feature_columns
        X = frame[feature_columns].copy()
        y = frame[target_col].copy()
        X = X.fillna(0.0)
        return X, y

    def fit(self, records: Iterable[Mapping[str, Any]], target_col: str = "label") -> dict[str, Any]:
        X, y = self.prepare_dataset(records, target_col=target_col)
        self.model = RandomForestClassifier(n_estimators=self.n_estimators, random_state=self.random_state)
        self.model.fit(X, y)
        return {"feature_columns": list(X.columns), "classes": list(self.model.classes_)}

    def train_test_split(self, records: Iterable[Mapping[str, Any]], target_col: str = "label", test_size: float = 0.2) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
        X, y = self.prepare_dataset(records, target_col=target_col)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, stratify=y, random_state=self.random_state)
        return X_train, X_test, y_train, y_test

    def evaluate(self, records: Iterable[Mapping[str, Any]], target_col: str = "label") -> dict[str, Any]:
        X_train, X_test, y_train, y_test = self.train_test_split(records, target_col=target_col)
        if self.model is None:
            self.model = RandomForestClassifier(n_estimators=self.n_estimators, random_state=self.random_state)
        self.model.fit(X_train, y_train)
        predictions = self.model.predict(X_test)

        precision = precision_score(y_test, predictions, zero_division=0)
        recall = recall_score(y_test, predictions, zero_division=0)
        f1 = f1_score(y_test, predictions, zero_division=0)
        accuracy = accuracy_score(y_test, predictions)
        tn, fp, fn, tp = confusion_matrix(y_test, predictions).ravel()
        false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

        return {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "false_positive_rate": float(false_positive_rate),
            "n_test_samples": len(y_test),
        }

    def predict(self, sample: Mapping[str, Any] | pd.Series) -> dict[str, Any]:
        if self.model is None:
            raise ValueError("The model has not been trained.")

        if isinstance(sample, pd.Series):
            row = sample.to_frame().T
        else:
            row = pd.DataFrame([sample])

        row = row.fillna(0.0)
        if self.feature_columns:
            row = row[self.feature_columns]

        prediction = self.model.predict(row)[0]
        probabilities = self.model.predict_proba(row)[0]
        return {
            "detector": "random_forest",
            "decision": "attack" if prediction == 1 else "normal",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "predicted_label": int(prediction),
            "probabilities": {str(label): float(prob) for label, prob in zip(self.model.classes_, probabilities)},
        }

    def save(self, path: str | Path) -> str:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "feature_columns": self.feature_columns}, file_path)
        return str(file_path)

    def load(self, path: str | Path) -> "RandomForestDetector":
        payload = joblib.load(path)
        self.model = payload["model"]
        self.feature_columns = payload.get("feature_columns", [])
        return self

    def detect(self, sample: Mapping[str, Any]) -> dict[str, Any]:
        return self.predict(sample)
