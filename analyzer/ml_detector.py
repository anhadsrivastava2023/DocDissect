
from pathlib import Path

import joblib
import pandas as pd

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"

MODEL_FILES = {
    "word": MODEL_DIR / "word_model.joblib",
    "pdf": MODEL_DIR / "pdf_model.joblib",
    "excel": MODEL_DIR / "excel_model.joblib",
}


def load_model(file_type):
    """Load a trained model artifact for a supported document type."""
    file_type = file_type.lower()

    if file_type not in MODEL_FILES:
        raise ValueError(f"Unsupported model type: {file_type}")

    model_path = MODEL_FILES[file_type]

    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    artifact = joblib.load(model_path)

    required_keys = {"model", "features", "medians", "labels"}
    if not required_keys.issubset(artifact):
        raise ValueError(f"Invalid model artifact: {model_path}")

    return artifact


def predict_document(file_type, extracted_features):
    """
    Predict using features from a compatible feature extractor.

    extracted_features must contain the exact features used in training.
    """
    artifact = load_model(file_type)
    expected_features = artifact["features"]

    missing = [
        feature for feature in expected_features
        if feature not in extracted_features
    ]

    if missing:
        raise ValueError(
            f"Missing features for {file_type}: {missing}"
        )

    # Preserve the exact feature names and training order.
    row = {
        feature: extracted_features[feature]
        for feature in expected_features
    }

    X = pd.DataFrame([row], columns=expected_features)
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([float("inf"), float("-inf")], float("nan"))

    medians = pd.Series(artifact["medians"])
    X = X.fillna(medians.reindex(expected_features).fillna(0))

    model = artifact["model"]
    predicted_label = model.predict(X)[0]

    result = {
        "model_type": file_type,
        "predicted_label": predicted_label.item()
        if hasattr(predicted_label, "item")
        else predicted_label,
        "labels": list(artifact["labels"]),
        "disclaimer": (
            "This is a dataset-trained prediction, not proof that "
            "a document is safe or malicious."
        ),
    }

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[0]
        result["class_probabilities"] = {
            str(label): float(probability)
            for label, probability in zip(model.classes_, probabilities)
        }

    return result
