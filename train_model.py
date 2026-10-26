
from pathlib import Path
import json

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / "dataset"
MODEL_DIR = BASE_DIR / "models"

DATASETS = {
    "word": DATASET_DIR / "Word_Top10_Features.csv",
    "pdf": DATASET_DIR / "PDF_Top10_Features.csv",
    "excel": DATASET_DIR / "Excel_Top10_Features.csv",
}


def train_model(file_type):
    if file_type not in DATASETS:
        raise ValueError(f"Unknown file type: {file_type}")

    csv_path = DATASETS[file_type]

    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")

    # Remove identifiers that should not be model features.
    drop_columns = [
        col for col in ("label", "file_name")
        if col in df.columns
    ]

    X = df.drop(columns=drop_columns).copy()
    y = df["label"]

    if y.isna().any():
        raise ValueError("Labels contain missing values.")

    if y.nunique() < 2:
        raise ValueError("Training requires at least two classes.")

    # Convert feature columns to numeric and reject invalid values.
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([float("inf"), float("-inf")], float("nan"))

    # Median imputation is fitted on training data only.
    class_counts = y.value_counts()
    if class_counts.min() < 2:
        raise ValueError("Each class needs at least two rows.")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    medians = X_train.median().fillna(0)
    X_train = X_train.fillna(medians)
    X_test = X_test.fillna(medians)

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    print(f"\n=== {file_type.upper()} MODEL ===")
    print(f"Rows: {len(df)}")
    print(f"Features: {len(X.columns)}")
    print(f"Label counts:\n{y.value_counts().to_string()}")
    print(f"\nAccuracy: {accuracy_score(y_test, predictions):.4f}")
    print("\nClassification report:")
    print(classification_report(y_test, predictions, zero_division=0))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, predictions))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    artifact = {
        "model": model,
        "features": list(X.columns),
        "medians": medians.to_dict(),
        "labels": list(model.classes_),
        "file_type": file_type,
    }

    model_path = MODEL_DIR / f"{file_type}_model.joblib"
    joblib.dump(artifact, model_path)

    print(f"\nSaved model to: {model_path}")


if __name__ == "__main__":
    # Start with Word; later run "pdf" and "excel".
    train_model("excel")
