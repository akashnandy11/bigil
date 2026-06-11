"""
BIGIL Network Intrusion Detection Model Trainer
Dataset: CIC-IDS2017 (Canadian Institute for Cybersecurity)
Features: 79 network flow features
Target: Binary (BENIGN vs ATTACK) + Multiclass attack type
"""

import os
import sys
import json
import pickle
import warnings
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.pipeline import Pipeline

warnings.filterwarnings('ignore')

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
DATASET_DIR = BASE_DIR / 'datasets' / 'MachineLearningCSV' / 'MachineLearningCVE'
MODEL_DIR = Path(__file__).parent

CSV_FILES = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
]

# Features to drop (non-informative or leak-prone)
DROP_FEATURES = [' Label', 'Flow ID', ' Source IP', ' Source Port',
                 ' Destination IP', 'Timestamp', ' Fwd Header Length.1']


def load_dataset(sample_per_file: int = 4000) -> pd.DataFrame:
    """Load and concatenate all CIC-IDS2017 CSV files with balanced sampling."""
    print("\n[Dataset] Loading CIC-IDS2017 dataset...")
    dfs = []
    for fname in CSV_FILES:
        fpath = DATASET_DIR / fname
        if not fpath.exists():
            print(f"  [Warn] Skipping (not found): {fname}")
            continue
        try:
            df = pd.read_csv(fpath, encoding='utf-8', low_memory=False)
            # Strip whitespace from column names
            df.columns = df.columns.str.strip()
            if 'Label' not in df.columns and ' Label' in df.columns:
                df = df.rename(columns={' Label': 'Label'})
            df.columns = df.columns.str.strip()

            n_benign = len(df[df['Label'] == 'BENIGN'])
            n_attack = len(df[df['Label'] != 'BENIGN'])
            sample_n = min(sample_per_file, len(df))
            df_sampled = df.sample(n=sample_n, random_state=42)
            dfs.append(df_sampled)
            print(f"   {fname[:45]:<45} | rows: {len(df):>7} | benign: {n_benign:>7} | attack: {n_attack:>7} | sampled: {sample_n}")
        except Exception as e:
            print(f"   Error loading {fname}: {e}")

    if not dfs:
        raise RuntimeError("No dataset files found. Check datasets/MachineLearningCSV/MachineLearningCVE/")

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n  Total rows loaded: {len(combined):,}")
    print("  Label distribution:")
    for label_name, val in combined['Label'].value_counts().items():
        # Encode as ASCII ignoring non-ascii
        safe_label = str(label_name).encode('ascii', 'ignore').decode('ascii')
        print(f"    {safe_label}: {val}")
    print("")
    return combined


def preprocess(df: pd.DataFrame):
    """Clean, encode, and prepare features for training."""
    print("Preprocessing...")

    # Drop unwanted columns
    drop_cols = [c for c in DROP_FEATURES if c in df.columns]
    labels = df['Label'].copy()
    df = df.drop(columns=drop_cols + ['Label'], errors='ignore')

    # Replace inf/nan
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.median(numeric_only=True), inplace=True)

    # Keep only numeric columns
    df = df.select_dtypes(include=[np.number])

    # Binary label: BENIGN=0, ATTACK=1
    binary_labels = (labels != 'BENIGN').astype(int)

    # Multiclass label encoding
    le = LabelEncoder()
    multi_labels = le.fit_transform(labels)

    feature_names = df.columns.tolist()
    print(f"  Features: {len(feature_names)}")
    print(f"  Binary label distribution: {dict(zip(*np.unique(binary_labels, return_counts=True)))}")

    return df.values, binary_labels.values, multi_labels, le, feature_names


def train_binary_model(X_train, y_train, X_test, y_test, feature_names):
    """Train RandomForest binary classifier (BENIGN vs ATTACK)."""
    print("\nTraining Binary Intrusion Detection Model (RandomForest)...")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print(f"  Accuracy:  {acc*100:.2f}%")
    print(f"  Precision: {prec*100:.2f}%")
    print(f"  Recall:    {rec*100:.2f}%")
    print(f"  F1 Score:  {f1*100:.2f}%")

    # Feature importance
    importances = model.feature_importances_
    top_features = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1], reverse=True
    )[:20]
    print("\n  Top 10 most important features:")
    for fname, imp in top_features[:10]:
        print(f"    {fname:<35} {imp:.4f}")

    return model, {
        'accuracy': round(acc, 4),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1': round(f1, 4),
        'top_features': [(f, round(i, 4)) for f, i in top_features]
    }


def train_multiclass_model(X_train, y_train, X_test, y_test, label_encoder):
    """Train RandomForest multiclass classifier (attack type)."""
    print("\nTraining Multiclass Attack Classifier (RandomForest)...")

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

    print(f"  Accuracy:  {acc*100:.2f}%")
    print(f"  F1 (weighted): {f1*100:.2f}%")

    classes = [str(c).encode('ascii', 'ignore').decode('ascii') for c in label_encoder.classes_]
    print(f"  Attack classes ({len(classes)}): {classes}")

    return model, {
        'accuracy': round(acc, 4),
        'f1_weighted': round(f1, 4),
        'classes': classes
    }


def save_models(binary_model, multi_model, label_encoder, feature_names,
                binary_metrics, multi_metrics, scaler):
    """Persist trained models and metadata."""
    print("\nSaving models...")

    with open(MODEL_DIR / 'ids_binary_model.pkl', 'wb') as f:
        pickle.dump(binary_model, f)

    with open(MODEL_DIR / 'ids_multi_model.pkl', 'wb') as f:
        pickle.dump(multi_model, f)

    with open(MODEL_DIR / 'ids_label_encoder.pkl', 'wb') as f:
        pickle.dump(label_encoder, f)

    with open(MODEL_DIR / 'ids_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)

    metadata = {
        'dataset': 'CIC-IDS2017',
        'feature_names': feature_names,
        'binary_metrics': binary_metrics,
        'multi_metrics': multi_metrics,
        'n_features': len(feature_names)
    }
    with open(MODEL_DIR / 'ids_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"   ids_binary_model.pkl")
    print(f"   ids_multi_model.pkl")
    print(f"   ids_label_encoder.pkl")
    print(f"   ids_scaler.pkl")
    print(f"   ids_metadata.json")


def main():
    print("=" * 65)
    print("  BIGIL - CIC-IDS2017 Network Intrusion Detection Trainer")
    print("=" * 65)

    # Load
    df = load_dataset(sample_per_file=15000)

    # Preprocess
    X, y_binary, y_multi, label_encoder, feature_names = preprocess(df)

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Split
    X_train, X_test, yb_train, yb_test, ym_train, ym_test = train_test_split(
        X_scaled, y_binary, y_multi, test_size=0.2, random_state=42, stratify=y_binary
    )

    # Train
    binary_model, binary_metrics = train_binary_model(
        X_train, yb_train, X_test, yb_test, feature_names
    )
    multi_model, multi_metrics = train_multiclass_model(
        X_train, ym_train, X_test, ym_test, label_encoder
    )

    # Save
    save_models(binary_model, multi_model, label_encoder, feature_names,
                binary_metrics, multi_metrics, scaler)

    print("\n" + "=" * 65)
    print("  CIC-IDS2017 Training Complete!")
    print(f"     Binary IDS   - Accuracy: {binary_metrics['accuracy']*100:.2f}%  F1: {binary_metrics['f1']*100:.2f}%")
    print(f"     Multiclass   - Accuracy: {multi_metrics['accuracy']*100:.2f}%  F1: {multi_metrics['f1_weighted']*100:.2f}%")
    print("=" * 65)

    return binary_metrics, multi_metrics


if __name__ == '__main__':
    main()
