"""
BIGIL Log Anomaly Classifier Trainer
Dataset: LogHub (BGL, HDFS, Apache, Linux, OpenSSH structured logs)
Target: Binary anomaly detection from log content
"""

import json
import pickle
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

warnings.filterwarnings('ignore')

BASE_DIR = Path(__file__).parent.parent
LOGHUB_DIRS = [
    BASE_DIR / 'datasets' / 'raw' / 'loghub-master',
    BASE_DIR / 'datasets' / 'loghub-master',
]
MODEL_DIR = Path(__file__).parent

LOG_SOURCES = [
    ('BGL', 'BGL_2k.log_structured.csv'),
    ('HDFS', 'HDFS_2k.log_structured.csv'),
    ('Apache', 'Apache_2k.log_structured.csv'),
    ('Linux', 'Linux_2k.log_structured.csv'),
    ('OpenSSH', 'OpenSSH_2k.log_structured.csv'),
    ('HPC', 'HPC_2k.log_structured.csv'),
    ('Spark', 'Spark_2k.log_structured.csv'),
    ('Windows', 'Windows_2k.log_structured.csv'),
]


def find_loghub_root():
    for d in LOGHUB_DIRS:
        if d.exists():
            return d
    raise FileNotFoundError('LogHub dataset not found. Extract loghub-master.zip to datasets/raw/')


def load_loghub_data():
    root = find_loghub_root()
    print(f"\n[Dataset] Loading LogHub from {root}...")
    frames = []
    for subdir, fname in LOG_SOURCES:
        fpath = root / subdir / fname
        if not fpath.exists():
            print(f"  [Skip] {fname}")
            continue
        df = pd.read_csv(fpath, low_memory=False)
        df['source'] = subdir
        frames.append(df)
        print(f"   {subdir:<12} {len(df):>6} rows")
    if not frames:
        raise RuntimeError('No LogHub CSV files found.')
    combined = pd.concat(frames, ignore_index=True)
    print(f"\n  Total rows: {len(combined):,}")
    return combined


def build_labels(df):
    labels = np.zeros(len(df), dtype=int)
    if 'Label' in df.columns:
        lbl = df['Label'].fillna('-').astype(str).str.strip()
        labels |= (lbl != '-').astype(int).values
    if 'Level' in df.columns:
        lvl = df['Level'].fillna('').astype(str).str.upper()
        labels |= lvl.isin(['FATAL', 'ERROR', 'FAIL', 'CRITICAL', 'WARN']).astype(int).values
    return labels


def build_text_features(df):
    parts = []
    for col in ('Component', 'Level', 'Content', 'EventTemplate'):
        if col in df.columns:
            parts.append(df[col].fillna('').astype(str))
    if not parts:
        return df.iloc[:, -1].fillna('').astype(str)
    text = parts[0]
    for p in parts[1:]:
        text = text + ' ' + p
    return text.str.strip()


def train_model(df):
    print("\nPreprocessing LogHub data...")
    y = build_labels(df)
    X_text = build_text_features(df)
    print(f"  Normal: {len(y) - y.sum():,}  |  Anomaly: {y.sum():,}")
    X_train, X_test, y_train, y_test = train_test_split(
        X_text, y, test_size=0.2, random_state=42, stratify=y
    )
    print("\nTraining Log Anomaly Classifier (TF-IDF + RandomForest)...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
        ('clf', RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42, class_weight='balanced'))
    ])
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    print(f"  Accuracy: {acc * 100:.2f}%")
    print(f"  F1 Score: {f1 * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Anomaly'], zero_division=0))
    return pipeline, {'accuracy': round(acc, 4), 'f1': round(f1, 4)}


def save_model(pipeline, metrics):
    print("\nSaving LogHub model...")
    with open(MODEL_DIR / 'log_anomaly_model.pkl', 'wb') as f:
        pickle.dump(pipeline, f)
    with open(MODEL_DIR / 'log_metadata.json', 'w') as f:
        json.dump({'dataset': 'LogHub', 'metrics': metrics, 'type': 'tfidf_random_forest'}, f, indent=2)


def main():
    print("=" * 65)
    print("  BIGIL - LogHub Log Anomaly Classifier Trainer")
    print("=" * 65)
    df = load_loghub_data()
    pipeline, metrics = train_model(df)
    save_model(pipeline, metrics)
    print(f"\n  LogHub Complete! Accuracy: {metrics['accuracy']*100:.2f}%  F1: {metrics['f1']*100:.2f}%")
    return metrics


if __name__ == '__main__':
    main()
