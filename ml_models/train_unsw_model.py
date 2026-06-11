"""
BIGIL UNSW-NB15 Attack Category Classifier Trainer
Dataset: UNSW-NB15 (University of New South Wales)
Features: 45 mixed (numeric + categorical) features
Target: attack_cat (9 attack categories + Normal)
"""

import os
import json
import pickle
import warnings
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, f1_score, classification_report
)

warnings.filterwarnings('ignore')

BASE_DIR = Path(__file__).parent.parent
DATASET_DIR = BASE_DIR / 'datasets' / 'OneDriveData' / 'CSV Files' / 'Training and Testing Sets'
MODEL_DIR = Path(__file__).parent

TRAIN_CSV = DATASET_DIR / 'UNSW_NB15_training-set.csv'
TEST_CSV  = DATASET_DIR / 'UNSW_NB15_testing-set.csv'

CATEGORICAL_COLS = ['proto', 'service', 'state']
DROP_COLS = ['id']


def load_dataset():
    """Load UNSW-NB15 training and testing sets."""
    print("\n[Dataset] Loading UNSW-NB15 dataset...")
    if not TRAIN_CSV.exists():
        raise FileNotFoundError(f"Training set not found: {TRAIN_CSV}")

    df_train = pd.read_csv(TRAIN_CSV, low_memory=False, nrows=80000)
    print(f"  Training set: {len(df_train):,} rows (sampled)")

    df_test = None
    if TEST_CSV.exists():
        df_test = pd.read_csv(TEST_CSV, low_memory=False, nrows=20000)
        print(f"  Testing set:  {len(df_test):,} rows")

    print(f"\n  Attack category distribution (training):")
    print(df_train['attack_cat'].fillna('Normal').value_counts().to_string(header=False))

    return df_train, df_test


def preprocess(df_train, df_test=None):
    """Encode categoricals, handle nulls, split X/y."""
    print("\nPreprocessing UNSW-NB15...")

    # Fill NaN in attack_cat
    df_train['attack_cat'] = df_train['attack_cat'].fillna('Normal').str.strip()
    if df_test is not None:
        df_test['attack_cat'] = df_test['attack_cat'].fillna('Normal').str.strip()

    # Encode target
    le_target = LabelEncoder()
    all_labels = pd.concat([
        df_train['attack_cat'],
        df_test['attack_cat'] if df_test is not None else pd.Series(dtype=str)
    ])
    le_target.fit(all_labels)

    y_train = le_target.transform(df_train['attack_cat'])
    y_binary_train = (df_train['attack_cat'] != 'Normal').astype(int).values

    # Label for test
    y_test = None
    y_binary_test = None
    if df_test is not None:
        y_test = le_target.transform(df_test['attack_cat'])
        y_binary_test = (df_test['attack_cat'] != 'Normal').astype(int).values

    # Drop target and id columns
    feature_df_train = df_train.drop(columns=['attack_cat', 'label'] + DROP_COLS, errors='ignore')
    feature_df_test  = df_test.drop(columns=['attack_cat', 'label'] + DROP_COLS, errors='ignore') if df_test is not None else None

    # Encode categoricals
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        all_vals = feature_df_train[col].fillna('unknown').astype(str)
        if feature_df_test is not None:
            all_vals = pd.concat([all_vals, feature_df_test[col].fillna('unknown').astype(str)])
        le.fit(all_vals)
        encoders[col] = le
        feature_df_train[col] = le.transform(feature_df_train[col].fillna('unknown').astype(str))
        if feature_df_test is not None:
            feature_df_test[col] = le.transform(feature_df_test[col].fillna('unknown').astype(str))

    # Replace inf/nan
    feature_df_train.replace([np.inf, -np.inf], np.nan, inplace=True)
    feature_df_train.fillna(feature_df_train.median(numeric_only=True), inplace=True)
    if feature_df_test is not None:
        feature_df_test.replace([np.inf, -np.inf], np.nan, inplace=True)
        feature_df_test.fillna(feature_df_test.median(numeric_only=True), inplace=True)

    feature_names = feature_df_train.columns.tolist()
    print(f"  Features: {len(feature_names)}")
    print(f"  Classes:  {list(le_target.classes_)}")

    X_train = feature_df_train.values
    X_test  = feature_df_test.values if feature_df_test is not None else None

    return X_train, X_test, y_train, y_test, y_binary_train, y_binary_test, le_target, encoders, feature_names


def train_models(X_train, X_test, y_train, y_test, y_binary_train, y_binary_test, label_encoder, scaler):
    """Train multiclass and binary classifiers."""
    print("\nTraining Multiclass Attack Category Classifier (RandomForest)...")

    # Scale
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test) if X_test is not None else None

    # If no separate test set, split from training
    if X_test_s is None:
        X_train_s, X_test_s, y_train, y_test, y_binary_train, y_binary_test = train_test_split(
            X_train_s, y_train, y_binary_train, test_size=0.2, random_state=42, stratify=y_train
        )

    # Multiclass model
    multi_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )
    multi_clf.fit(X_train_s, y_train)
    y_pred_multi = multi_clf.predict(X_test_s)
    acc_multi = accuracy_score(y_test, y_pred_multi)
    f1_multi  = f1_score(y_test, y_pred_multi, average='weighted', zero_division=0)

    print(f"  Multiclass Accuracy:   {acc_multi*100:.2f}%")
    print(f"  Multiclass F1 (w-avg): {f1_multi*100:.2f}%")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred_multi,
                                 target_names=label_encoder.classes_, zero_division=0))

    # Binary model
    print("Training Binary Anomaly Detector (RandomForest)...")
    binary_clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )
    binary_clf.fit(X_train_s, y_binary_train)
    y_pred_bin = binary_clf.predict(X_test_s)
    acc_bin = accuracy_score(y_binary_test, y_pred_bin)
    f1_bin  = f1_score(y_binary_test, y_pred_bin, zero_division=0)

    print(f"  Binary Accuracy: {acc_bin*100:.2f}%")
    print(f"  Binary F1:       {f1_bin*100:.2f}%")

    return multi_clf, binary_clf, {
        'multiclass': {'accuracy': round(acc_multi, 4), 'f1_weighted': round(f1_multi, 4)},
        'binary': {'accuracy': round(acc_bin, 4), 'f1': round(f1_bin, 4)}
    }


def save_models(multi_clf, binary_clf, le_target, encoders, feature_names, metrics, scaler):
    """Save all UNSW-NB15 models and metadata."""
    print("\nSaving UNSW-NB15 models...")

    with open(MODEL_DIR / 'unsw_multi_model.pkl', 'wb') as f:
        pickle.dump(multi_clf, f)
    with open(MODEL_DIR / 'unsw_binary_model.pkl', 'wb') as f:
        pickle.dump(binary_clf, f)
    with open(MODEL_DIR / 'unsw_label_encoder.pkl', 'wb') as f:
        pickle.dump(le_target, f)
    with open(MODEL_DIR / 'unsw_cat_encoders.pkl', 'wb') as f:
        pickle.dump(encoders, f)
    with open(MODEL_DIR / 'unsw_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)

    metadata = {
        'dataset': 'UNSW-NB15',
        'feature_names': feature_names,
        'attack_categories': list(le_target.classes_),
        'categorical_features': CATEGORICAL_COLS,
        'metrics': metrics
    }
    with open(MODEL_DIR / 'unsw_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    print("   unsw_multi_model.pkl")
    print("   unsw_binary_model.pkl")
    print("   unsw_label_encoder.pkl")
    print("   unsw_cat_encoders.pkl")
    print("   unsw_scaler.pkl")
    print("   unsw_metadata.json")


def main():
    print("=" * 65)
    print("  BIGIL - UNSW-NB15 Attack Category Classifier Trainer")
    print("=" * 65)

    df_train, df_test = load_dataset()

    X_train, X_test, y_train, y_test, y_binary_train, y_binary_test, \
        le_target, encoders, feature_names = preprocess(df_train, df_test)

    scaler = StandardScaler()
    multi_clf, binary_clf, metrics = train_models(
        X_train, X_test, y_train, y_test,
        y_binary_train, y_binary_test, le_target, scaler
    )

    save_models(multi_clf, binary_clf, le_target, encoders, feature_names, metrics, scaler)

    print("\n" + "=" * 65)
    print("  UNSW-NB15 Training Complete!")
    print(f"     Multiclass - Accuracy: {metrics['multiclass']['accuracy']*100:.2f}%  F1: {metrics['multiclass']['f1_weighted']*100:.2f}%")
    print(f"     Binary     - Accuracy: {metrics['binary']['accuracy']*100:.2f}%  F1: {metrics['binary']['f1']*100:.2f}%")
    print("=" * 65)

    return metrics


if __name__ == '__main__':
    main()
