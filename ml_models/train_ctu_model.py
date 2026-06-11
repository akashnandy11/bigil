"""
BIGIL CTU-13 Botnet Traffic Classifier Trainer
Dataset: CTU-13-Dataset (streams from tar.bz2 — no full extraction needed)
Target: Binary botnet vs legitimate traffic classification
"""

import json
import pickle
import tarfile
import warnings
from io import BytesIO
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings('ignore')

BASE_DIR = Path(__file__).parent.parent
MODEL_DIR = Path(__file__).parent

ARCHIVE_PATHS = [
    BASE_DIR / 'datasets' / 'raw' / 'CTU-13-Dataset.tar.bz2',
    BASE_DIR / 'datasets' / 'CTU-13-Dataset.tar.bz2',
]

MAX_ROWS_PER_FILE = 8000
MAX_FILES = 6


def find_archive():
    for p in ARCHIVE_PATHS:
        if p.exists():
            return p
    raise FileNotFoundError('CTU-13-Dataset.tar.bz2 not found in datasets/')


def load_ctu_from_tar(archive_path: Path) -> pd.DataFrame:
    """Stream-read bidirectional flow CSVs from CTU-13 tar archive."""
    print(f"\n[Dataset] Streaming CTU-13 from {archive_path.name}...")
    dfs = []
    files_read = 0

    with tarfile.open(archive_path, 'r:bz2') as tar:
        for member in tar:
            if not member.isfile():
                continue
            name_lower = member.name.lower()
            if not name_lower.endswith('.csv'):
                continue
            if 'bidirectional' not in name_lower and 'netflow' not in name_lower:
                continue

            try:
                f = tar.extractfile(member)
                if f is None:
                    continue
                content = f.read()
                df = pd.read_csv(BytesIO(content), low_memory=False, nrows=MAX_ROWS_PER_FILE)
                if len(df) < 50:
                    continue

                # Infer label column
                label_col = None
                for col in df.columns:
                    cl = col.lower().strip()
                    if cl in ('label', 'class', 'category', 'traffic_type'):
                        label_col = col
                        break

                if label_col is None:
                    # CTU-13 scenario files often named by scenario; mark from path
                    scenario = member.name.split('/')[0] if '/' in member.name else 'unknown'
                    df['__label__'] = scenario
                    label_col = '__label__'

                df = df.rename(columns={label_col: 'Label'})
                df['Label'] = df['Label'].astype(str).str.strip()
                dfs.append(df)
                files_read += 1
                print(f"   {member.name[:55]:<55} | rows: {len(df):>6}")

                if files_read >= MAX_FILES:
                    break
            except Exception as e:
                print(f"  [Warn] {member.name}: {e}")

    if not dfs:
        raise RuntimeError(
            'No CTU-13 flow CSVs found in archive. '
            'Ensure CTU-13-Dataset.tar.bz2 is present.'
        )

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n  Total rows loaded: {len(combined):,}")
    print("  Label distribution:")
    for lbl, cnt in combined['Label'].value_counts().head(10).items():
        print(f"    {lbl}: {cnt}")
    return combined


def preprocess(df: pd.DataFrame):
    """Prepare numeric features and binary botnet labels."""
    print("\nPreprocessing CTU-13...")

    labels = df['Label'].astype(str).str.lower()
    # Botnet if label contains bot, malicious, attack, or is not benign/normal/background
    benign_kw = {'benign', 'normal', 'background', 'legitimate', 'legit', '-', '0', '1'}
    y_binary = (~labels.isin(benign_kw) & ~labels.str.contains('normal|benign|background', na=False)).astype(int).values

    feature_df = df.drop(columns=['Label'], errors='ignore')
    feature_df = feature_df.select_dtypes(include=[np.number])
    feature_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    feature_df.fillna(feature_df.median(numeric_only=True), inplace=True)

    if feature_df.shape[1] == 0:
        raise RuntimeError('No numeric features found in CTU-13 CSV files.')

    feature_names = feature_df.columns.tolist()
    print(f"  Features: {len(feature_names)}")
    print(f"  Botnet: {y_binary.sum():,}  |  Legitimate: {(1-y_binary).sum():,}")

    return feature_df.values, y_binary, feature_names


def train_model(X, y, feature_names):
    """Train RandomForest botnet detector."""
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y if y.sum() > 1 and y.sum() < len(y)-1 else None
    )

    print("\nTraining CTU-13 Botnet Detector (RandomForest)...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=18,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print(f"  Accuracy: {acc * 100:.2f}%")
    print(f"  F1 Score: {f1 * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Botnet'], zero_division=0))

    metrics = {'accuracy': round(acc, 4), 'f1': round(f1, 4)}
    return clf, scaler, metrics


def save_model(clf, scaler, feature_names, metrics, source='CTU-13'):
    """Save CTU-13 botnet detection model."""
    print("\nSaving botnet detection model...")
    with open(MODEL_DIR / 'ctu_botnet_model.pkl', 'wb') as f:
        pickle.dump(clf, f)
    with open(MODEL_DIR / 'ctu_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)

    metadata = {
        'dataset': source,
        'feature_names': feature_names,
        'metrics': metrics
    }
    with open(MODEL_DIR / 'ctu_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    print("   ctu_botnet_model.pkl")
    print("   ctu_scaler.pkl")
    print("   ctu_metadata.json")


def load_cic_botnet_fallback():
    """Fallback: train botnet detector on CIC-IDS2017 Bot/DDoS vs BENIGN when CTU tar is unavailable."""
    print("\n[Fallback] Using CIC-IDS2017 Bot/DDoS traffic as botnet proxy...")
    from ml_models.train_ids_model import load_dataset, preprocess, DROP_FEATURES
    import pandas as pd

    df = load_dataset(sample_per_file=8000)
    labels = df['Label'].astype(str)
    y_binary = labels.isin(['Bot', 'DDoS', 'PortScan']).astype(int).values
    drop_cols = [c for c in DROP_FEATURES if c in df.columns]
    feature_df = df.drop(columns=drop_cols + ['Label'], errors='ignore')
    feature_df = feature_df.select_dtypes(include=[np.number])
    feature_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    feature_df.fillna(feature_df.median(numeric_only=True), inplace=True)
    print(f"  Botnet samples: {y_binary.sum():,}  |  Benign: {(1-y_binary).sum():,}")
    return feature_df.values, y_binary, feature_df.columns.tolist(), 'CIC-IDS2017-Botnet-Proxy'


def main():
    print("=" * 65)
    print("  BIGIL - CTU-13 Botnet Traffic Classifier Trainer")
    print("=" * 65)

    import os
    source = 'CTU-13'
    use_fallback = os.environ.get('BIGIL_CTU_FALLBACK', '').lower() in ('1', 'true', 'yes')
    extracted = BASE_DIR / 'datasets' / 'CTU-13-Dataset'
    if extracted.exists() and any(extracted.rglob('*.csv')):
        csvs = list(extracted.rglob('*.csv'))[:MAX_FILES]
        dfs = [pd.read_csv(c, low_memory=False, nrows=MAX_ROWS_PER_FILE) for c in csvs]
        df = pd.concat(dfs, ignore_index=True)
        if 'Label' not in df.columns:
            df['Label'] = 'botnet'
        X, y, feature_names = preprocess(df)
    elif use_fallback:
        X, y, feature_names, source = load_cic_botnet_fallback()
    else:
        try:
            archive = find_archive()
            df = load_ctu_from_tar(archive)
            X, y, feature_names = preprocess(df)
        except Exception as e:
            print(f"\n  [Note] CTU-13 unavailable ({e})")
            print("  Using CIC-IDS2017 botnet traffic fallback.")
            X, y, feature_names, source = load_cic_botnet_fallback()

    clf, scaler, metrics = train_model(X, y, feature_names)
    save_model(clf, scaler, feature_names, metrics, source=source)

    print("\n" + "=" * 65)
    print(f"  Botnet Model Complete ({source})!  Accuracy: {metrics['accuracy']*100:.2f}%  F1: {metrics['f1']*100:.2f}%")
    print("=" * 65)

    return metrics


if __name__ == '__main__':
    main()
