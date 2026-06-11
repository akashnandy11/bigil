"""
BIGIL — Train All ML Models
One-command script to train both CIC-IDS2017 and UNSW-NB15 models.
Run this from the project root: python train_all_models.py
"""

import sys
import time
from pathlib import Path

def print_header(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)

def main():
    print_header("BIGIL Forensic Platform — ML Model Training Suite")
    print("""
  Datasets:
    - CIC-IDS2017  -> Network Intrusion Detection (RandomForest)
    - UNSW-NB15    -> Attack Category Classification (RandomForest)
    - LogHub       -> Log Anomaly Detection (TF-IDF + RandomForest)
    - CTU-13       -> Botnet Traffic Detection (RandomForest, streamed)

  This may take 5-20 minutes depending on your hardware.
  Models will be saved to: ml_models/
    """)

    results = {}
    total_start = time.time()

    # -- Train CIC-IDS2017 ------------------------------------------
    print_header("Step 1/4 - CIC-IDS2017 Network Intrusion Detection")
    try:
        from ml_models.train_ids_model import main as train_ids
        t = time.time()
        binary_m, multi_m = train_ids()
        elapsed = time.time() - t
        results['IDS (CIC-IDS2017)'] = {
            'status': 'SUCCESS',
            'binary_accuracy': f"{binary_m['accuracy']*100:.2f}%",
            'binary_f1': f"{binary_m['f1']*100:.2f}%",
            'multi_accuracy': f"{multi_m['accuracy']*100:.2f}%",
            'time': f"{elapsed:.1f}s"
        }
    except Exception as e:
        results['IDS (CIC-IDS2017)'] = {'status': f'FAILED: {e}'}
        print(f"\n  Error: {e}")

    # -- Train UNSW-NB15 --------------------------------------------
    print_header("Step 2/4 - UNSW-NB15 Attack Category Classifier")
    try:
        from ml_models.train_unsw_model import main as train_unsw
        t = time.time()
        unsw_m = train_unsw()
        elapsed = time.time() - t
        results['Attack Classifier (UNSW-NB15)'] = {
            'status': 'SUCCESS',
            'multi_accuracy': f"{unsw_m['multiclass']['accuracy']*100:.2f}%",
            'multi_f1': f"{unsw_m['multiclass']['f1_weighted']*100:.2f}%",
            'binary_accuracy': f"{unsw_m['binary']['accuracy']*100:.2f}%",
            'time': f"{elapsed:.1f}s"
        }
    except Exception as e:
        results['Attack Classifier (UNSW-NB15)'] = {'status': f'FAILED: {e}'}
        print(f"\n  Error: {e}")

    # -- Train LogHub -----------------------------------------------
    print_header("Step 3/4 - LogHub Log Anomaly Classifier")
    try:
        from ml_models.train_log_model import main as train_log
        t = time.time()
        log_m = train_log()
        elapsed = time.time() - t
        results['Log Anomaly (LogHub)'] = {
            'status': 'SUCCESS',
            'accuracy': f"{log_m['accuracy']*100:.2f}%",
            'f1': f"{log_m['f1']*100:.2f}%",
            'time': f"{elapsed:.1f}s"
        }
    except Exception as e:
        results['Log Anomaly (LogHub)'] = {'status': f'FAILED: {e}'}
        print(f"\n  Error: {e}")

    # -- Train CTU-13 -----------------------------------------------
    print_header("Step 4/4 - CTU-13 Botnet Traffic Classifier")
    try:
        from ml_models.train_ctu_model import main as train_ctu
        t = time.time()
        ctu_m = train_ctu()
        elapsed = time.time() - t
        results['Botnet Detector (CTU-13)'] = {
            'status': 'SUCCESS',
            'accuracy': f"{ctu_m['accuracy']*100:.2f}%",
            'f1': f"{ctu_m['f1']*100:.2f}%",
            'time': f"{elapsed:.1f}s"
        }
    except Exception as e:
        results['Botnet Detector (CTU-13)'] = {'status': f'FAILED: {e}'}
        print(f"\n  Error: {e}")

    # -- Summary ----------------------------------------------------
    total_time = time.time() - total_start
    print_header(f"Training Complete - Total time: {total_time:.1f}s")

    for model_name, r in results.items():
        print(f"\n   {model_name}")
        print(f"     Status: {r['status']}")
        for k, v in r.items():
            if k != 'status':
                label = k.replace('_', ' ').title()
                print(f"     {label:<25} {v}")

    print("\n" + "=" * 65)
    print("  Models saved to ml_models/ directory.")
    print("  The Flask app will load these automatically on next startup.")
    print("=" * 65 + "\n")


if __name__ == '__main__':
    main()
