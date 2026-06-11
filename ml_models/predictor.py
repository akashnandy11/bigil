"""
BIGIL ML Predictor — Unified Prediction API
Loads trained models ONCE at import time (not per-request).
Provides fast inference for network flow analysis and attack classification.
"""

import json
import pickle
import numpy as np
from pathlib import Path
from typing import Optional

MODEL_DIR = Path(__file__).parent

# ── Lazy-loaded model state ────────────────────────────────────────────────────
_ids_models = None
_unsw_models = None
_log_model = None


def _load_ids_models():
    """Load CIC-IDS2017 models into memory (called once)."""
    global _ids_models
    if _ids_models is not None:
        return _ids_models

    try:
        with open(MODEL_DIR / 'ids_binary_model.pkl', 'rb') as f:
            binary_model = pickle.load(f)
        with open(MODEL_DIR / 'ids_multi_model.pkl', 'rb') as f:
            multi_model = pickle.load(f)
        with open(MODEL_DIR / 'ids_label_encoder.pkl', 'rb') as f:
            label_encoder = pickle.load(f)
        with open(MODEL_DIR / 'ids_scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        with open(MODEL_DIR / 'ids_metadata.json', 'r') as f:
            metadata = json.load(f)

        _ids_models = {
            'binary': binary_model,
            'multi': multi_model,
            'label_encoder': label_encoder,
            'scaler': scaler,
            'feature_names': metadata['feature_names'],
            'metrics': {
                'binary': metadata['binary_metrics'],
                'multi': metadata['multi_metrics']
            }
        }
        return _ids_models
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[BIGIL-ML] Error loading IDS models: {e}")
        return None


def _load_unsw_models():
    """Load UNSW-NB15 models into memory (called once)."""
    global _unsw_models
    if _unsw_models is not None:
        return _unsw_models

    try:
        with open(MODEL_DIR / 'unsw_multi_model.pkl', 'rb') as f:
            multi_model = pickle.load(f)
        with open(MODEL_DIR / 'unsw_binary_model.pkl', 'rb') as f:
            binary_model = pickle.load(f)
        with open(MODEL_DIR / 'unsw_label_encoder.pkl', 'rb') as f:
            label_encoder = pickle.load(f)
        with open(MODEL_DIR / 'unsw_cat_encoders.pkl', 'rb') as f:
            cat_encoders = pickle.load(f)
        with open(MODEL_DIR / 'unsw_scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        with open(MODEL_DIR / 'unsw_metadata.json', 'r') as f:
            metadata = json.load(f)

        _unsw_models = {
            'multi': multi_model,
            'binary': binary_model,
            'label_encoder': label_encoder,
            'cat_encoders': cat_encoders,
            'scaler': scaler,
            'feature_names': metadata['feature_names'],
            'attack_categories': metadata['attack_categories'],
            'metrics': metadata['metrics']
        }
        return _unsw_models
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[BIGIL-ML] Error loading UNSW models: {e}")
        return None


def _load_log_model():
    """Load LogHub TF-IDF anomaly classifier."""
    global _log_model
    if _log_model is not None:
        return _log_model
    try:
        with open(MODEL_DIR / 'log_anomaly_model.pkl', 'rb') as f:
            pipeline = pickle.load(f)
        with open(MODEL_DIR / 'log_metadata.json', 'r') as f:
            metadata = json.load(f)
        _log_model = {'pipeline': pipeline, 'metrics': metadata.get('metrics', {})}
        return _log_model
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[BIGIL-ML] Error loading log model: {e}")
        return None


def models_loaded() -> dict:
    """Return status of loaded models."""
    ids = _load_ids_models()
    unsw = _load_unsw_models()
    log_m = _load_log_model()
    return {
        'ids_loaded': ids is not None,
        'unsw_loaded': unsw is not None,
        'log_loaded': log_m is not None,
        'ids_metrics': ids['metrics'] if ids else None,
        'unsw_metrics': unsw['metrics'] if unsw else None,
        'log_metrics': log_m['metrics'] if log_m else None,
    }


def predict_log_anomaly(log_text: str) -> dict:
    """Classify a log line using the LogHub-trained TF-IDF + RandomForest model."""
    model = _load_log_model()
    if model is None:
        return {'is_anomaly': False, 'confidence': 0.0, 'error': 'Log model not trained'}
    try:
        proba = model['pipeline'].predict_proba([log_text])[0]
        pred = int(model['pipeline'].predict([log_text])[0])
        confidence = float(proba[pred] * 100)
        return {
            'is_anomaly': bool(pred == 1),
            'confidence': round(confidence, 2),
            'model_accuracy': round(model['metrics'].get('accuracy', 0) * 100, 2),
            'dataset': 'LogHub'
        }
    except Exception as e:
        return {'is_anomaly': False, 'confidence': 0.0, 'error': str(e)}


def predict_network_flow(features: dict) -> dict:
    """
    Predict if a network flow is malicious using CIC-IDS2017 model.
    
    Args:
        features: dict mapping feature_name -> numeric_value
        
    Returns:
        {
            'is_malicious': bool,
            'confidence': float (0-100),
            'attack_type': str,
            'risk_level': str,  # critical/high/medium/low
            'model_accuracy': float
        }
    """
    models = _load_ids_models()
    if models is None:
        return {
            'is_malicious': False,
            'confidence': 0.0,
            'attack_type': 'Unknown (model not trained)',
            'risk_level': 'unknown',
            'model_accuracy': 0.0,
            'error': 'Models not trained yet. Run python train_all_models.py first.'
        }

    # Build feature vector in correct order
    feature_names = models['feature_names']
    X = np.array([features.get(f, 0.0) for f in feature_names]).reshape(1, -1)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Scale
    X_scaled = models['scaler'].transform(X)

    # Binary prediction
    proba = models['binary'].predict_proba(X_scaled)[0]
    is_malicious = bool(proba[1] > 0.5)
    confidence = float(proba[1] * 100)

    # Attack type (multiclass)
    attack_idx = models['multi'].predict(X_scaled)[0]
    attack_type = models['label_encoder'].classes_[attack_idx]

    # Risk level based on confidence
    if confidence >= 85:
        risk_level = 'critical'
    elif confidence >= 65:
        risk_level = 'high'
    elif confidence >= 40:
        risk_level = 'medium'
    else:
        risk_level = 'low'

    return {
        'is_malicious': is_malicious,
        'confidence': round(confidence, 2),
        'attack_type': attack_type if is_malicious else 'BENIGN',
        'risk_level': risk_level if is_malicious else 'info',
        'model_accuracy': round(models['metrics']['binary'].get('accuracy', 0) * 100, 2)
    }


def predict_attack_category(features: dict) -> dict:
    """
    Predict attack category using UNSW-NB15 model.
    
    Args:
        features: dict with UNSW-NB15 feature names
        
    Returns:
        {
            'is_attack': bool,
            'attack_category': str,
            'confidence': float,
            'all_probabilities': dict
        }
    """
    models = _load_unsw_models()
    if models is None:
        return {
            'is_attack': False,
            'attack_category': 'Unknown (model not trained)',
            'confidence': 0.0,
            'all_probabilities': {},
            'error': 'UNSW models not trained yet.'
        }

    feature_names = models['feature_names']
    cat_encoders = models['cat_encoders']

    # Encode categorical features
    encoded_features = {}
    for fname in feature_names:
        val = features.get(fname, 0)
        if fname in cat_encoders:
            try:
                val = cat_encoders[fname].transform([str(val)])[0]
            except ValueError:
                val = 0  # unknown category
        encoded_features[fname] = val

    X = np.array([encoded_features.get(f, 0.0) for f in feature_names]).reshape(1, -1)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = models['scaler'].transform(X)

    # Multiclass prediction
    proba_multi = models['multi'].predict_proba(X_scaled)[0]
    pred_idx = np.argmax(proba_multi)
    attack_category = models['label_encoder'].classes_[pred_idx]
    confidence = float(proba_multi[pred_idx] * 100)

    # Binary prediction
    proba_bin = models['binary'].predict_proba(X_scaled)[0]
    is_attack = bool(proba_bin[1] > 0.5)

    all_probas = {
        cat: round(float(p * 100), 2)
        for cat, p in zip(models['attack_categories'], proba_multi)
    }

    return {
        'is_attack': is_attack,
        'attack_category': attack_category,
        'confidence': round(confidence, 2),
        'all_probabilities': all_probas
    }


def analyze_log_entry(log_text: str) -> dict:
    """
    Heuristic log analysis (when ML features aren't available).
    Scans log text for known attack indicators.
    """
    INDICATORS = {
        'sql_injection': ['SELECT', 'UNION', 'DROP TABLE', 'OR 1=1', 'xp_cmdshell', "' OR '"],
        'xss': ['<script>', 'javascript:', 'onerror=', 'alert(', 'document.cookie'],
        'path_traversal': ['../../../', '..\\..\\', '/etc/passwd', '/etc/shadow'],
        'brute_force': ['Failed password', 'authentication failure', 'Invalid user', 'Too many'],
        'command_injection': ['cmd.exe', 'powershell', '/bin/sh', 'wget ', 'curl '],
        'malware_ioc': ['mimikatz', 'meterpreter', 'cobalt strike', 'wannacry', 'petya'],
        'data_exfiltration': ['base64', 'encoded payload', 'large outbound', 'DNS tunnel'],
        'dos_attack': ['SYN flood', 'ICMP flood', '429 Too Many', 'rate limit exceeded'],
    }

    text_lower = log_text.lower()
    findings = []
    severity = 'info'

    for attack_type, patterns in INDICATORS.items():
        for pattern in patterns:
            if pattern.lower() in text_lower:
                findings.append({
                    'type': attack_type,
                    'pattern': pattern,
                    'severity': 'critical' if attack_type in ['sql_injection', 'malware_ioc', 'command_injection'] else 'high'
                })
                severity = 'critical' if attack_type in ['sql_injection', 'malware_ioc', 'command_injection'] else severity

    is_malicious = len(findings) > 0
    if findings:
        sev_levels = [f['severity'] for f in findings]
        severity = 'critical' if 'critical' in sev_levels else 'high' if 'high' in sev_levels else 'medium'

    return {
        'is_malicious': is_malicious,
        'severity': severity,
        'findings': findings,
        'confidence': min(100, len(findings) * 25),
        'attack_types': list(set(f['type'] for f in findings))
    }


def analyze_investigation_logs(log_entries: list) -> dict:
    """Run full investigation engine analysis on parsed log entries."""
    try:
        from ml_models.investigation_engine import analyze_threats
        return analyze_threats(log_entries)
    except Exception as e:
        return {'error': str(e), 'slow_poison': {'detected': False, 'risk_score': 0}}


def detect_slow_poison(log_text: str) -> dict:
    """Detect long-term compromise indicators in raw log text."""
    try:
        from ml_models.investigation_engine import detect_slow_poison as _detect
        entries = [{'raw': line, 'line_num': i, 'timestamp': '', 'ip': ''}
                   for i, line in enumerate(log_text.split('\n')) if line.strip()]
        return _detect(entries)
    except Exception as e:
        return {'detected': False, 'error': str(e)}
