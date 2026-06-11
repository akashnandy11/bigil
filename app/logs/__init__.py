import os
import json
import io
import csv
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import db
import re

logs = Blueprint('logs', __name__)

SEVERITY_PATTERNS = {
    'critical': [r'CRITICAL', r'EMERGENCY', r'kernel panic', r'ransomware', r'exfiltration', r'data breach'],
    'high': [r'ERROR', r'FAILED LOGIN', r'unauthorized', r'privilege escalation', r'lateral movement',
             r'suspicious process', r'malware detected', r'brute.?force'],
    'medium': [r'WARNING', r'WARN', r'failed', r'denied', r'rejected', r'blocked', r'multiple login'],
    'low': [r'INFO', r'NOTICE', r'started', r'stopped', r'connected']
}


def classify_severity(line):
    line_upper = line.upper()
    for severity, patterns in SEVERITY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return severity
    return 'info'


def parse_log_lines(content, log_type='generic'):
    lines = content.split('\n')
    parsed = []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        severity = classify_severity(line)
        # Try to extract timestamp
        ts_match = re.search(r'\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}', line)
        timestamp = ts_match.group(0) if ts_match else ''
        # Try to extract IP
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        ip = ip_match.group(0) if ip_match else ''
        parsed.append({
            'line_num': i + 1,
            'raw': line,
            'severity': severity,
            'timestamp': timestamp,
            'ip': ip
        })
    return parsed


@logs.route('/')
@login_required
def index():
    try:
        from ml_models.predictor import models_loaded
        ml_status = models_loaded()
    except Exception:
        ml_status = {'ids_loaded': False, 'unsw_loaded': False, 'log_loaded': False}
    return render_template('logs/index.html', ml_status=ml_status)


@logs.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    parsed_logs = []
    anomalies = []
    stats = {}
    threat_analysis = None
    log_type = 'generic'
    filename = ''

    if request.method == 'POST':
        log_type = request.form.get('log_type', 'generic')

        if 'log_file' in request.files and request.files['log_file'].filename:
            file = request.files['log_file']
            filename = secure_filename(file.filename)
            content = file.read().decode('utf-8', errors='ignore')
        else:
            content = request.form.get('log_text', '')

        if content:
            parsed_logs = parse_log_lines(content, log_type)
            # Stats
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for entry in parsed_logs:
                sv = entry['severity']
                severity_counts[sv] = severity_counts.get(sv, 0) + 1

            # Anomalies = critical + high entries
            anomalies = [e for e in parsed_logs if e['severity'] in ('critical', 'high')]

            # AI anomaly scoring using basic threshold
            total = len(parsed_logs)
            anomaly_pct = round((len(anomalies) / total * 100) if total > 0 else 0, 1)

            stats = {
                'total_lines': total,
                'severity_counts': severity_counts,
                'anomaly_count': len(anomalies),
                'anomaly_pct': anomaly_pct,
                'unique_ips': len(set(e['ip'] for e in parsed_logs if e['ip']))
            }

            # LogHub ML model + Isolation Forest ensemble
            ml_anomaly_count = 0
            try:
                from ml_models.predictor import predict_log_anomaly, models_loaded
                ml_status = models_loaded()
                stats['ml_models'] = ml_status
                if ml_status.get('log_loaded'):
                    for entry in parsed_logs:
                        pred = predict_log_anomaly(entry['raw'])
                        entry['ml_anomaly'] = pred.get('is_anomaly', False)
                        entry['ml_confidence'] = pred.get('confidence', 0)
                        if entry['ml_anomaly']:
                            ml_anomaly_count += 1
                    stats['ml_anomaly_count'] = ml_anomaly_count
            except Exception:
                stats['ml_models'] = {'log_loaded': False}

            if total > 20:
                try:
                    import numpy as np
                    from sklearn.ensemble import IsolationForest
                    X = np.array([[len(e['raw']), len(e['ip'])] for e in parsed_logs])
                    clf = IsolationForest(contamination=0.1, random_state=42)
                    preds = clf.fit_predict(X)
                    ai_anomaly_indices = set(i for i, p in enumerate(preds) if p == -1)
                    for i, entry in enumerate(parsed_logs):
                        entry['ai_anomaly'] = i in ai_anomaly_indices
                    stats['ai_anomaly_count'] = len(ai_anomaly_indices)
                except Exception:
                    stats['ai_anomaly_count'] = 0

            # Heuristic + ML log analysis per line
            try:
                from ml_models.predictor import analyze_log_entry
                heuristic_hits = 0
                for entry in parsed_logs:
                    h = analyze_log_entry(entry['raw'])
                    entry['heuristic_findings'] = h.get('findings', [])
                    if h.get('is_malicious'):
                        heuristic_hits += 1
                stats['heuristic_hits'] = heuristic_hits
            except Exception:
                pass

            # Advanced investigation engine: slow poison, entity analysis, early warnings
            try:
                from ml_models.investigation_engine import analyze_threats
                threat_analysis = analyze_threats(parsed_logs)
            except Exception:
                threat_analysis = None

            flash(
                f'Analysis complete: {stats.get("total_lines", 0)} lines, '
                f'{stats.get("anomaly_count", 0)} anomalies, '
                f'{stats.get("heuristic_hits", 0)} threat pattern hits.',
                'success'
            )
        else:
            threat_analysis = None
            flash('No log content provided. Paste logs or upload a file.', 'warning')
    else:
        threat_analysis = None

    return render_template('logs/analyze.html',
                           parsed_logs=parsed_logs,
                           anomalies=anomalies,
                           stats=stats,
                           log_type=log_type,
                           filename=filename,
                           threat_analysis=threat_analysis)


@logs.route('/network', methods=['GET', 'POST'])
@login_required
def network():
    """Analyze network flows using CIC-IDS2017 / UNSW-NB15 trained ML models."""
    results = []
    stats = {}
    dataset = 'cic'
    source_file = ''
    proof_sha256 = ''

    evidence_dir = os.path.join(current_app.root_path, '..', 'uploads', 'dataset_evidence')
    dataset_files = {
        'cic': [
            ('CIC-IDS2017_DDoS_flows.csv', 'CIC-IDS2017 DDoS'),
            ('CIC-IDS2017_PortScan_flows.csv', 'CIC-IDS2017 PortScan'),
            ('CIC-IDS2017_Web_Attacks_flows.csv', 'CIC-IDS2017 Web Attacks'),
        ],
        'unsw': [
            ('UNSW-NB15_DoS_flows.csv', 'UNSW-NB15 DoS'),
            ('UNSW-NB15_Exploits_flows.csv', 'UNSW-NB15 Exploits'),
            ('UNSW-NB15_Reconnaissance_flows.csv', 'UNSW-NB15 Reconnaissance'),
        ],
    }

    if request.method == 'POST':
        dataset = request.form.get('dataset', 'cic')
        selected = request.form.get('dataset_file', '')

        import pandas as pd
        from ml_models.predictor import predict_network_flow, predict_attack_category, models_loaded

        stats['ml_models'] = models_loaded()
        fpath = None

        if 'flow_file' in request.files and request.files['flow_file'].filename:
            file = request.files['flow_file']
            filename = secure_filename(file.filename)
            fpath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(fpath)
            source_file = filename
        elif selected:
            fpath = os.path.join(evidence_dir, selected)
            source_file = selected

        if fpath and os.path.isfile(fpath):
            import hashlib
            h = hashlib.sha256()
            with open(fpath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            proof_sha256 = h.hexdigest()

            df = pd.read_csv(fpath, nrows=50, low_memory=False)
            df.columns = df.columns.str.strip()
            if ' Label' in df.columns:
                df = df.rename(columns={' Label': 'Label'})

            malicious_count = 0
            for _, row in df.iterrows():
                features = {c: row.get(c, 0) for c in df.columns if c != 'Label'}
                if dataset == 'unsw':
                    pred = predict_attack_category(features)
                    is_bad = pred.get('is_attack', False)
                    label = pred.get('attack_category', 'Unknown')
                else:
                    pred = predict_network_flow(features)
                    is_bad = pred.get('is_malicious', False)
                    label = pred.get('attack_type', 'BENIGN')

                actual_label = str(row.get('Label', row.get('attack_cat', '')))
                if is_bad:
                    malicious_count += 1
                results.append({
                    'prediction': label,
                    'confidence': pred.get('confidence', 0),
                    'is_malicious': is_bad,
                    'actual_label': actual_label if actual_label not in ('nan', '') else '—',
                    'risk_level': pred.get('risk_level', 'medium'),
                    'match': actual_label.lower() in label.lower() if actual_label not in ('', 'nan', 'Normal', 'BENIGN') else not is_bad
                })

            stats = {
                'total_flows': len(results),
                'malicious_detected': malicious_count,
                'source': source_file,
                'sha256': proof_sha256,
                'dataset': dataset.upper(),
                'ml_models': stats.get('ml_models', models_loaded()),
            }
            flash(
                f'Network ML analysis complete: {malicious_count}/{len(results)} malicious flows detected.',
                'success'
            )
        elif request.method == 'POST':
            flash('Could not load the selected flow file. Choose a dataset sample or upload a CSV.', 'warning')

    try:
        from ml_models.predictor import models_loaded
        ml_status = models_loaded()
    except Exception:
        ml_status = {'ids_loaded': False, 'unsw_loaded': False, 'log_loaded': False}

    return render_template('logs/network.html',
                           results=results,
                           stats=stats,
                           dataset=dataset,
                           dataset_files=dataset_files,
                           source_file=source_file,
                           proof_sha256=proof_sha256,
                           ml_status=ml_status)


@logs.route('/api/sample-logs')
@login_required
def api_sample_logs():
    """Load real LogHub dataset log lines as analysis sample."""
    from pathlib import Path
    loghub = Path(current_app.root_path).parent / 'datasets' / 'raw' / 'loghub-master'
    candidates = [
        loghub / 'OpenSSH' / 'OpenSSH_2k.log',
        loghub / 'Linux' / 'Linux_2k.log',
        loghub / 'BGL' / 'BGL_2k.log',
    ]
    lines = []
    source = 'LogHub Dataset'
    for fpath in candidates:
        if fpath.exists():
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [ln.strip() for ln in f.readlines()[:80] if ln.strip()]
            source = f'LogHub — {fpath.parent.name}/{fpath.name}'
            break
    if not lines:
        return jsonify({'sample': '', 'source': 'No LogHub files found. Run import_real_data.py'})
    return jsonify({'sample': '\n'.join(lines), 'source': source})
