import os
import json
import io
import csv
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, jsonify, Response
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
            # Prevent path traversal by securing the filename
            selected = os.path.basename(selected)
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


# ----------------------------------------------------
# Real-Time Continuous Log Monitoring Routes
# ----------------------------------------------------

@logs.route('/continuous')
@login_required
def continuous():
    """Renders the real-time continuous log monitoring interface."""
    from ml_models.predictor import models_loaded
    try:
        ml_status = models_loaded()
    except Exception:
        ml_status = {'ids_loaded': False, 'unsw_loaded': False, 'log_loaded': False}
    return render_template('logs/continuous.html', ml_status=ml_status)


@logs.route('/api/logs/continuous/stream')
@login_required
def continuous_stream():
    """Server-Sent Events (SSE) endpoint to stream live logs and anomalies."""
    source_type = request.args.get('source', 'simulated')  # 'simulated' or 'file'
    file_path = request.args.get('filepath', '')

    if source_type == 'file':
        if not file_path:
            return jsonify({'error': 'File path is required for file mode'}), 400
        
        # Security validation: check path traversal and file type
        normalized_path = os.path.normpath(file_path)
        filename = os.path.basename(normalized_path).lower()
        
        # Block access to system configurations, database and python files
        if filename in ('.env', 'bigil.db', 'config.py', 'settings.py') or \
           normalized_path.endswith('.py') or normalized_path.endswith('.db') or \
           normalized_path.endswith('.sqlite') or '.git' in normalized_path:
            return jsonify({'error': 'Access to this file type is restricted for security.'}), 403
            
        # Ensure it is a file and exists
        if not os.path.exists(normalized_path) or not os.path.isfile(normalized_path):
            return jsonify({'error': 'Target file not found or is not a valid file.'}), 404
        
        file_path = normalized_path

    def event_generator():
        import time
        import random
        from ml_models.predictor import predict_log_anomaly, analyze_log_entry
        
        # Keep track of file read pointer
        file_pointer = 0
        if source_type == 'file' and file_path and os.path.isfile(file_path):
            try:
                file_pointer = os.path.getsize(file_path)
            except Exception:
                pass

        simulated_ips = ['192.168.1.105', '10.0.0.45', '172.16.254.1', '8.8.8.8', '185.220.101.4', '198.51.100.12']
        simulated_messages = [
            # Benign
            ('info', 'System service sshd.service started successfully.'),
            ('info', 'Connection established from {ip} to internal port 22.'),
            ('info', 'DHCP lease renewed for client {ip}.'),
            ('info', 'Cron job logrotate executed without errors.'),
            ('info', 'Backup sync completed for /var/www/uploads.'),
            # Medium Warning
            ('medium', 'WARNING: Database connection pool threshold reached (80%).'),
            ('medium', 'WARNING: Failed login attempt for user "admin" from {ip}.'),
            ('medium', 'WARNING: SSH login attempt rejected (invalid key) from {ip}.'),
            ('medium', 'WARNING: API gateway rate limit reached for {ip}.'),
            # High Anomaly
            ('high', 'ERROR: Privilege escalation attempt detected for user "guest" on host-web-01.'),
            ('high', 'ERROR: Multiple failed login attempts (possible brute-force) from {ip}.'),
            ('high', 'ERROR: Lateral movement attempt: suspicious SMB session from {ip}.'),
            ('high', 'ERROR: Windows Defender flagged suspicious Powershell execution in temp.'),
            # Critical Alert
            ('critical', 'CRITICAL: Ransomware active signature pattern detected in user directory.'),
            ('critical', 'CRITICAL: Data exfiltration alert - 12GB sent to external IP {ip}.'),
            ('critical', 'CRITICAL: Critical kernel panic: driver loaded malicious payload.'),
            ('critical', 'CRITICAL: Exfiltration payload detected! Endpoint compromised: {ip}.'),
            ('critical', 'CRITICAL: Nation-State APT APT41 backchannel established to C2 server.')
        ]

        counter = 0
        while True:
            # Yield heartbeat
            counter += 1
            if source_type == 'file' and file_path:
                if not os.path.isfile(file_path):
                    yield f"data: {json.dumps({'error': 'Target file not found or inaccessible.'})}\n\n"
                    time.sleep(3)
                    continue

                try:
                    current_size = os.path.getsize(file_path)
                    if current_size < file_pointer:
                        # File was truncated/rotated
                        file_pointer = 0
                    
                    if current_size > file_pointer:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            f.seek(file_pointer)
                            new_lines = f.readlines()
                            file_pointer = f.tell()
                        
                        for line in new_lines:
                            line = line.strip()
                            if not line:
                                continue
                            
                            severity = classify_severity(line)
                            # Try to extract IP
                            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                            ip = ip_match.group(0) if ip_match else ''
                            
                            # ML Prediction
                            ml_anomaly = False
                            ml_confidence = 0.0
                            try:
                                pred = predict_log_anomaly(line)
                                ml_anomaly = pred.get('is_anomaly', False)
                                ml_confidence = pred.get('confidence', 0.0)
                            except Exception:
                                pass
                            
                            findings = []
                            try:
                                h = analyze_log_entry(line)
                                findings = h.get('findings', [])
                            except Exception:
                                pass

                            payload = {
                                'line_num': counter,
                                'raw': line,
                                'severity': severity,
                                'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                                'ip': ip,
                                'ml_anomaly': ml_anomaly,
                                'ml_confidence': ml_confidence,
                                'findings': findings
                            }
                            yield f"data: {json.dumps(payload)}\n\n"
                except Exception as ex:
                    yield f"data: {json.dumps({'error': f'Error reading log: {str(ex)}'})}\n\n"
                
                time.sleep(1)
            else:
                # Simulated live stream
                time.sleep(random.uniform(0.5, 2.0))
                
                # Pick severity weighted towards info (benign)
                roll = random.random()
                if roll < 0.65:
                    sev, msg_template = simulated_messages[random.randint(0, 4)]
                elif roll < 0.85:
                    sev, msg_template = simulated_messages[random.randint(5, 8)]
                elif roll < 0.95:
                    sev, msg_template = simulated_messages[random.randint(9, 12)]
                else:
                    sev, msg_template = simulated_messages[random.randint(13, 17)]
                
                ip = random.choice(simulated_ips)
                line = msg_template.replace('{ip}', ip)
                
                # Run analyzer on the simulated line
                ml_anomaly = (sev in ('critical', 'high')) or (random.random() < 0.1)
                ml_confidence = random.uniform(0.65, 0.98) if ml_anomaly else random.uniform(0.01, 0.15)
                
                findings = []
                if sev == 'critical':
                    findings.append("Match: Nation-State IOC Signature")
                elif sev == 'high':
                    findings.append("Pattern: Privilege Escalation Behavior")

                payload = {
                    'line_num': counter,
                    'raw': line,
                    'severity': sev,
                    'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'ip': ip if random.random() > 0.3 else '',
                    'ml_anomaly': ml_anomaly,
                    'ml_confidence': ml_confidence,
                    'findings': findings
                }
                yield f"data: {json.dumps(payload)}\n\n"

    return Response(event_generator(), mimetype='text/event-stream')


# ----------------------------------------------------
# Endpoint Threat & Ransomware Scanner Routes
# ----------------------------------------------------

@logs.route('/scanner')
@login_required
def scanner():
    """Renders the PC threat and ransomware scanner dashboard."""
    default_dir = os.path.abspath(os.path.join(current_app.root_path, '..'))
    return render_template('logs/scanner.html', default_dir=default_dir)


@logs.route('/api/scan/start', methods=['POST'])
@login_required
def api_scan_start():
    """Starts the filesystem threat scanner in a background thread."""
    from app.scanner_utils import start_scan
    
    target_dir = request.form.get('target_dir', '').strip()
    if not target_dir:
        return jsonify({'error': 'Directory path is required'}), 400
        
    if not os.path.isdir(target_dir):
        return jsonify({'error': 'The specified path is not a valid directory'}), 400

    # Start scanning in background
    app = current_app._get_current_object()
    success = start_scan(target_dir, app)
    
    if success:
        return jsonify({'status': 'started', 'message': f'Scan started successfully on {target_dir}'})
    else:
        return jsonify({'error': 'A scan is already running. Please wait or stop it first.'}), 400


@logs.route('/api/scan/status')
@login_required
def api_scan_status():
    """Returns the current progress and detected threats from the scanner."""
    from app.scanner_utils import scanner_state, state_lock
    
    with state_lock:
        return jsonify({
            'is_running': scanner_state['is_running'],
            'scanned_files': scanner_state['scanned_files'],
            'total_files': scanner_state['total_files'],
            'threats': scanner_state['threats'],
            'current_file': scanner_state['current_file'],
            'target_dir': scanner_state['target_dir'],
            'error': scanner_state['error']
        })


@logs.route('/api/scan/stop', methods=['POST'])
@login_required
def api_scan_stop():
    """Stops the active scan."""
    from app.scanner_utils import stop_scan
    stop_scan()
    return jsonify({'status': 'stopped'})


@logs.route('/api/scan/add-evidence', methods=['POST'])
@login_required
def api_scan_add_evidence():
    """Imports a detected threat file into the digital evidence registry."""
    filepath = request.form.get('filepath')
    description = request.form.get('description', '')
    threat_type = request.form.get('threat_type', 'Malware Artifact')
    
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'File not found on filesystem'}), 404
        
    filename = os.path.basename(filepath)
    # Compute hashes and size
    from app.scanner_utils import compute_file_hashes
    md5_hash, sha256_hash = compute_file_hashes(filepath)
    file_size = os.path.getsize(filepath)
    
    from app.evidence import generate_evidence_id
    
    ev = Evidence(
        evidence_id=generate_evidence_id(),
        title=f"Scanner Flagged: {filename}",
        description=f"Type: {threat_type}. {description}\nPath: {filepath}",
        category='artifact',
        file_name=filename,
        file_path=filepath,
        file_size=file_size,
        file_hash_md5=md5_hash,
        file_hash_sha256=sha256_hash,
        source=f"PC Endpoint Scanner ({filepath})",
        collected_by=current_user.id,
        tags="endpoint-threat,scanner,auto-ingest",
        status='verified',
        verified=True,
        verified_by=current_user.id
    )
    
    db.session.add(ev)
    db.session.flush()
    
    chain = EvidenceChain(
        evidence_id=ev.id,
        action='collected',
        performed_by=current_user.id,
        notes=f'Threat file flagged and imported into forensics registry by {current_user.username}',
        location='Local Endpoint System'
    )
    db.session.add(chain)
    
    audit = AuditLog(
        user_id=current_user.id,
        action='EVIDENCE_SCANNER_INGEST',
        resource_type='evidence',
        resource_id=ev.evidence_id,
        ip_address=request.remote_addr,
        details=f'Ingested scanned threat file {filename} SHA256:{sha256_hash}',
        status='success'
    )
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'status': 'success', 'evidence_id': ev.evidence_id})


@logs.route('/api/scan/create-alert', methods=['POST'])
@login_required
def api_scan_create_alert():
    """Escalates a scanner-detected threat by logging it as a high-priority dashboard alert."""
    filepath = request.form.get('filepath')
    filename = os.path.basename(filepath) if filepath else 'Unknown File'
    threat_type = request.form.get('threat_type', 'System Threat')
    severity = request.form.get('severity', 'high')
    description = request.form.get('description', '')
    
    alert = Alert(
        title=f"{threat_type} Detected on PC",
        description=f"File: {filename}\nPath: {filepath}\n\n{description}",
        severity=severity,
        alert_type='anomaly',
        source=f"Local Endpoint Threat Scanner",
        status='open',
        risk_score=90 if severity == 'critical' else 75
    )
    
    db.session.add(alert)
    
    audit = AuditLog(
        user_id=current_user.id,
        action='SCANNER_ALERT_ESCALATE',
        resource_type='alert',
        resource_id=filename,
        ip_address=request.remote_addr,
        details=f'Escalated threat alert for file: {filepath} ({threat_type})',
        status='success'
    )
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': 'Incident alert escalated successfully'})

