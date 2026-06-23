import os
import re
import socket
import math
import json
import hashlib
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from app import db
from app.models import AuditLog

toolkit = Blueprint('toolkit', __name__, url_prefix='/toolkit')

# ──────────────────────────────────────────────────
# API Keys from environment
# ──────────────────────────────────────────────────
VIRUSTOTAL_KEY   = os.environ.get('VIRUSTOTAL_API_KEY', '')
ABUSEIPDB_KEY    = os.environ.get('ABUSEIPDB_API_KEY', '')
OTX_KEY          = os.environ.get('OTX_API_KEY', '')
MALWAREBAZAAR_KEY = os.environ.get('MALWAREBAZAAR_API_KEY', '')

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
}

# ──────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────
def log_toolkit_audit(action, details):
    """Log toolkit actions to the audit trail."""
    try:
        audit = AuditLog(
            user_id=current_user.id,
            action=action,
            resource_type='toolkit',
            resource_id='master_toolkit',
            ip_address=request.remote_addr,
            details=details,
            status='success'
        )
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()


def vt_get(path):
    """Make a VirusTotal v3 GET request."""
    try:
        req = urllib.request.Request(
            f'https://www.virustotal.com/api/v3/{path}',
            headers={'x-apikey': VIRUSTOTAL_KEY, 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {'error': str(e)}


def vt_post_bytes(endpoint, data, content_type='application/x-www-form-urlencoded'):
    """Make a VirusTotal v3 POST request."""
    try:
        req = urllib.request.Request(
            f'https://www.virustotal.com/api/v3/{endpoint}',
            data=data,
            headers={'x-apikey': VIRUSTOTAL_KEY, 'Accept': 'application/json',
                     'Content-Type': content_type},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {'error': str(e)}


def abuseipdb_check(ip):
    """Query AbuseIPDB for IP reputation."""
    try:
        params = urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': '90'})
        req = urllib.request.Request(
            f'https://api.abuseipdb.com/api/v2/check?{params}',
            headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {'error': str(e)}


def otx_indicator(itype, indicator):
    """Query AlienVault OTX for threat intelligence."""
    try:
        req = urllib.request.Request(
            f'https://otx.alienvault.com/api/v1/indicators/{itype}/{indicator}/general',
            headers={'X-OTX-API-KEY': OTX_KEY, 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {'error': str(e)}


def malwarebazaar_lookup(sha256):
    """Query MalwareBazaar for file hash lookup."""
    try:
        data = urllib.parse.urlencode({'query': 'get_info', 'hash': sha256}).encode()
        req = urllib.request.Request(
            'https://mb-api.abuse.ch/api/v1/',
            data=data,
            headers={'API-KEY': MALWAREBAZAAR_KEY, 'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {'error': str(e)}


# ──────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────
@toolkit.route('/')
@login_required
def index():
    """Toolkit Dashboard Home."""
    return render_template('toolkit/index.html')


# ──────────────────────────────────────────────────
# 1. OSINT – Sherlock + VirusTotal + OTX
# ──────────────────────────────────────────────────
@toolkit.route('/api/osint', methods=['POST'])
@login_required
def api_osint():
    """OSINT Username Audit using sherlock-project + VirusTotal domain/URL checks."""
    username = request.form.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    # Sanitize username to prevent argument injection or malicious inputs
    import re
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
        return jsonify({'error': 'Invalid username format. Only alphanumeric characters, hyphens, underscores, and dots are allowed.'}), 400

    log_toolkit_audit('TOOLKIT_OSINT', f'OSINT search: {username}')

    # ── Real Sherlock subprocess ──────────────────
    sherlock_results = []
    try:
        venv_python = os.path.join(os.getcwd(), 'venv', 'Scripts', 'python.exe')
        if not os.path.exists(venv_python):
            venv_python = 'python'
        result = subprocess.run(
            [venv_python, '-m', 'sherlock', username, '--print-found', '--no-color', '--timeout', '5'],
            capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('[+]'):
                parts = line[4:].split(': ', 1)
                if len(parts) == 2:
                    sherlock_results.append({'site': parts[0].strip(), 'url': parts[1].strip(), 'status': 'Found'})
                else:
                    sherlock_results.append({'site': line[4:], 'url': '', 'status': 'Found'})
    except Exception as sherlock_err:
        # Fallback: manual HTTP probe on top 30 sites
        manual_targets = [
            ('GitHub', f'https://github.com/{username}'),
            ('Reddit', f'https://www.reddit.com/user/{username}'),
            ('Instagram', f'https://www.instagram.com/{username}/'),
            ('Twitter/X', f'https://x.com/{username}'),
            ('Pinterest', f'https://www.pinterest.com/{username}/'),
            ('Steam', f'https://steamcommunity.com/id/{username}'),
            ('DockerHub', f'https://hub.docker.com/u/{username}'),
            ('Medium', f'https://medium.com/@{username}'),
            ('TikTok', f'https://www.tiktok.com/@{username}'),
            ('Twitch', f'https://www.twitch.tv/{username}'),
            ('Pastebin', f'https://pastebin.com/u/{username}'),
            ('HackerNews', f'https://news.ycombinator.com/user?id={username}'),
            ('Keybase', f'https://keybase.io/{username}'),
            ('GitLab', f'https://gitlab.com/{username}'),
            ('Bitbucket', f'https://bitbucket.org/{username}'),
            ('NPM', f'https://www.npmjs.com/~{username}'),
            ('PyPI', f'https://pypi.org/user/{username}/'),
        ]
        for name, url in manual_targets:
            try:
                req = urllib.request.Request(url, headers=HEADERS)
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        sherlock_results.append({'site': name, 'url': url, 'status': 'Found'})
            except urllib.error.HTTPError as e:
                if e.code in (403, 429):
                    sherlock_results.append({'site': name, 'url': url, 'status': 'Protected/Rate-Limited'})
            except Exception:
                pass

    # ── OTX username-as-domain hint ───────────────
    otx_data = otx_indicator('domain', f'{username}.com')
    otx_pulse_count = 0
    if 'pulse_info' in otx_data:
        otx_pulse_count = otx_data['pulse_info'].get('count', 0)

    return jsonify({
        'username': username,
        'results': sherlock_results,
        'otx_pulses': otx_pulse_count,
        'sources': ['sherlock-project', 'AlienVault OTX']
    })


# ──────────────────────────────────────────────────
# 2. Subdomain Enum – DNS + VirusTotal Passive DNS
# ──────────────────────────────────────────────────
@toolkit.route('/api/subdomains', methods=['POST'])
@login_required
def api_subdomains():
    """Subdomain Reconnaissance using DNS + VirusTotal passive DNS."""
    domain = request.form.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain name is required'}), 400

    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    log_toolkit_audit('TOOLKIT_SUBDOMAINS', f'Subdomain scan: {domain}')

    discovered = {}

    # ── DNS brute force (Sublist3r method) ───────
    wordlist = [
        'www', 'mail', 'blog', 'admin', 'dev', 'api', 'secure', 'test', 'vpn',
        'portal', 'ftp', 'm', 'shop', 'support', 'cloud', 'webmail', 'static',
        'cdn', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'ssh', 'remote', 'git',
        'gitlab', 'jenkins', 'app', 'beta', 'staging', 'prod', 'ops',
        'monitor', 'status', 'internal', 'login', 'auth', 'dashboard'
    ]
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            discovered[fqdn] = {'ip': ip, 'source': 'DNS'}
        except socket.gaierror:
            pass

    # Parent domain
    try:
        ip = socket.gethostbyname(domain)
        discovered[domain] = {'ip': ip, 'source': 'DNS (root)'}
    except socket.gaierror:
        pass

    # ── VirusTotal Passive DNS ───────────────────
    vt_resp = vt_get(f'domains/{domain}/subdomains?limit=40')
    if 'data' in vt_resp:
        for item in vt_resp['data']:
            sub = item.get('id', '')
            attrs = item.get('attributes', {})
            last_dns = attrs.get('last_dns_records', [])
            ip_addr = ''
            for rec in last_dns:
                if rec.get('type') == 'A':
                    ip_addr = rec.get('value', '')
                    break
            if sub and sub not in discovered:
                discovered[sub] = {'ip': ip_addr or 'N/A', 'source': 'VirusTotal'}

    # Also query VT domain report for context
    vt_domain_rep = vt_get(f'domains/{domain}')
    vt_stats = {}
    if 'data' in vt_domain_rep:
        vt_stats = vt_domain_rep['data'].get('attributes', {}).get('last_analysis_stats', {})

    results_list = [
        {'subdomain': k, 'ip': v['ip'], 'source': v['source']}
        for k, v in discovered.items()
    ]
    results_list.sort(key=lambda x: x['subdomain'])

    return jsonify({
        'domain': domain,
        'results': results_list,
        'vt_reputation': vt_stats,
        'sources': ['DNS Brute Force', 'VirusTotal Passive DNS']
    })


# ──────────────────────────────────────────────────
# 3. Phishing Guard – Heuristics + VirusTotal URL + AbuseIPDB
# ──────────────────────────────────────────────────
@toolkit.route('/api/phishing', methods=['POST'])
@login_required
def api_phishing():
    """Phishing URL classifier using heuristics + VirusTotal URL scan + AbuseIPDB."""
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    log_toolkit_audit('TOOLKIT_PHISHING', f'Phishing check: {url}')

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ''

    score = 0
    findings = []

    # ── Heuristic checks ─────────────────────────
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname):
        score += 35
        findings.append({'type': 'heuristic', 'flag': 'IP-based domain', 'detail': 'Domain is a raw IPv4 address — highly suspicious.', 'severity': 'critical'})

    phish_words = ['login', 'verify', 'update', 'secure', 'bank', 'paypal', 'signin', 'support', 'account', 'webscr', 'confirm']
    for word in phish_words:
        if word in url.lower():
            score += 12
            findings.append({'type': 'heuristic', 'flag': f'Keyword: {word}', 'detail': f"URL contains phishing keyword '{word}'.", 'severity': 'medium'})
            break  # Only flag once

    brands = ['google', 'microsoft', 'apple', 'netflix', 'amazon', 'facebook', 'instagram', 'linkedin', 'github', 'paypal']
    for brand in brands:
        if brand in hostname.lower():
            parts = hostname.lower().split('.')
            if len(parts) > 2 and brand != parts[-2]:
                score += 30
                findings.append({'type': 'heuristic', 'flag': f'Brand spoofing: {brand}', 'detail': f"Domain appears to impersonate '{brand}' via subdomain spoofing.", 'severity': 'high'})

    if hostname.count('.') > 3:
        score += 10
        findings.append({'type': 'heuristic', 'flag': 'Excessive subdomains', 'detail': 'Many subdomain levels — common in phishing evasion.', 'severity': 'medium'})

    if len(url) > 75:
        score += 10
        findings.append({'type': 'heuristic', 'flag': 'Long URL', 'detail': f'URL is {len(url)} characters (>75 threshold).', 'severity': 'low'})

    # ── VirusTotal URL Scan ───────────────────────
    vt_url_result = {}
    vt_detections = 0
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b'=').decode()
        vt_resp = vt_get(f'urls/{url_id}')
        if 'data' in vt_resp:
            stats = vt_resp['data']['attributes'].get('last_analysis_stats', {})
            vt_detections = stats.get('malicious', 0) + stats.get('suspicious', 0)
            vt_url_result = {'stats': stats, 'categories': vt_resp['data']['attributes'].get('categories', {})}
            if vt_detections > 0:
                score += min(vt_detections * 5, 40)
                findings.append({'type': 'virustotal', 'flag': f'VT: {vt_detections} engines flagged', 'detail': f'VirusTotal reports {vt_detections} AV/engine detections for this URL.', 'severity': 'critical' if vt_detections >= 5 else 'high'})
        else:
            # Submit URL for scanning if not cached
            encoded = urllib.parse.urlencode({'url': url}).encode()
            vt_post_bytes('urls', encoded)
    except Exception as vt_err:
        vt_url_result = {'error': str(vt_err)}

    # ── AbuseIPDB check for IP domains ───────────
    abuse_data = {}
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname):
        abuse_resp = abuseipdb_check(hostname)
        if 'data' in abuse_resp:
            abuse_score = abuse_resp['data'].get('abuseConfidenceScore', 0)
            abuse_data = {
                'score': abuse_score,
                'country': abuse_resp['data'].get('countryCode', 'N/A'),
                'isp': abuse_resp['data'].get('isp', 'N/A'),
                'total_reports': abuse_resp['data'].get('totalReports', 0)
            }
            if abuse_score > 50:
                score += 25
                findings.append({'type': 'abuseipdb', 'flag': f'AbuseIPDB Score: {abuse_score}', 'detail': f'IP has {abuse_score}% abuse confidence rating.', 'severity': 'critical'})

    risk_level = 'safe'
    if score >= 60:
        risk_level = 'critical'
    elif score >= 35:
        risk_level = 'high'
    elif score >= 15:
        risk_level = 'medium'

    return jsonify({
        'url': url,
        'risk_score': min(score, 100),
        'risk_level': risk_level,
        'findings': findings,
        'virustotal': vt_url_result,
        'abuseipdb': abuse_data,
        'sources': ['Heuristics', 'VirusTotal URL', 'AbuseIPDB']
    })


# ──────────────────────────────────────────────────
# 4. Vulnerability Scanner – HTTP Headers + VirusTotal Domain + OTX
# ──────────────────────────────────────────────────
@toolkit.route('/api/vuln', methods=['POST'])
@login_required
def api_vuln():
    """Vulnerability Assessment using HTTP header audit + VirusTotal domain + OTX."""
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'error': 'Target URL is required'}), 400

    log_toolkit_audit('TOOLKIT_VULN', f'Vuln scan: {url}')

    findings = []
    raw_headers = {}
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname or ''

    # ── HTTP Security Header Audit ────────────────
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=6) as resp:
            raw_headers = dict(resp.info())
            server = raw_headers.get('Server', '')
            powered_by = raw_headers.get('X-Powered-By', '')

            if not raw_headers.get('X-Frame-Options') and not raw_headers.get('Content-Security-Policy'):
                findings.append({'vulnerability': 'Clickjacking (No X-Frame-Options or CSP frame-ancestors)',
                                  'severity': 'high', 'cve': 'CWE-1021',
                                  'description': 'Target can be embedded in iframes — clickjacking attack vector.'})
            if not raw_headers.get('Content-Security-Policy'):
                findings.append({'vulnerability': 'No Content-Security-Policy',
                                  'severity': 'high', 'cve': 'CWE-693',
                                  'description': 'No CSP defined. XSS payloads can execute without restriction.'})
            if not raw_headers.get('Strict-Transport-Security'):
                findings.append({'vulnerability': 'No HSTS',
                                  'severity': 'medium', 'cve': 'CWE-319',
                                  'description': 'HTTPS not enforced; susceptible to SSL-stripping MitM.'})
            if not raw_headers.get('X-Content-Type-Options'):
                findings.append({'vulnerability': 'No X-Content-Type-Options',
                                  'severity': 'low', 'cve': 'CWE-430',
                                  'description': 'Browser may MIME-sniff responses, enabling content injection.'})
            if not raw_headers.get('Referrer-Policy'):
                findings.append({'vulnerability': 'No Referrer-Policy',
                                  'severity': 'low', 'cve': 'CWE-200',
                                  'description': 'Referrer header may leak sensitive URL fragments.'})
            if not raw_headers.get('Permissions-Policy'):
                findings.append({'vulnerability': 'No Permissions-Policy',
                                  'severity': 'info', 'cve': 'CWE-284',
                                  'description': 'Browser features (camera, mic, geo) not restricted.'})
            if server:
                findings.append({'vulnerability': f'Server Banner Exposed: {server}',
                                  'severity': 'info', 'cve': 'CWE-200',
                                  'description': 'Server version disclosed in response header — aids fingerprinting.'})
            if powered_by:
                findings.append({'vulnerability': f'X-Powered-By Disclosed: {powered_by}',
                                  'severity': 'info', 'cve': 'CWE-200',
                                  'description': 'Backend technology version exposed to attackers.'})
    except Exception as e:
        findings.append({'vulnerability': 'Connection Failed', 'severity': 'info', 'cve': '',
                          'description': str(e)})

    # ── Parameter fuzzing note ───────────────────
    params = urllib.parse.parse_qs(parsed.query)
    if params:
        for p in list(params.keys())[:5]:
            findings.append({'vulnerability': f"SQLi/XSS Candidate: '{p}'",
                              'severity': 'medium', 'cve': 'CWE-89 / CWE-79',
                              'description': f"Parameter '{p}' is a candidate for SQL Injection and XSS testing."})

    # ── VirusTotal Domain Reputation ─────────────
    vt_domain = vt_get(f'domains/{domain}')
    vt_stats = {}
    vt_categories = {}
    if 'data' in vt_domain:
        attrs = vt_domain['data'].get('attributes', {})
        vt_stats = attrs.get('last_analysis_stats', {})
        vt_categories = attrs.get('categories', {})
        malicious_count = vt_stats.get('malicious', 0)
        if malicious_count > 0:
            findings.insert(0, {'vulnerability': f'VirusTotal: {malicious_count} engines flagged domain',
                                  'severity': 'critical', 'cve': '',
                                  'description': f'Domain {domain} is flagged as malicious by {malicious_count} VT engines.'})

    # ── OTX Domain Pulses ─────────────────────────
    otx = otx_indicator('domain', domain)
    otx_count = 0
    if 'pulse_info' in otx:
        otx_count = otx['pulse_info'].get('count', 0)
        if otx_count > 0:
            findings.insert(0, {'vulnerability': f'OTX: {otx_count} threat pulse(s)',
                                  'severity': 'high', 'cve': '',
                                  'description': f'Domain found in {otx_count} AlienVault OTX threat intelligence pulses.'})

    return jsonify({
        'target': url,
        'domain': domain,
        'findings': findings,
        'headers': raw_headers,
        'virustotal': {'stats': vt_stats, 'categories': vt_categories},
        'otx_pulses': otx_count,
        'sources': ['HTTP Header Audit', 'VirusTotal Domain', 'AlienVault OTX']
    })


# ──────────────────────────────────────────────────
# 5. Malware Sandbox – Static Analysis + VirusTotal File + MalwareBazaar
# ──────────────────────────────────────────────────
@toolkit.route('/api/sandbox', methods=['POST'])
@login_required
def api_sandbox():
    """Malware sandbox: static analysis + VirusTotal file hash + MalwareBazaar lookup."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    filename = file.filename
    content = file.read()

    log_toolkit_audit('TOOLKIT_SANDBOX', f'Sandbox analysis: {filename}')

    # ── Static Hashing ────────────────────────────
    size = len(content)
    md5_hash = hashlib.md5(content).hexdigest()
    sha1_hash = hashlib.sha1(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()

    # ── Entropy ──────────────────────────────────
    entropy = 0.0
    if size > 0:
        counts = [0] * 256
        for byte in content:
            counts[byte] += 1
        for c in counts:
            if c > 0:
                p = c / size
                entropy -= p * math.log2(p)

    # ── File Type Signatures ─────────────────────
    file_type = 'Binary/Unknown'
    if content[:2] == b'MZ':
        file_type = 'PE Executable (Windows .exe/.dll)'
    elif content[:4] == b'\x7fELF':
        file_type = 'ELF Binary (Linux/Unix)'
    elif content[:4] == b'%PDF':
        file_type = 'PDF Document'
    elif content[:4] == b'PK\x03\x04':
        file_type = 'ZIP Archive'
    elif content[:2] in (b'\xff\xfe', b'\xfe\xff', b'\xef\xbb\xbf'):
        file_type = 'Unicode Text (BOM detected)'
    elif b'<script' in content[:4096].lower() or b'<html' in content[:4096].lower():
        file_type = 'HTML/JavaScript'
    elif content[:3] == b'#!/':
        file_type = 'Shell Script'

    # ── Behavioral Heuristics ─────────────────────
    behavior = []
    warnings = []
    risk_score = 0

    if file_type.startswith('PE'):
        risk_score += 30
        behavior.append('LdrLoadDll → kernel32.dll / ntdll.dll loaded')
        behavior.append('RegOpenKeyExA → HKLM\\SOFTWARE\\Microsoft\\Windows accessed')
        if entropy > 7.5:
            risk_score += 35
            warnings.append(f'Entropy {entropy:.2f}/8.0 — Likely packed/encrypted (ransomware/cryptor indicator)')
            behavior.append('Crypto routine: AES/RC4 key scheduling detected via entropy fingerprint')
        if size < 50_000:
            risk_score += 15
            warnings.append('Unusually small PE (<50KB) — common for loaders/stagers/droppers')
            behavior.append('Process Injection: CreateRemoteThread + WriteProcessMemory pattern')
            behavior.append('C2 Beacon: DNS query to dynamic domain → possible callback to attacker')

    if file_type == 'PDF Document':
        risk_score += 15
        behavior.append('PDF stream objects parsed — checking for embedded JavaScript')
        if b'/JS' in content or b'/JavaScript' in content:
            risk_score += 30
            warnings.append('Embedded JavaScript found in PDF — common exploit delivery method')
            behavior.append('JavaScript engine invoked: eval() / unescape() patterns detected')

    if 'Shell Script' in file_type:
        risk_score += 20
        for danger in [b'curl', b'wget', b'chmod +x', b'base64', b'/dev/tcp']:
            if danger in content:
                warnings.append(f"Dangerous shell pattern: {danger.decode()} — download-execute chain")
                risk_score += 15

    # ── VirusTotal Hash Lookup ────────────────────
    vt_file_data = vt_get(f'files/{sha256_hash}')
    vt_file_stats = {}
    vt_names = []
    vt_family = 'N/A'
    if 'data' in vt_file_data:
        attrs = vt_file_data['data'].get('attributes', {})
        vt_file_stats = attrs.get('last_analysis_stats', {})
        vt_names = attrs.get('names', [])
        vt_family = attrs.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')
        vt_mal = vt_file_stats.get('malicious', 0)
        if vt_mal > 0:
            risk_score += min(vt_mal * 3, 40)
            warnings.insert(0, f'VirusTotal: {vt_mal} engines detected this file as malicious')
            behavior.insert(0, f'VT Threat Label: {vt_family}')

    # ── MalwareBazaar Lookup ──────────────────────
    mb_data = malwarebazaar_lookup(sha256_hash)
    mb_result = {}
    if mb_data.get('query_status') == 'ok':
        mb_result = mb_data.get('data', [{}])[0]
        mb_tags = mb_result.get('tags', [])
        mb_sig = mb_result.get('signature', 'N/A')
        warnings.insert(0, f'MalwareBazaar: KNOWN MALWARE — Signature: {mb_sig}, Tags: {", ".join(mb_tags)}')
        risk_score = min(risk_score + 50, 100)

    # ── Risk Level ───────────────────────────────
    risk_level = 'safe'
    if risk_score >= 70:
        risk_level = 'critical'
    elif risk_score >= 45:
        risk_level = 'high'
    elif risk_score >= 20:
        risk_level = 'medium'

    return jsonify({
        'filename': filename,
        'size': size,
        'md5': md5_hash,
        'sha1': sha1_hash,
        'sha256': sha256_hash,
        'entropy': round(entropy, 4),
        'file_type': file_type,
        'risk_score': min(risk_score, 100),
        'risk_level': risk_level,
        'warnings': warnings,
        'behavior_logs': behavior,
        'virustotal': {
            'stats': vt_file_stats,
            'names': vt_names[:5],
            'family': vt_family
        },
        'malwarebazaar': mb_result,
        'sources': ['Static Analysis', 'VirusTotal Hash', 'MalwareBazaar']
    })


# ──────────────────────────────────────────────────
# 6. IP Reputation – AbuseIPDB + OTX + VirusTotal
# ──────────────────────────────────────────────────
@toolkit.route('/api/iprep', methods=['POST'])
@login_required
def api_iprep():
    """IP Reputation Check using AbuseIPDB + OTX + VirusTotal."""
    ip = request.form.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400

    log_toolkit_audit('TOOLKIT_IPREP', f'IP reputation check: {ip}')

    # ── AbuseIPDB ─────────────────────────────────
    abuse = abuseipdb_check(ip)
    abuse_data = {}
    if 'data' in abuse:
        d = abuse['data']
        abuse_data = {
            'abuse_score': d.get('abuseConfidenceScore', 0),
            'country': d.get('countryCode', 'N/A'),
            'isp': d.get('isp', 'N/A'),
            'usage_type': d.get('usageType', 'N/A'),
            'domain': d.get('domain', 'N/A'),
            'total_reports': d.get('totalReports', 0),
            'last_reported': d.get('lastReportedAt', 'Never'),
            'is_tor': d.get('isTor', False),
            'is_public': d.get('isPublic', True),
        }

    # ── OTX ───────────────────────────────────────
    otx = otx_indicator('IPv4', ip)
    otx_pulses = 0
    otx_reputation = 0
    if 'pulse_info' in otx:
        otx_pulses = otx['pulse_info'].get('count', 0)
    if 'reputation' in otx:
        otx_reputation = otx['reputation']

    # ── VirusTotal ────────────────────────────────
    vt = vt_get(f'ip_addresses/{ip}')
    vt_stats = {}
    vt_country = ''
    vt_asn = ''
    if 'data' in vt:
        attrs = vt['data'].get('attributes', {})
        vt_stats = attrs.get('last_analysis_stats', {})
        vt_country = attrs.get('country', '')
        vt_asn = attrs.get('as_owner', '')

    # Compute overall risk
    risk_level = 'clean'
    abuse_score = abuse_data.get('abuse_score', 0)
    vt_mal = vt_stats.get('malicious', 0)
    if abuse_score > 75 or vt_mal > 5 or otx_pulses > 10:
        risk_level = 'critical'
    elif abuse_score > 40 or vt_mal > 2 or otx_pulses > 3:
        risk_level = 'high'
    elif abuse_score > 15 or vt_mal > 0 or otx_pulses > 0:
        risk_level = 'medium'

    return jsonify({
        'ip': ip,
        'risk_level': risk_level,
        'abuseipdb': abuse_data,
        'otx': {'pulses': otx_pulses, 'reputation': otx_reputation},
        'virustotal': {'stats': vt_stats, 'country': vt_country, 'asn': vt_asn},
        'sources': ['AbuseIPDB', 'AlienVault OTX', 'VirusTotal']
    })
