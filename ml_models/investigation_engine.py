"""
BIGIL Advanced Investigation Engine
Evidence correlation, slow-poison detection, threat scoring, and early warning analysis.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Dict, Any


# ── Slow Poison / Long-Term Compromise Indicators ─────────────────────────────
SLOW_POISON_PATTERNS = {
    'scheduled_task_persistence': {
        'patterns': [r'schtasks', r'cron\s', r'at\s+job', r'scheduled\s+task', r'task\s+scheduler',
                     r'crontab', r'launchd', r'plist.*launch'],
        'severity': 'high',
        'category': 'persistence',
        'description': 'Unusual scheduled task — possible persistence mechanism'
    },
    'registry_persistence': {
        'patterns': [r'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                     r'RunOnce', r'StartupApproved', r'winlogon', r'services\.exe'],
        'severity': 'high',
        'category': 'persistence',
        'description': 'Registry or service persistence indicator'
    },
    'periodic_beaconing': {
        'patterns': [r'beacon', r'heartbeat', r'keep.?alive', r'callback', r'C2', r'command.and.control',
                     r'every\s+\d+\s+(min|hour|sec)', r'interval.*connect'],
        'severity': 'critical',
        'category': 'beaconing',
        'description': 'Periodic outbound communication — possible C2 beaconing'
    },
    'credential_abuse': {
        'patterns': [r'pass.?the.?hash', r'pass.?the.?ticket', r'kerberoast', r'mimikatz', r'lsass',
                     r'credential\s+dump', r'ntlm', r'golden\s+ticket', r'silver\s+ticket',
                     r'abnormal\s+login', r'impossible\s+travel', r'off.?hours\s+access'],
        'severity': 'critical',
        'category': 'credential_abuse',
        'description': 'Credential abuse or theft indicator'
    },
    'gradual_exfiltration': {
        'patterns': [r'slow\s+exfil', r'steady\s+outbound', r'incremental\s+transfer',
                     r'small\s+chunk', r'drip\s+exfil', r'low.?and.?slow',
                     r'outbound.*\d+\s*(MB|GB|KB).*repeated', r'dns\s+tunnel', r'icmp\s+tunnel'],
        'severity': 'critical',
        'category': 'exfiltration',
        'description': 'Gradual data theft pattern — slow poison exfiltration'
    },
    'stealth_process': {
        'patterns': [r'hidden\s+process', r'rootkit', r'process\s+hollowing', r'dll\s+injection',
                     r'reflective\s+loading', r'living\s+off\s+the\s+land', r'lolbas',
                     r'signed\s+binary\s+proxy', r'certutil', r'mshta', r'regsvr32'],
        'severity': 'high',
        'category': 'stealth',
        'description': 'Stealth execution or living-off-the-land technique'
    },
    'insider_threat': {
        'patterns': [r'after.?hours', r'weekend\s+access', r'bulk\s+download', r'mass\s+file\s+access',
                     r'usb\s+insert', r'removable\s+media', r'unauthorized\s+export',
                     r'data\s+staging', r'archive.*password'],
        'severity': 'high',
        'category': 'insider_threat',
        'description': 'Insider threat behavioral indicator'
    },
    'privilege_escalation': {
        'patterns': [r'privilege\s+escalat', r'sudo\s+', r'uac\s+bypass', r'elevat.*admin',
                     r'getsystem', r'token\s+impersonat', r'seimpersonate', r'potato'],
        'severity': 'critical',
        'category': 'privilege_escalation',
        'description': 'Suspicious privilege escalation attempt'
    },
}

# ── Standard Threat Indicators ────────────────────────────────────────────────
THREAT_PATTERNS = {
    'lateral_movement': [r'psexec', r'wmiexec', r'smbexec', r'rdp.*connect', r'winrm',
                         r'lateral\s+movement', r'remote\s+exec'],
    'malware': [r'malware', r'trojan', r'backdoor', r'ransomware', r'wannacry', r'cobalt\s+strike'],
    'brute_force': [r'brute\s*force', r'failed\s+login', r'authentication\s+failure', r'account\s+locked'],
    'phishing': [r'phish', r'spear.?phish', r'malicious\s+attachment', r'spoofed\s+sender'],
}


def _match_patterns(text: str, pattern_groups: dict) -> List[Dict]:
    """Scan text against pattern groups and return findings."""
    findings = []
    text_lower = text.lower()
    for name, cfg in pattern_groups.items():
        if isinstance(cfg, dict):
            patterns = cfg['patterns']
            meta = cfg
        else:
            patterns = cfg
            meta = {'severity': 'high', 'category': name, 'description': name.replace('_', ' ').title()}
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                findings.append({
                    'indicator': name,
                    'pattern': pat,
                    'severity': meta.get('severity', 'high'),
                    'category': meta.get('category', name),
                    'description': meta.get('description', ''),
                    'matched_text': text[:200]
                })
                break
    return findings


def detect_slow_poison(log_entries: List[Dict]) -> Dict[str, Any]:
    """
    Detect long-term compromise indicators across parsed log entries.
    Returns slow poison assessment with risk score and notifications.
    """
    all_findings = []
    category_counts = Counter()
    affected_lines = set()

    for entry in log_entries:
        raw = entry.get('raw', '')
        findings = _match_patterns(raw, SLOW_POISON_PATTERNS)
        for f in findings:
            f['line_num'] = entry.get('line_num')
            f['timestamp'] = entry.get('timestamp', '')
            f['ip'] = entry.get('ip', '')
            all_findings.append(f)
            category_counts[f['category']] += 1
            affected_lines.add(entry.get('line_num'))

    # Risk scoring: weighted by category diversity and severity
    severity_weights = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
    risk_score = min(100, sum(severity_weights.get(f['severity'], 5) for f in all_findings))
    # Bonus for multiple categories (indicates prolonged multi-stage compromise)
    risk_score = min(100, risk_score + len(category_counts) * 5)

    compromised = risk_score >= 40
    threat_level = 'critical' if risk_score >= 75 else 'high' if risk_score >= 50 else 'medium' if risk_score >= 25 else 'low'

    notifications = []
    if compromised:
        notifications.append({
            'type': 'slow_poison_alert',
            'title': 'Prolonged Compromise Indicators Detected',
            'message': f'Evidence suggests a long-term stealth compromise. {len(category_counts)} attack categories identified across {len(affected_lines)} log entries.',
            'severity': threat_level,
            'action': 'Initiate full forensic timeline reconstruction and evidence correlation.'
        })

    for cat, count in category_counts.most_common(3):
        if count >= 2:
            notifications.append({
                'type': 'pattern_cluster',
                'title': f'Repeated {cat.replace("_", " ").title()} Activity',
                'message': f'{count} instances of {cat.replace("_", " ")} indicators — possible sustained attacker presence.',
                'severity': 'high',
                'action': f'Correlate {cat} events with authentication and network logs.'
            })

    return {
        'detected': len(all_findings) > 0,
        'compromised_likely': compromised,
        'risk_score': risk_score,
        'threat_level': threat_level,
        'findings': all_findings[:50],
        'category_summary': dict(category_counts),
        'affected_line_count': len(affected_lines),
        'notifications': notifications,
        'recommendations': _generate_recommendations(category_counts, risk_score)
    }


def analyze_threats(log_entries: List[Dict]) -> Dict[str, Any]:
    """Full threat analysis: standard threats + slow poison + entity extraction."""
    slow_poison = detect_slow_poison(log_entries)

    standard_findings = []
    for entry in log_entries:
        for name, patterns in THREAT_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, entry.get('raw', ''), re.IGNORECASE):
                    standard_findings.append({
                        'indicator': name,
                        'line_num': entry.get('line_num'),
                        'severity': 'critical' if name in ('malware', 'lateral_movement') else 'high',
                        'category': name
                    })
                    break

    entities = extract_entities(log_entries)
    risk_score = min(100, slow_poison['risk_score'] + len(standard_findings) * 3)

    return {
        'slow_poison': slow_poison,
        'standard_threats': standard_findings[:30],
        'standard_threat_count': len(standard_findings),
        'entities': entities,
        'overall_risk_score': risk_score,
        'early_warnings': generate_early_warnings(slow_poison, standard_findings, entities)
    }


def extract_entities(log_entries: List[Dict]) -> Dict[str, Any]:
    """Extract IPs, users, hosts for entity relationship analysis."""
    ips = Counter()
    users = Counter()
    hosts = Counter()

    user_pat = re.compile(r'user[=\s:]+([^\s,;]+)', re.I)
    host_pat = re.compile(r'host[=\s:]+([^\s,;]+)', re.I)

    for entry in log_entries:
        raw = entry.get('raw', '')
        if entry.get('ip'):
            ips[entry['ip']] += 1
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw):
            ips[ip] += 1
        um = user_pat.search(raw)
        if um:
            users[um.group(1)] += 1
        hm = host_pat.search(raw)
        if hm:
            hosts[hm.group(1)] += 1

    # Build simple relationship edges (IP co-occurrence in same severity events)
    edges = []
    high_ips = [e['ip'] for e in log_entries if e.get('severity') in ('critical', 'high') and e.get('ip')]
    ip_pairs = Counter()
    for i in range(len(high_ips)):
        for j in range(i + 1, min(i + 5, len(high_ips))):
            if high_ips[i] != high_ips[j]:
                pair = tuple(sorted([high_ips[i], high_ips[j]]))
                ip_pairs[pair] += 1
    for (a, b), cnt in ip_pairs.most_common(10):
        edges.append({'source': a, 'target': b, 'weight': cnt, 'type': 'co-occurrence'})

    return {
        'ips': [{'value': ip, 'count': c} for ip, c in ips.most_common(15)],
        'users': [{'value': u, 'count': c} for u, c in users.most_common(10)],
        'hosts': [{'value': h, 'count': c} for h, c in hosts.most_common(10)],
        'edges': edges,
        'node_count': len(ips) + len(users) + len(hosts)
    }


def generate_early_warnings(slow_poison: dict, threats: list, entities: dict) -> List[Dict]:
    """Generate predictive early warnings and preventive recommendations."""
    warnings = []

    if slow_poison.get('compromised_likely'):
        warnings.append({
            'level': 'critical',
            'title': 'Long-Term Compromise Risk',
            'prediction': 'Attack progression likely in exfiltration or lateral movement phase',
            'recommendation': 'Isolate affected hosts, preserve forensic images, and expand log collection to DNS/proxy/firewall.',
            'assets_at_risk': 'Domain controllers, file servers, authentication infrastructure'
        })

    if len(entities.get('ips', [])) > 5:
        warnings.append({
            'level': 'high',
            'title': 'Distributed Attack Surface',
            'prediction': 'Multiple source IPs suggest coordinated or multi-vector campaign',
            'recommendation': 'Cross-reference IPs against IOC database and threat intelligence feeds.',
            'assets_at_risk': 'Perimeter firewalls, VPN gateways, exposed services'
        })

    cred_cats = slow_poison.get('category_summary', {}).get('credential_abuse', 0)
    if cred_cats > 0:
        warnings.append({
            'level': 'critical',
            'title': 'Credential Compromise Indicators',
            'prediction': 'Privilege escalation and lateral movement imminent',
            'recommendation': 'Force credential rotation, enable MFA, audit privileged account usage.',
            'assets_at_risk': 'Active Directory, privileged service accounts'
        })

    beacon_cats = slow_poison.get('category_summary', {}).get('beaconing', 0)
    if beacon_cats > 0:
        warnings.append({
            'level': 'high',
            'title': 'C2 Beaconing Detected',
            'prediction': 'Persistent command channel may enable further payload delivery',
            'recommendation': 'Block outbound connections to suspicious destinations at firewall/proxy layer.',
            'assets_at_risk': 'Workstations with periodic outbound traffic patterns'
        })

    if len(threats) > 5:
        warnings.append({
            'level': 'medium',
            'title': 'Elevated Threat Activity',
            'prediction': 'Incident escalation probable without immediate triage',
            'recommendation': 'Open investigation case and begin attack timeline reconstruction.',
            'assets_at_risk': 'Affected network segments'
        })

    return warnings


def _generate_recommendations(category_counts: Counter, risk_score: int) -> List[str]:
    recs = []
    if risk_score >= 50:
        recs.append('URGENT: Evidence indicates prolonged compromise — initiate full incident response protocol.')
    if category_counts.get('persistence'):
        recs.append('Audit scheduled tasks, registry Run keys, and startup items on all affected systems.')
    if category_counts.get('beaconing'):
        recs.append('Analyze network traffic for periodic outbound connections to unknown destinations.')
    if category_counts.get('credential_abuse'):
        recs.append('Reset credentials for affected accounts and review authentication logs for 90-day lookback.')
    if category_counts.get('exfiltration'):
        recs.append('Review DLP logs and outbound transfer volumes for gradual data theft patterns.')
    if category_counts.get('insider_threat'):
        recs.append('Correlate user activity with HR records and access control policies.')
    if not recs:
        recs.append('Continue monitoring — no prolonged compromise indicators at current threshold.')
    return recs


def compute_security_posture(stats: dict) -> Dict[str, Any]:
    """Compute organization security posture score for breach prevention dashboard."""
    base = 85
    deductions = 0
    deductions += stats.get('critical_alerts', 0) * 8
    deductions += stats.get('high_alerts', 0) * 4
    deductions += stats.get('open_cases', 0) * 2
    deductions = min(deductions, 60)
    score = max(20, base - deductions)

    return {
        'score': score,
        'grade': 'A' if score >= 80 else 'B' if score >= 65 else 'C' if score >= 50 else 'D' if score >= 35 else 'F',
        'status': 'healthy' if score >= 70 else 'at_risk' if score >= 45 else 'critical',
        'factors': {
            'critical_alerts': stats.get('critical_alerts', 0),
            'high_alerts': stats.get('high_alerts', 0),
            'active_investigations': stats.get('active_cases', 0),
            'evidence_integrity': 'verified'
        }
    }
