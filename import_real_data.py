"""
BIGIL — Import Real Dataset Evidence
Populates the database from actual cybersecurity datasets with verifiable proofs.
Run: python import_real_data.py
"""

import json
import hashlib
import shutil
import re
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd

from app import create_app, db
from app.models import (
    User, Investigator, Case, Evidence, EvidenceChain,
    AttackTimeline, IOC, ThreatActor, APTCampaign,
    Alert, AuditLog, InvestigationNote
)

BASE_DIR = Path(__file__).parent
DATASETS = BASE_DIR / 'datasets'
UPLOADS = BASE_DIR / 'uploads'
EVIDENCE_DIR = UPLOADS / 'dataset_evidence'

STIX_PATH = DATASETS / 'attack-stix-data' / 'attack-stix-data-master' / 'enterprise-attack' / 'enterprise-attack.json'
CIC_DIR = DATASETS / 'MachineLearningCSV' / 'MachineLearningCVE'
UNSW_TRAIN = DATASETS / 'OneDriveData' / 'CSV Files' / 'Training and Testing Sets' / 'UNSW_NB15_training-set.csv'
LOGHUB_DIR = DATASETS / 'raw' / 'loghub-master'

CIC_FILES = {
    'DDoS': 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'PortScan': 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Web Attacks': 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Infiltration': 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Bot': 'Friday-WorkingHours-Morning.pcap_ISCX.csv',
}

LOG_SOURCES = [
    ('BGL', 'BGL_2k.log'),
    ('HDFS', 'HDFS_2k.log'),
    ('OpenSSH', 'OpenSSH_2k.log'),
    ('Linux', 'Linux_2k.log'),
    ('Apache', 'Apache_2k.log'),
]


def compute_hashes(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def _ev_id(n):
    return f'EV-DATA-{n:05d}'


def _case_num(n):
    return f'GP-REAL-{datetime.utcnow().year}-{n:04d}'


def create_users():
    users_data = [
        {'username': 'dcp_suresh', 'email': 'suresh.kumar@hry.gov.in', 'role': 'admin',
         'badge_number': 'GP-89304', 'full_name': 'Suresh Kumar', 'rank': 'DCP Cyber Crime',
         'unit': 'Cyber Cell Headquarters', 'specialization': 'Command & Cyber Policy'},
        {'username': 'insp_rajendra', 'email': 'rajendra.prasad@hry.gov.in', 'role': 'investigator',
         'badge_number': 'GP-77291', 'full_name': 'Rajendra Prasad', 'rank': 'Inspector',
         'unit': 'Forensics Lab', 'specialization': 'Digital Forensics'},
        {'username': 'si_akash', 'email': 'akash.sharma@hry.gov.in', 'role': 'analyst',
         'badge_number': 'GP-90123', 'full_name': 'Akash Sharma', 'rank': 'Sub-Inspector',
         'unit': 'Threat Intelligence Unit', 'specialization': 'Log & Network Analysis'},
    ]
    users = {}
    for ud in users_data:
        u = User(username=ud['username'], email=ud['email'], role=ud['role'],
                 badge_number=ud['badge_number'], full_name=ud['full_name'], is_active=True)
        u.set_password('Gurugram@1234')
        db.session.add(u)
        db.session.flush()
        db.session.add(Investigator(user_id=u.id, rank=ud['rank'], unit=ud['unit'],
                                  specialization=ud['specialization'], cases_handled=0))
        users[ud['username']] = u
    return users


def import_mitre_actors():
    """Import real MITRE ATT&CK intrusion-set groups from STIX JSON."""
    if not STIX_PATH.exists():
        print(f'  [Skip] STIX not found: {STIX_PATH}')
        return []

    print('  Loading MITRE ATT&CK enterprise-attack.json...')
    with open(STIX_PATH, 'r', encoding='utf-8') as f:
        bundle = json.load(f)

    objects = {o['id']: o for o in bundle.get('objects', []) if 'id' in o}
    intrusion_sets = [o for o in bundle.get('objects', []) if o.get('type') == 'intrusion-set']

    # Build technique map from relationships
    actor_techniques = {}
    for obj in bundle.get('objects', []):
        if obj.get('type') != 'relationship':
            continue
        if obj.get('relationship_type') == 'uses' and obj.get('source_ref', '').startswith('intrusion-set'):
            src = objects.get(obj['source_ref'])
            tgt = objects.get(obj.get('target_ref', ''))
            if src and tgt and tgt.get('type') == 'attack-pattern':
                name = src.get('name', '')
                ext_id = ''
                for ref in tgt.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        ext_id = ref.get('external_id', '')
                        break
                actor_techniques.setdefault(name, []).append({
                    'id': ext_id,
                    'name': tgt.get('name', ''),
                    'tactic': (tgt.get('kill_chain_phases') or [{}])[0].get('phase_name', '')
                })

    actors = []
    priority_groups = ['APT28', 'APT29', 'APT41', 'Lazarus Group', 'Sandworm Team',
                       'FIN7', 'Wizard Spider', 'OilRig', 'Turla', 'Kimsuky']

    for name in priority_groups:
        stix_obj = next((o for o in intrusion_sets if o.get('name') == name), None)
        if not stix_obj:
            continue
        aliases = ', '.join(stix_obj.get('aliases', []))
        desc = stix_obj.get('description', '')[:2000]
        ttps = json.dumps(actor_techniques.get(name, [])[:15])
        origin = 'Unknown'
        desc_lower = (desc + aliases).lower()
        if any(x in desc_lower for x in ['russia', 'russian', 'gru']):
            origin = 'Russia'
        elif any(x in desc_lower for x in ['china', 'chinese', 'prc']):
            origin = 'China'
        elif any(x in desc_lower for x in ['north korea', 'dprk', 'korean']):
            origin = 'North Korea'
        elif any(x in desc_lower for x in ['iran', 'iranian']):
            origin = 'Iran'

        actor = ThreatActor(
            name=name,
            aliases=aliases,
            origin_country=origin,
            motivation='Cyber Espionage / Financial Crime',
            sophistication='nation-state' if 'APT' in name or name in ('Sandworm Team', 'Lazarus Group') else 'advanced',
            active_since='2010',
            description=f'[MITRE ATT&CK STIX] {desc}',
            targets='Government, Financial, Critical Infrastructure',
            ttps=ttps,
            tools='[]',
            infrastructure='[]',
            risk_score=min(99, 60 + len(actor_techniques.get(name, [])))
        )
        db.session.add(actor)
        actors.append(actor)

    db.session.flush()
    print(f'  Imported {len(actors)} MITRE ATT&CK threat actors')
    return actors


def _load_cic_attack_sample(fpath, attack_label, max_rows=200):
    """Load verified attack-labeled rows from a CIC-IDS2017 CSV (not benign-only slices)."""
    chunks = []
    label_col = 'Label'
    for chunk in pd.read_csv(fpath, low_memory=False, chunksize=50000):
        chunk.columns = chunk.columns.str.strip()
        if ' Label' in chunk.columns:
            chunk = chunk.rename(columns={' Label': 'Label'})
        if label_col not in chunk.columns:
            continue
        if attack_label == 'Bot':
            attacks = chunk[chunk[label_col].astype(str).str.contains('Bot', case=False, na=False)]
        else:
            attacks = chunk[chunk[label_col].astype(str).str.strip() == attack_label]
        if not attacks.empty:
            chunks.append(attacks)
        if sum(len(c) for c in chunks) >= max_rows:
            break
    if not chunks:
        return None
    return pd.concat(chunks, ignore_index=True).head(max_rows)


def import_cic_cases(users, actors):
    """Create investigation cases from real CIC-IDS2017 labeled attack flows."""
    cases = []
    analyst = users['si_akash']

    case_idx = 1
    for attack_label, csv_name in CIC_FILES.items():
        fpath = CIC_DIR / csv_name
        if not fpath.exists():
            continue

        sample = _load_cic_attack_sample(fpath, attack_label)
        if sample is None or sample.empty:
            continue
        proof_file = EVIDENCE_DIR / f'CIC-IDS2017_{attack_label.replace(" ", "_")}_flows.csv'
        sample.to_csv(proof_file, index=False)
        md5, sha256 = compute_hashes(proof_file)

        case = Case(
            case_number=_case_num(case_idx),
            title=f'CIC-IDS2017 Investigation: {attack_label} Network Intrusion',
            description=(
                f'Real network flow evidence from Canadian Institute for Cybersecurity CIC-IDS2017 dataset. '
                f'Source file: {csv_name}. Contains {len(sample)} verified attack flow records '
                f'labeled as {attack_label}. Dataset proof: MachineLearningCSV/MachineLearningCVE/{csv_name}'
            ),
            status='active',
            priority='critical' if attack_label in ('DDoS', 'Infiltration') else 'high',
            case_type=attack_label,
            assigned_to=analyst.id,
            created_by=analyst.id,
            victim_org='Critical Infrastructure Sector (Dataset Target)',
            victim_sector='Energy / Government',
            tags=f'CIC-IDS2017,{attack_label},real-dataset'
        )
        db.session.add(case)
        db.session.flush()
        cases.append(case)

        ev = Evidence(
            evidence_id=_ev_id(case_idx),
            case_id=case.id,
            title=f'CIC-IDS2017 {attack_label} Flow Export',
            description=f'Exported {len(sample)} real attack flows from {csv_name}',
            category='network',
            file_name=proof_file.name,
            file_path=str(proof_file),
            file_size=proof_file.stat().st_size,
            file_hash_md5=md5,
            file_hash_sha256=sha256,
            source=f'CIC-IDS2017 Dataset — {csv_name}',
            collected_by=analyst.id,
            tags='CIC-IDS2017,network-flow,verified',
            status='verified',
            verified=True,
            verified_by=analyst.id
        )
        db.session.add(ev)
        db.session.flush()
        db.session.add(EvidenceChain(
            evidence_id=ev.id, action='collected', performed_by=analyst.id,
            notes=f'Imported from CIC-IDS2017 dataset file: {csv_name}',
            location='BIGIL Dataset Evidence Store'
        ))

        # Network flow signatures (CIC CSV has flow features, not raw IPs — stored as network_flow IOCs)
        port_col = next((c for c in sample.columns if 'Destination Port' in c), None)
        dur_col = next((c for c in sample.columns if 'Flow Duration' in c), None)
        if port_col:
            for port in sample[port_col].dropna().astype(int).unique()[:5]:
                db.session.add(IOC(
                    ioc_type='network_flow',
                    value=f'CIC-IDS2017:{attack_label}:dst-port-{int(port)}',
                    description=(
                        f'Verified CIC-IDS2017 {attack_label} flow — destination port {int(port)}. '
                        f'Source: MachineLearningCVE/{csv_name}, SHA256:{sha256[:16]}...'
                    ),
                    threat_actor='',
                    severity='high' if attack_label != 'PortScan' else 'medium',
                    confidence=100,
                    first_seen=datetime.utcnow() - timedelta(days=30),
                    last_seen=datetime.utcnow(),
                    tags=f'CIC-IDS2017,{attack_label},verified-dataset',
                    case_id=case.id
                ))

        # Timeline from first 5 attack rows (real flow metrics)
        for i, (_, row) in enumerate(sample.head(5).iterrows()):
            port = int(row[port_col]) if port_col and pd.notna(row.get(port_col)) else 0
            duration = float(row[dur_col]) if dur_col and pd.notna(row.get(dur_col)) else 0
            db.session.add(AttackTimeline(
                case_id=case.id,
                event_time=datetime.utcnow() - timedelta(hours=5 - i),
                event_title=f'{attack_label} network flow detected',
                event_description=(
                    f'CIC-IDS2017 labeled flow. Port: {port}, Duration: {duration:.0f}µs. '
                    f'Label: {row.get("Label", attack_label)}. Proof: {csv_name}'
                ),
                attack_phase='initial_access' if i == 0 else 'execution',
                mitre_technique='T1071' if attack_label == 'DDoS' else 'T1046',
                severity='critical' if attack_label in ('DDoS', 'Infiltration') else 'high',
                evidence_ref=ev.evidence_id
            ))

        db.session.add(Alert(
            title=f'CIC-IDS2017: {attack_label} detected in network flows',
            description=f'{len(sample)} verified {attack_label} flows from dataset {csv_name}. SHA256: {sha256[:16]}...',
            severity='critical' if attack_label in ('DDoS', 'Infiltration') else 'high',
            alert_type='ioc_match',
            source='CIC-IDS2017 Dataset',
            case_id=case.id,
            assigned_to=analyst.id,
            status='open',
            risk_score=90
        ))

        case_idx += 1

    print(f'  Imported {len(cases)} cases from CIC-IDS2017')
    return cases


def import_unsw_cases(users):
    """Create cases from real UNSW-NB15 attack category distribution."""
    if not UNSW_TRAIN.exists():
        print(f'  [Skip] UNSW not found')
        return []

    df = pd.read_csv(UNSW_TRAIN, usecols=['attack_cat', 'proto', 'service', 'dur', 'spkts', 'dpkts', 'dbytes'], nrows=50000)
    df['attack_cat'] = df['attack_cat'].fillna('Normal')
    attacks = df[df['attack_cat'] != 'Normal']
    categories = attacks['attack_cat'].value_counts().head(6)

    analyst = users['si_akash']
    cases = []
    for idx, (cat, count) in enumerate(categories.items(), 1):
        cat_rows = attacks[attacks['attack_cat'] == cat].head(100)
        proof_file = EVIDENCE_DIR / f'UNSW-NB15_{cat.replace(" ", "_")}_flows.csv'
        cat_rows.to_csv(proof_file, index=False)
        md5, sha256 = compute_hashes(proof_file)

        case = Case(
            case_number=_case_num(100 + idx),
            title=f'UNSW-NB15 Investigation: {cat} Attack Category',
            description=(
                f'Real attack flows from UNSW-NB15 dataset (University of New South Wales). '
                f'{count:,} total {cat} records in training set. '
                f'Proof file: {proof_file.name}. Source: UNSW_NB15_training-set.csv'
            ),
            status='active',
            priority='high' if cat in ('Exploits', 'DoS', 'Generic') else 'medium',
            case_type=cat,
            assigned_to=analyst.id,
            created_by=analyst.id,
            victim_org='Enterprise Network (UNSW-NB15 Lab Capture)',
            victim_sector='Research / Enterprise',
            tags=f'UNSW-NB15,{cat},real-dataset'
        )
        db.session.add(case)
        db.session.flush()
        cases.append(case)

        ev = Evidence(
            evidence_id=_ev_id(100 + idx),
            case_id=case.id,
            title=f'UNSW-NB15 {cat} Flow Sample',
            description=f'100 real {cat} network flows from UNSW-NB15 training set',
            category='network',
            file_name=proof_file.name,
            file_path=str(proof_file),
            file_size=proof_file.stat().st_size,
            file_hash_md5=md5,
            file_hash_sha256=sha256,
            source='UNSW-NB15 Dataset — UNSW_NB15_training-set.csv',
            collected_by=analyst.id,
            status='verified', verified=True, verified_by=analyst.id,
            tags='UNSW-NB15,verified'
        )
        db.session.add(ev)

        db.session.add(Alert(
            title=f'UNSW-NB15 ML Alert: {cat} attack pattern ({count:,} flows)',
            description=f'Attack category {cat} identified in UNSW-NB15 dataset with {count:,} training samples.',
            severity='high',
            alert_type='anomaly',
            source='UNSW-NB15 Dataset / ML Classifier',
            case_id=case.id,
            assigned_to=analyst.id,
            status='open',
            risk_score=85
        ))

    print(f'  Imported {len(cases)} cases from UNSW-NB15')
    return cases


def import_loghub_evidence(users, cases):
    """Copy real LogHub log files as verified digital evidence."""
    if not LOGHUB_DIR.exists():
        print('  [Skip] LogHub not found')
        return 0

    analyst = users['insp_rajendra']
    count = 0
    for i, (subdir, fname) in enumerate(LOG_SOURCES, 1):
        src = LOGHUB_DIR / subdir / fname
        if not src.exists():
            continue
        dst = EVIDENCE_DIR / f'LogHub_{subdir}_{fname}'
        shutil.copy2(src, dst)
        md5, sha256 = compute_hashes(dst)
        case = cases[i % len(cases)] if cases else None

        ev = Evidence(
            evidence_id=_ev_id(200 + i),
            case_id=case.id if case else None,
            title=f'LogHub {subdir} Security Log',
            description=f'Real system log from LogHub dataset ({subdir}). {dst.stat().st_size:,} bytes. Source: loghub-master/{subdir}/{fname}',
            category='log',
            file_name=dst.name,
            file_path=str(dst),
            file_size=dst.stat().st_size,
            file_hash_md5=md5,
            file_hash_sha256=sha256,
            source=f'LogHub Dataset — {subdir}/{fname}',
            collected_by=analyst.id,
            status='verified', verified=True, verified_by=analyst.id,
            tags=f'LogHub,{subdir},real-log'
        )
        db.session.add(ev)
        db.session.flush()
        db.session.add(EvidenceChain(
            evidence_id=ev.id, action='collected', performed_by=analyst.id,
            notes=f'Imported from LogHub dataset: {subdir}/{fname}',
            location='BIGIL Dataset Evidence Store'
        ))
        count += 1

    print(f'  Imported {count} LogHub log evidence files')
    return count


def import_loghub_iocs(users, cases):
    """Extract real IP addresses from LogHub security logs as IOCs."""
    if not LOGHUB_DIR.exists():
        return 0
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    count = 0
    analyst = users['si_akash']
    for subdir, fname in LOG_SOURCES:
        fpath = LOGHUB_DIR / subdir / fname
        if not fpath.exists():
            continue
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        ips = sorted(set(ip_re.findall(content)))
        case = cases[count % len(cases)] if cases else None
        for ip in ips[:15]:
            if ip.startswith(('0.', '127.', '255.')):
                continue
            db.session.add(IOC(
                ioc_type='ip',
                value=ip,
                description=(
                    f'IP address extracted from LogHub dataset log '
                    f'loghub-master/{subdir}/{fname} (verified source file)'
                ),
                threat_actor='',
                severity='medium',
                confidence=100,
                first_seen=datetime.utcnow() - timedelta(days=14),
                last_seen=datetime.utcnow(),
                tags=f'LogHub,{subdir},verified-ip,unattributed',
                case_id=case.id if case else None
            ))
            count += 1
    print(f'  Imported {count} IOCs from LogHub log IP extraction')
    return count


def import_campaigns(actors, cases):
    """Create investigation tracking entries for real dataset cases (MITRE TTP reference only)."""
    if not cases:
        return
    for i, case in enumerate(cases[:min(5, len(cases))]):
        actor = actors[i % len(actors)] if actors else None
        camp_name = f'Investigation: {case.case_type} ({case.case_number})'
        camp = APTCampaign(
            name=camp_name,
            threat_actor_id=actor.id if actor else None,
            start_date=datetime.utcnow() - timedelta(days=60),
            status='active',
            targets=json.dumps([case.victim_sector or 'Unknown']),
            objective=f'Analyze verified {case.case_type} flows from public security datasets',
            description=(
                f'Active investigation on case {case.case_number} using verified dataset evidence. '
                f'MITRE actor {actor.name} listed for TTP comparison only — not confirmed attribution.'
                if actor else f'Active investigation on case {case.case_number} using verified dataset evidence.'
            ),
            ttps_used=actor.ttps if actor else '[]',
            iocs_count=IOC.query.filter_by(case_id=case.id).count(),
            confidence=100,
            risk_level='high' if case.priority == 'critical' else 'medium',
            case_id=case.id
        )
        db.session.add(camp)
        db.session.flush()
        IOC.query.filter_by(case_id=case.id).update({'campaign': camp_name})


def main():
    print('=' * 65)
    print('  BIGIL — Real Dataset Import')
    print('=' * 65)

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    app = create_app()
    with app.app_context():
        print('\n[1/6] Resetting database...')
        db.drop_all()
        db.create_all()

        print('[2/6] Creating users...')
        users = create_users()

        print('[3/6] Importing MITRE ATT&CK threat actors...')
        actors = import_mitre_actors()

        print('[4/6] Importing CIC-IDS2017 cases & evidence...')
        cic_cases = import_cic_cases(users, actors)

        print('[5/6] Importing UNSW-NB15 cases...')
        unsw_cases = import_unsw_cases(users)
        all_cases = cic_cases + unsw_cases

        print('[6/7] Importing LogHub log evidence...')
        import_loghub_evidence(users, all_cases)
        print('[7/7] Extracting real IOCs from LogHub logs...')
        import_loghub_iocs(users, all_cases)
        import_campaigns(actors, all_cases)

        db.session.add(AuditLog(
            user_id=users['dcp_suresh'].id,
            action='DATASET_IMPORT',
            resource_type='system',
            details='Imported real data from CIC-IDS2017, UNSW-NB15, LogHub, MITRE ATT&CK STIX',
            status='success'
        ))

        db.session.commit()

        print('\n' + '=' * 65)
        print('  Import Complete!')
        print(f'    Threat Actors: {ThreatActor.query.count()} (MITRE ATT&CK STIX)')
        print(f'    Cases:         {Case.query.count()} (CIC-IDS2017 + UNSW-NB15)')
        print(f'    Evidence:      {Evidence.query.count()} (with real files + SHA256)')
        print(f'    IOCs:          {IOC.query.count()} (from CIC-IDS2017 flows)')
        print(f'    Alerts:        {Alert.query.count()}')
        print(f'    Timeline:      {AttackTimeline.query.count()}')
        print('\n  Login: dcp_suresh / Gurugram@1234')
        print('=' * 65)


if __name__ == '__main__':
    main()
