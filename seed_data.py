from app import create_app, db
from app.models import User, Investigator, Case, Evidence, EvidenceChain, AttackTimeline, IOC, ThreatActor, APTCampaign, Alert, AuditLog, InvestigationNote
from datetime import datetime, timedelta
import random

def seed():
    app = create_app()
    with app.app_context():
        print("Re-creating database tables...")
        db.drop_all()
        db.create_all()

        print("Seeding Users and Investigators...")
        # 1. Users
        users_data = [
            {
                'username': 'dcp_suresh',
                'email': 'suresh.kumar@hry.gov.in',
                'role': 'admin',
                'badge_number': 'GP-89304',
                'full_name': 'Suresh Kumar',
                'rank': 'DCP Cyber Crime',
                'unit': 'Cyber Cell Headquarters',
                'specialization': 'Command & Cyber Policy'
            },
            {
                'username': 'insp_rajendra',
                'email': 'rajendra.prasad@hry.gov.in',
                'role': 'investigator',
                'badge_number': 'GP-77291',
                'full_name': 'Rajendra Prasad',
                'rank': 'Inspector',
                'unit': 'Forensics Lab Division',
                'specialization': 'Digital Forensics & Malware Analysis'
            },
            {
                'username': 'si_akash',
                'email': 'akash.sharma@hry.gov.in',
                'role': 'analyst',
                'badge_number': 'GP-90123',
                'full_name': 'Akash Sharma',
                'rank': 'Sub-Inspector',
                'unit': 'Threat Intelligence Unit',
                'specialization': 'Network Intrusion & Log Analysis'
            },
            {
                'username': 'sp_crime',
                'email': 'sp.crime@hry.gov.in',
                'role': 'viewer',
                'badge_number': 'GP-55482',
                'full_name': 'Devender Yadav',
                'rank': 'SP Crime',
                'unit': 'Supervisory Board',
                'specialization': 'Oversight & Compliance'
            }
        ]

        users = {}
        for ud in users_data:
            u = User(
                username=ud['username'],
                email=ud['email'],
                role=ud['role'],
                badge_number=ud['badge_number'],
                full_name=ud['full_name'],
                is_active=True
            )
            u.set_password('Gurugram@1234')
            db.session.add(u)
            db.session.flush() # get user id
            users[ud['username']] = u

            # Add Investigator Profile
            inv = Investigator(
                user_id=u.id,
                rank=ud['rank'],
                unit=ud['unit'],
                specialization=ud['specialization'],
                cases_handled=random.randint(5, 25)
            )
            db.session.add(inv)

        print("Seeding Threat Actors...")
        # 2. Threat Actors
        actors_data = [
            {
                'name': 'Sandworm',
                'aliases': 'TeleBots, Voodoo Bear, Iron Viking, APT44',
                'origin_country': 'Russia',
                'motivation': 'Sabotage & Geopolitical Espionage',
                'sophistication': 'nation-state',
                'active_since': '2009',
                'description': 'Highly destructive group operating under the Russian GRU. Notorious for targetting power grids, using BlackEnergy and Industroyer payloads, and deploying the devastating NotPetya malware.',
                'targets': 'Energy, Utilities, Government, Defense, Critical Infrastructure',
                'ttps': '[{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}, {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"}, {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}]',
                'tools': '["Industroyer", "BlackEnergy", "NotPetya", "Mimikatz", "PasTool"]',
                'infrastructure': '["185.220.101.5", "log.sandworm-c2.net", "update.microsoft-sys.com"]',
                'risk_score': 98
            },
            {
                'name': 'Lazarus Group',
                'aliases': 'Hidden Cobra, Guardians of Peace, APT38',
                'origin_country': 'North Korea',
                'motivation': 'Financial Theft & Espionage',
                'sophistication': 'nation-state',
                'active_since': '2009',
                'description': 'State-sponsored hacker group linked to the North Korean government. Responsible for major cryptocurrency thefts, the WannaCry ransomware attack, and the Sony Pictures hack.',
                'targets': 'Financial Institutions, Cryptocurrency Exchanges, Government, Media',
                'ttps': '[{"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"}, {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"}]',
                'tools': '["WannaCry", "Conti", "Fallchill", "Mimikatz", "Dacls"]',
                'infrastructure': '["91.240.118.12", "cdn.jquery-update.org", "wallet.blockchain-rewards.info"]',
                'risk_score': 95
            },
            {
                'name': 'APT41',
                'aliases': 'Double Dragon, Barium, Winnti, Wicked Panda',
                'origin_country': 'China',
                'motivation': 'Espionage & Personal Financial Gain',
                'sophistication': 'nation-state',
                'active_since': '2012',
                'description': 'Prolific state-sponsored threat group that also conducts financially motivated operations outside of normal government hours. Known for supply-chain compromises.',
                'targets': 'Software Providers, Telecommunications, Healthcare, Gov Portals',
                'ttps': '[{"id": "T1195.002", "name": "Supply Chain Compromise: Compromise Software Dependencies", "tactic": "Initial Access"}, {"id": "T1021.004", "name": "SSH Sessions", "tactic": "Lateral Movement"}]',
                'tools': '["ShadowPad", "Cobalt Strike", "PlugX", "ChinChopper", "Crossbow"]',
                'infrastructure': '["103.255.44.89", "service.winnti-server.com", "update.linux-patch.org"]',
                'risk_score': 92
            },
            {
                'name': 'APT28',
                'aliases': 'Fancy Bear, Sofacy, Sednit, Tsar Team',
                'origin_country': 'Russia',
                'motivation': 'Geopolitical Espionage & Influence Operations',
                'sophistication': 'nation-state',
                'active_since': '2004',
                'description': 'Russian military intelligence actor. Specialized in targeting government, military, security organizations, and political parties globally. Active in spreading disinformation.',
                'targets': 'Defense, Government, NATO, Political Organizations, Think Tanks',
                'ttps': '[{"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"}, {"id": "T1078.003", "name": "Local Accounts", "tactic": "Persistence"}]',
                'tools': '["X-Agent", "CHOPSTICK", "Seduploader", "Responder", "Empire"]',
                'infrastructure': '["45.89.223.12", "mail.defense-nato.org", "login.state-mail.net"]',
                'risk_score': 89
            }
        ]

        actors = {}
        for ad in actors_data:
            ta = ThreatActor(
                name=ad['name'],
                aliases=ad['aliases'],
                origin_country=ad['origin_country'],
                motivation=ad['motivation'],
                sophistication=ad['sophistication'],
                active_since=ad['active_since'],
                description=ad['description'],
                targets=ad['targets'],
                ttps=ad['ttps'],
                tools=ad['tools'],
                infrastructure=ad['infrastructure'],
                risk_score=ad['risk_score']
            )
            db.session.add(ta)
            db.session.flush()
            actors[ad['name']] = ta

        print("Seeding Cases...")
        # 3. Cases
        cases_data = [
            {
                'case_number': 'CYB-493021-2026',
                'title': 'Intrusion Campaign targeting Gurugram State Power Distribution Grid',
                'description': 'Unusual telemetry command anomalies detected in District-4 Power distribution SCADA system. Initial logs indicate unauthorized remote login via legacy VPN endpoint and subsequent lateral movement to domain controllers. Attributed to Sandworm targeting public utility systems.',
                'status': 'active',
                'priority': 'critical',
                'case_type': 'APT',
                'assigned_to': users['si_akash'].id,
                'created_by': users['dcp_suresh'].id,
                'tags': 'scada, energy, power-grid, sandworm, vpn-breach',
                'victim_org': 'Haryana State Electricity Board (HSEB)',
                'victim_sector': 'Energy & Utilities'
            },
            {
                'case_number': 'CYB-883011-2026',
                'title': 'Ransomware threat targeting District General Hospital networks',
                'description': 'Hospital administrative systems locked with Conti-variant payload. Internal Active Directory compromised. Forensic evidence shows initial entry through spearphishing emails targetting HR department staff. Financial demands routed through North Korean associated digital wallet addresses.',
                'status': 'open',
                'priority': 'high',
                'case_type': 'Ransomware',
                'assigned_to': users['insp_rajendra'].id,
                'created_by': users['dcp_suresh'].id,
                'tags': 'hospital, ransomware, conti, phishing, lazarus',
                'victim_org': 'Gurugram General District Hospital',
                'victim_sector': 'Healthcare & Pharma'
            },
            {
                'case_number': 'CYB-129034-2026',
                'title': 'State Secretariat Phishing & Document Exfiltration Incident',
                'description': 'Multiple high-ranking secretariat officials targeted with highly customized malicious PDF attachments mimicking official security bulletins. Several mailboxes compromised and active synchronization detected to external IP resources attributed to APT28 infrastructure.',
                'status': 'active',
                'priority': 'high',
                'case_type': 'APT',
                'assigned_to': users['si_akash'].id,
                'created_by': users['dcp_suresh'].id,
                'tags': 'phishing, exfiltration, apt28, gov-cell',
                'victim_org': 'Haryana State Secretariat Office',
                'victim_sector': 'Government & Defense'
            },
            {
                'case_number': 'CYB-553018-2026',
                'title': 'Unauthorized API Database Queries on Government ID Registry Portal',
                'description': 'Security operations center detected automated API requests scanning identity registration numbers from an IP block located in Southeast Asia. System logs show database traversal commands matching indicators for APT41 tools.',
                'status': 'pending',
                'priority': 'medium',
                'case_type': 'DataExfil',
                'assigned_to': users['insp_rajendra'].id,
                'created_by': users['dcp_suresh'].id,
                'tags': 'api, database, scanning, apt41, api-abuse',
                'victim_org': 'State Identity Card Registry Office',
                'victim_sector': 'Government & Defense'
            },
            {
                'case_number': 'CYB-998311-2026',
                'title': 'Resolved DDoS Outage on Gurugram Municipal Corporation Portal',
                'description': 'Municipal payment portals faced 4-hour service degradation due to coordinated botnet HTTP flood. System successfully mitigated after rate-limiting suspect subnet blocks and updating edge firewall rules.',
                'status': 'closed',
                'priority': 'low',
                'case_type': 'DDoS',
                'assigned_to': users['si_akash'].id,
                'created_by': users['dcp_suresh'].id,
                'tags': 'ddos, web, downtime, closed-case',
                'victim_org': 'Municipal Corporation of Gurugram',
                'victim_sector': 'Public Infrastructure',
                'closed_at': datetime.utcnow()
            }
        ]

        cases = {}
        for cd in cases_data:
            c = Case(
                case_number=cd['case_number'],
                title=cd['title'],
                description=cd['description'],
                status=cd['status'],
                priority=cd['priority'],
                case_type=cd['case_type'],
                assigned_to=cd['assigned_to'],
                created_by=cd['created_by'],
                tags=cd['tags'],
                victim_org=cd['victim_org'],
                victim_sector=cd['victim_sector'],
                closed_at=cd.get('closed_at')
            )
            db.session.add(c)
            db.session.flush()
            cases[cd['case_number']] = c

        print("Seeding APT Campaigns...")
        # 4. APT Campaigns
        campaigns_data = [
            {
                'name': 'Operation GridLock',
                'threat_actor_id': actors['Sandworm'].id,
                'start_date': datetime.utcnow() - timedelta(days=60),
                'end_date': None,
                'status': 'active',
                'targets': 'Haryana PowerSCADA utility networks, Regional Load Despatch Centers',
                'objective': 'Establish persistence in power substations, test remote command execution triggers',
                'description': 'A highly sophisticated infrastructure targeting campaign. Employs modified legacy VPN configs to gain access, deploys custom PowerShell loader files to bypass logging, and scans for IEC-104 control systems.',
                'ttps_used': '[{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}, {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"}, {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}]',
                'iocs_count': 12,
                'confidence': 85,
                'risk_level': 'critical',
                'case_id': cases['CYB-493021-2026'].id
            },
            {
                'name': 'Operation ShadowPhish',
                'threat_actor_id': actors['APT28'].id,
                'start_date': datetime.utcnow() - timedelta(days=30),
                'end_date': None,
                'status': 'active',
                'targets': 'State Secretariat official email communication systems',
                'objective': 'Exfiltration of diplomatic cables, administrative bulletins and military coordination reports',
                'description': 'Targeted spearphishing campaign using custom attachments pretending to be HR survey notices or security alerts. Downloads lightweight shell tools mapping back to Russian GRU command-and-control servers.',
                'ttps_used': '[{"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"}, {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"}]',
                'iocs_count': 8,
                'confidence': 90,
                'risk_level': 'high',
                'case_id': cases['CYB-129034-2026'].id
            }
        ]

        for cmp in campaigns_data:
            ac = APTCampaign(
                name=cmp['name'],
                threat_actor_id=cmp['threat_actor_id'],
                start_date=cmp['start_date'],
                end_date=cmp['end_date'],
                status=cmp['status'],
                targets=cmp['targets'],
                objective=cmp['objective'],
                description=cmp['description'],
                ttps_used=cmp['ttps_used'],
                iocs_count=cmp['iocs_count'],
                confidence=cmp['confidence'],
                risk_level=cmp['risk_level'],
                case_id=cmp['case_id']
            )
            db.session.add(ac)

        print("Seeding Evidence...")
        # 5. Evidence & Chain of Custody
        evidence_data = [
            {
                'evidence_id': 'EV-9018402',
                'case_id': cases['CYB-493021-2026'].id,
                'title': 'HSEB SCADA Substation-3 VPN Logs',
                'description': 'Network connection log dump from Fortinet VPN gateway at Substation-3 showing login anomalies from foreign IP subnet. SHA-256 integrity match.',
                'category': 'log',
                'file_name': 'hsebsub3_vpn_june2026.log',
                'file_size': 1204850,
                'file_hash_md5': '7b1d1fa523b8812739fa4bb5a2e58fb9',
                'file_hash_sha256': '9b0c2284fae238cbef12948011cbaef523b018cf427db9fa30f402e11894d03d',
                'source': 'HSEB-Substation-3-VPN-GW',
                'collected_by': users['si_akash'].id,
                'tags': 'VPN, logs, Sandworm, SCADA',
                'status': 'verified',
                'verified_by': users['insp_rajendra'].id,
                'chain_notes': 'Transferred via encrypted forensics USB drive from HSEB NOC to Cyber Cell forensics workspace. Initial SHA-256 computed and matched.'
            },
            {
                'evidence_id': 'EV-8820491',
                'case_id': cases['CYB-493021-2026'].id,
                'title': 'SCADA HMI Domain Controller Memory Dump',
                'description': 'Volatile memory dump (RAM) extracted from HSEB-DC-01 server containing running system processes and suspected active network sockets.',
                'category': 'memory',
                'file_name': 'hsebdc01_memdump.raw',
                'file_size': 16106127360,
                'file_hash_md5': 'b9f2a4128df050eb41fa16bcdeaa2b12',
                'file_hash_sha256': '2a9f4c328dbec1267b9fe41a2bcda8fb01278cb9d84faeef81b894101e40fe2c',
                'source': 'HSEB-DC-01-WinServer2019',
                'collected_by': users['insp_rajendra'].id,
                'tags': 'RAM, Memory, Windows, DC, Mimikatz',
                'status': 'collected',
                'verified_by': None,
                'chain_notes': 'RAM captured using FTK Imager CLI by Inspector Rajendra. Sealed in anti-static bag and locked in Cyber Lab Evidence Safe.'
            },
            {
                'evidence_id': 'EV-1290348',
                'case_id': cases['CYB-129034-2026'].id,
                'title': 'Spearphishing Email Payload PDF Attachment',
                'description': 'Malicious PDF payload attached to fake security bulletin emails sent to secretariat officials. Exploits CVE-2023-26360 vulnerability to execute shell code.',
                'category': 'artifact',
                'file_name': 'official_bulletin_2026.pdf',
                'file_size': 490218,
                'file_hash_md5': 'ea20fa128dbef0e123fa5a78cb1290fe',
                'file_hash_sha256': '77cf89be12aebcdeff120489cf8210fe9031c28ef0e998fa789dcd89fcdb890a',
                'source': 'Secretariat-MailSrv-Exchange',
                'collected_by': users['si_akash'].id,
                'tags': 'PDF, Phishing, Exploit, Shellcode, APT28',
                'status': 'verified',
                'verified_by': users['insp_rajendra'].id,
                'chain_notes': 'Extracted from mail servers queue. Isolated in forensics sandbox and computed SHA-256.'
            }
        ]

        for ed in evidence_data:
            ev = Evidence(
                evidence_id=ed['evidence_id'],
                case_id=ed['case_id'],
                title=ed['title'],
                description=ed['description'],
                category=ed['category'],
                file_name=ed['file_name'],
                file_size=ed['file_size'],
                file_hash_md5=ed['file_hash_md5'],
                file_hash_sha256=ed['file_hash_sha256'],
                source=ed['source'],
                collected_by=ed['collected_by'],
                tags=ed['tags'],
                status=ed['status'],
                verified=True if ed['status'] == 'verified' else False,
                verified_by=ed['verified_by']
            )
            db.session.add(ev)
            db.session.flush()

            # Custody Entry
            chain = EvidenceChain(
                evidence_id=ev.id,
                action='collected',
                performed_by=ed['collected_by'],
                notes=ed['chain_notes'],
                location='Gurugram Cyber forensics safe'
            )
            db.session.add(chain)

            if ed['status'] == 'verified':
                v_chain = EvidenceChain(
                    evidence_id=ev.id,
                    action='verified',
                    performed_by=ed['verified_by'],
                    notes=f"Cryptographic hash matched exactly against initial log value. Integrity verified.",
                    location='Cyber forensics lab console'
                )
                db.session.add(v_chain)

        print("Seeding Attack Timelines...")
        # 6. Attack Timelines
        timeline_events = [
            # Case 1 events
            {
                'case_id': cases['CYB-493021-2026'].id,
                'event_time': datetime.utcnow() - timedelta(days=5, hours=10),
                'event_title': 'Initial VPN Authentication Anomaly',
                'event_description': 'Legacy VPN gateway recorded successful authorization of user profile "hsebsub3_eng" using credentials previously leaked on darknet. Threat actor connection sourced from foreign VPN gateway.',
                'attack_phase': 'initial_access',
                'mitre_technique': 'T1078.003',
                'severity': 'high',
                'source_ip': '185.220.101.5',
                'dest_ip': '10.0.3.1',
                'evidence_ref': 'EV-9018402',
                'notes': 'VPN logs confirm authentication bypassed multi-factor check since substation legacy system only required username/password.'
            },
            {
                'case_id': cases['CYB-493021-2026'].id,
                'event_time': datetime.utcnow() - timedelta(days=5, hours=8),
                'event_title': 'Internal Network Scanning & Discovery',
                'event_description': 'Network sweeps originating from the compromised engineering terminal identified active Domain Controller IP and HMI terminal endpoints.',
                'attack_phase': 'recon',
                'mitre_technique': 'T1046',
                'severity': 'medium',
                'source_ip': '10.0.3.42',
                'dest_ip': '10.0.1.0/24',
                'evidence_ref': 'EV-9018402',
                'notes': 'Internal traffic analysis reveals ICMP ping sweeps and TCP port scans to ports 80, 445, and 3389.'
            },
            {
                'case_id': cases['CYB-493021-2026'].id,
                'event_time': datetime.utcnow() - timedelta(days=4, hours=22),
                'event_title': 'Domain Controller LSASS Credential Harvesting',
                'event_description': 'Volatile memory analysis of Domain Controller (HSEB-DC-01) indicates execution of Mimikatz payload targeting LSASS memory address space to dump credentials.',
                'attack_phase': 'execution',
                'mitre_technique': 'T1003.001',
                'severity': 'critical',
                'source_ip': '10.0.3.42',
                'dest_ip': '10.0.1.10',
                'evidence_ref': 'EV-8820491',
                'notes': 'Inspector Rajendra recovered command history remnants indicating a dump of local domain administrator hashes.'
            },
            # Case 2 events
            {
                'case_id': cases['CYB-129034-2026'].id,
                'event_time': datetime.utcnow() - timedelta(days=15),
                'event_title': 'Spearphishing Email Received by Secretariat DCP',
                'event_description': 'Officer received an email formatted to appear as Haryana Personnel Board administrative order containing a malicious PDF attachment titled "security_orders_june2026.pdf".',
                'attack_phase': 'initial_access',
                'mitre_technique': 'T1566.001',
                'severity': 'high',
                'source_ip': '45.89.223.12',
                'dest_ip': '10.150.12.80',
                'evidence_ref': 'EV-1290348',
                'notes': 'PDF contains javascript exploit triggering cmd.exe launch upon opening.'
            }
        ]

        for te in timeline_events:
            event = AttackTimeline(
                case_id=te['case_id'],
                event_time=te['event_time'],
                event_title=te['event_title'],
                event_description=te['event_description'],
                attack_phase=te['attack_phase'],
                mitre_technique=te['mitre_technique'],
                severity=te['severity'],
                source_ip=te['source_ip'],
                dest_ip=te['dest_ip'],
                evidence_ref=te['evidence_ref'],
                notes=te['notes']
            )
            db.session.add(event)

        print("Seeding IOCs...")
        # 7. IOCs
        iocs_data = [
            {
                'ioc_type': 'ip',
                'value': '185.220.101.5',
                'description': 'Known Tor exit node linked to Sandworm VPN login actions targeting public utility SCADA VPN gateways.',
                'threat_actor': 'Sandworm',
                'campaign': 'Operation GridLock',
                'severity': 'critical',
                'confidence': 90,
                'case_id': cases['CYB-493021-2026'].id
            },
            {
                'ioc_type': 'domain',
                'value': 'log.sandworm-c2.net',
                'description': 'Suspected command and control server used for staging malware loaders.',
                'threat_actor': 'Sandworm',
                'campaign': 'Operation GridLock',
                'severity': 'critical',
                'confidence': 85,
                'case_id': cases['CYB-493021-2026'].id
            },
            {
                'ioc_type': 'hash_sha256',
                'value': '77cf89be12aebcdeff120489cf8210fe9031c28ef0e998fa789dcd89fcdb890a',
                'description': 'Malicious PDF document containing exploit code targeting Adobe Acrobat buffer overflow vulnerability.',
                'threat_actor': 'APT28',
                'campaign': 'Operation ShadowPhish',
                'severity': 'high',
                'confidence': 95,
                'case_id': cases['CYB-129034-2026'].id
            },
            {
                'ioc_type': 'domain',
                'value': 'wallet.blockchain-rewards.info',
                'description': 'Crypto reward phishing domain utilized by North Korean threat groups to spoof finance logins.',
                'threat_actor': 'Lazarus Group',
                'campaign': '',
                'severity': 'high',
                'confidence': 80,
                'case_id': cases['CYB-883011-2026'].id
            },
            {
                'ioc_type': 'ip',
                'value': '103.255.44.89',
                'description': 'Cobalt Strike listener host scanning government portals across India.',
                'threat_actor': 'APT41',
                'campaign': '',
                'severity': 'medium',
                'confidence': 75,
                'case_id': cases['CYB-553018-2026'].id
            }
        ]

        for idt in iocs_data:
            ioc = IOC(
                ioc_type=idt['ioc_type'],
                value=idt['value'],
                description=idt['description'],
                threat_actor=idt['threat_actor'],
                campaign=idt['campaign'],
                severity=idt['severity'],
                confidence=idt['confidence'],
                first_seen=datetime.utcnow() - timedelta(days=90),
                last_seen=datetime.utcnow(),
                is_active=True,
                case_id=idt['case_id']
            )
            db.session.add(ioc)

        print("Seeding Alerts...")
        # 8. Alerts
        alerts_data = [
            {
                'title': 'Anomalous VPN Authentication Substation-3',
                'description': 'Telemetry detection system flagged successful VPN login from known Tor node IP 185.220.101.5 associated with Sandworm campaigns.',
                'severity': 'critical',
                'alert_type': 'ioc_match',
                'source': 'Threat Intelligence Engine',
                'case_id': cases['CYB-493021-2026'].id,
                'assigned_to': users['si_akash'].id,
                'status': 'open',
                'risk_score': 95
            },
            {
                'title': 'Host Compromise Alert: HSEB-DC-01',
                'description': 'Forensics logs reported unauthorized creation of admin domain account bypassing traditional registration mechanisms.',
                'severity': 'critical',
                'alert_type': 'anomaly',
                'source': 'AD Audit Monitor',
                'case_id': cases['CYB-493021-2026'].id,
                'assigned_to': users['si_akash'].id,
                'status': 'open',
                'risk_score': 98
            },
            {
                'title': 'Suspected Spearphishing Email Captured',
                'description': 'Inbox scanner flagged incoming email containing PDF payload with signature matching Operation ShadowPhish indicators.',
                'severity': 'high',
                'alert_type': 'ioc_match',
                'source': 'Exchange Gateway Sandbox',
                'case_id': cases['CYB-129034-2026'].id,
                'assigned_to': users['insp_rajendra'].id,
                'status': 'open',
                'risk_score': 88
            }
        ]

        for ad in alerts_data:
            alt = Alert(
                title=ad['title'],
                description=ad['description'],
                severity=ad['severity'],
                alert_type=ad['alert_type'],
                source=ad['source'],
                case_id=ad['case_id'],
                assigned_to=ad['assigned_to'],
                status=ad['status'],
                created_at=datetime.utcnow(),
                risk_score=ad['risk_score']
            )
            db.session.add(alt)

        print("Seeding Audit Logs...")
        # 9. Audit Logs
        audit_data = [
            {
                'user_id': users['dcp_suresh'].id,
                'action': 'USER_CREATE',
                'resource_type': 'users',
                'resource_id': str(users['si_akash'].id),
                'details': 'Initialized Sub-Inspector Akash Sharma analyst profile.',
                'status': 'success'
            },
            {
                'user_id': users['dcp_suresh'].id,
                'action': 'CASE_CREATE',
                'resource_type': 'cases',
                'resource_id': str(cases['CYB-493021-2026'].id),
                'details': 'Created case file for HSEB substation SCADA intrusion.',
                'status': 'success'
            },
            {
                'user_id': users['si_akash'].id,
                'action': 'EVIDENCE_UPLOAD',
                'resource_type': 'evidence',
                'resource_id': 'EV-9018402',
                'details': 'Uploaded and registered HSEB substation-3 VPN logs.',
                'status': 'success'
            },
            {
                'user_id': users['insp_rajendra'].id,
                'action': 'EVIDENCE_VERIFY',
                'resource_type': 'evidence',
                'resource_id': 'EV-9018402',
                'details': 'Verified SHA-256 integrity match on HSEB substation-3 VPN logs.',
                'status': 'success'
            }
        ]

        for ad in audit_data:
            log = AuditLog(
                user_id=ad['user_id'],
                action=ad['action'],
                resource_type=ad['resource_type'],
                resource_id=ad['resource_id'],
                ip_address='10.20.50.12',
                details=ad['details'],
                timestamp=datetime.utcnow() - timedelta(days=1),
                status=ad['status']
            )
            db.session.add(log)

        print("Seeding Case Notes...")
        # 10. Investigation Notes
        notes_data = [
            {
                'case_id': cases['CYB-493021-2026'].id,
                'author_id': users['si_akash'].id,
                'title': 'Initial Assessment Notes',
                'content': 'We suspect this is a Russian state-sponsored action targetting energy systems. The execution techniques line up with Sandworm. VPN credentials were key.',
                'note_type': 'intelligence'
            },
            {
                'case_id': cases['CYB-493021-2026'].id,
                'author_id': users['insp_rajendra'].id,
                'title': 'Forensics Lab Status',
                'content': 'Memory dump EV-8820491 is secured and analysis has started. Volatility tools being used to search for LSASS artifacts.',
                'note_type': 'technical'
            }
        ]

        for nd in notes_data:
            note = InvestigationNote(
                case_id=nd['case_id'],
                author_id=nd['author_id'],
                title=nd['title'],
                content=nd['content'],
                note_type=nd['note_type']
            )
            db.session.add(note)

        db.session.commit()
        print("Database Seeding Completed Successfully!")

if __name__ == '__main__':
    seed()
