"""Threat intelligence provider configuration from environment variables."""

import os

PROVIDERS = {
    'abuseipdb': {
        'name': 'AbuseIPDB',
        'env_key': 'ABUSEIPDB_API_KEY',
        'purpose': 'IP reputation, abuse reports, confidence scoring',
        'requires_key': True,
        'url': 'https://www.abuseipdb.com/',
    },
    'otx': {
        'name': 'AlienVault OTX',
        'env_key': 'OTX_API_KEY',
        'purpose': 'IOC enrichment, pulses, threat actor intelligence',
        'requires_key': True,
        'url': 'https://otx.alienvault.com/',
    },
    'malwarebazaar': {
        'name': 'MalwareBazaar',
        'env_key': 'MALWAREBAZAAR_API_KEY',
        'purpose': 'Malware sample intelligence, hash reputation',
        'requires_key': True,
        'url': 'https://bazaar.abuse.ch/api/',
    },
    'urlhaus': {
        'name': 'URLHaus',
        'env_key': 'URLHAUS_API_KEY',
        'purpose': 'Malicious URL intelligence, phishing tracking',
        'requires_key': True,
        'url': 'https://urlhaus.abuse.ch/api/',
    },
    'virustotal': {
        'name': 'VirusTotal',
        'env_key': 'VIRUSTOTAL_API_KEY',
        'purpose': 'Multi-engine file, URL, domain, IP intelligence',
        'requires_key': True,
        'url': 'https://www.virustotal.com/',
    },
}


def get_api_key(provider_id: str) -> str:
    cfg = PROVIDERS.get(provider_id, {})
    return (os.environ.get(cfg.get('env_key', '')) or '').strip()


def is_configured(provider_id: str) -> bool:
    cfg = PROVIDERS.get(provider_id, {})
    if not cfg.get('requires_key'):
        return True
    key = get_api_key(provider_id)
    return bool(key)


def get_provider_status() -> list:
    """Return configuration status for all TI providers."""
    status = []
    for pid, cfg in PROVIDERS.items():
        key = get_api_key(pid)
        configured = is_configured(pid)
        status.append({
            'id': pid,
            'name': cfg['name'],
            'purpose': cfg['purpose'],
            'configured': configured,
            'requires_key': cfg['requires_key'],
            'key_set': bool(key) if cfg['requires_key'] else True,
            'key_preview': f'{key[:6]}...{key[-4:]}' if key and len(key) > 12 else ('—' if cfg['requires_key'] else 'N/A'),
            'env_var': cfg['env_key'],
            'url': cfg['url'],
        })
    return status
