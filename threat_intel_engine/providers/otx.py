"""AlienVault OTX threat intelligence provider."""

import requests
from threat_intel_engine.config import get_api_key, is_configured
from threat_intel_engine.providers.base import BaseTIProvider

API_BASE = 'https://otx.alienvault.com/api/v1/indicators'
TIMEOUT = 20

OTX_TYPE_MAP = {
    'ip': 'IPv4',
    'ipv6': 'IPv6',
    'domain': 'domain',
    'url': 'url',
    'hash_sha256': 'file',
    'hash_md5': 'file',
}


class OTXProvider(BaseTIProvider):
    provider_id = 'otx'
    provider_name = 'AlienVault OTX'
    supported_types = ['ip', 'ipv6', 'domain', 'url', 'hash_sha256', 'hash_md5']

    def lookup(self, indicator: str, indicator_type: str) -> dict:
        if not is_configured(self.provider_id):
            return self._not_configured(indicator, indicator_type, 'OTX_API_KEY')

        otx_type = OTX_TYPE_MAP.get(indicator_type)
        if not otx_type:
            return self._error(indicator, indicator_type, f'OTX does not support type {indicator_type}')

        headers = {'X-OTX-API-KEY': get_api_key(self.provider_id)}
        try:
            general = requests.get(
                f'{API_BASE}/{otx_type}/{indicator}/general',
                headers=headers, timeout=TIMEOUT,
            )
            if general.status_code == 401:
                return self._error(indicator, indicator_type, 'Invalid OTX API key')
            general.raise_for_status()
            gdata = general.json()

            pulses = []
            try:
                pulses_resp = requests.get(
                    f'{API_BASE}/{otx_type}/{indicator}/pulses',
                    headers=headers, timeout=TIMEOUT,
                )
                if pulses_resp.ok:
                    pulses = (pulses_resp.json().get('results') or [])[:10]
            except requests.RequestException:
                pass
        except requests.RequestException as exc:
            return self._error(indicator, indicator_type, f'OTX request failed: {exc}')

        pulse_count = int(gdata.get('pulse_info', {}).get('count', 0) or len(pulses))
        malicious = pulse_count > 0
        confidence = min(100, pulse_count * 8 + (20 if malicious else 0))

        related = []
        for pulse in pulses[:5]:
            related.append({
                'type': 'pulse',
                'value': pulse.get('name', ''),
                'source': 'OTX',
                'tags': ', '.join((pulse.get('tags') or [])[:5]),
            })

        observations = []
        if gdata.get('country_name'):
            observations.append(f"Country: {gdata['country_name']}")
        if gdata.get('asn'):
            observations.append(f"ASN: {gdata['asn']}")
        validation = gdata.get('validation')
        if isinstance(validation, dict):
            for k, v in validation.items():
                if v:
                    observations.append(f"Validation — {k}: confirmed")
        elif isinstance(validation, list):
            for item in validation:
                if isinstance(item, dict):
                    name = item.get('name') or item.get('source') or 'validation'
                    if item.get('message'):
                        observations.append(f"Validation — {name}: {item['message']}")
                    elif item.get('validated'):
                        observations.append(f"Validation — {name}: confirmed")
        observations.append(f"Threat pulses: {pulse_count}")
        for pulse in pulses[:3]:
            observations.append(f"Pulse: {pulse.get('name', 'Unknown')} ({pulse.get('created', '')[:10]})")

        threat_cats = set()
        for pulse in pulses:
            for tag in (pulse.get('tags') or []):
                threat_cats.add(tag)
        threat_cat = ', '.join(sorted(threat_cats)[:5]) or ('threat_intel' if malicious else 'clean')

        risk = 'critical' if pulse_count >= 10 else 'high' if pulse_count >= 3 else 'medium' if pulse_count else 'info'

        return self._result(
            indicator, indicator_type,
            configured=True, success=True,
            malicious=malicious,
            confidence=confidence,
            threat_category=threat_cat,
            reputation_score=max(0, 100 - confidence),
            risk_level=risk,
            summary=f"OTX: {pulse_count} threat pulse(s) correlated with this indicator",
            related_indicators=related,
            observations=observations,
            raw={'pulse_count': pulse_count, 'reputation': gdata.get('reputation', 0)},
        )
