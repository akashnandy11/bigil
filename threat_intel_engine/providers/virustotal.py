"""VirusTotal multi-engine intelligence provider."""

import base64
import requests
from threat_intel_engine.config import get_api_key, is_configured
from threat_intel_engine.providers.base import BaseTIProvider

API_BASE = 'https://www.virustotal.com/api/v3'
TIMEOUT = 15


class VirusTotalProvider(BaseTIProvider):
    provider_id = 'virustotal'
    provider_name = 'VirusTotal'
    supported_types = ['ip', 'ipv6', 'domain', 'url', 'hash_sha256', 'hash_md5']

    def _headers(self):
        return {'x-apikey': get_api_key(self.provider_id)}

    def _endpoint(self, indicator: str, indicator_type: str) -> str:
        if indicator_type in ('hash_sha256', 'hash_md5'):
            return f'{API_BASE}/files/{indicator}'
        if indicator_type == 'ip':
            return f'{API_BASE}/ip_addresses/{indicator}'
        if indicator_type == 'ipv6':
            return f'{API_BASE}/ip_addresses/{indicator}'
        if indicator_type == 'domain':
            return f'{API_BASE}/domains/{indicator}'
        if indicator_type == 'url':
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip('=')
            return f'{API_BASE}/urls/{url_id}'
        raise ValueError(f'Unsupported type: {indicator_type}')

    def lookup(self, indicator: str, indicator_type: str) -> dict:
        if not is_configured(self.provider_id):
            return self._not_configured(indicator, indicator_type, 'VIRUSTOTAL_API_KEY')

        try:
            resp = requests.get(
                self._endpoint(indicator, indicator_type),
                headers=self._headers(),
                timeout=TIMEOUT,
            )
            if resp.status_code == 401:
                return self._error(indicator, indicator_type, 'Invalid VirusTotal API key')
            if resp.status_code == 404:
                return self._result(
                    indicator, indicator_type,
                    configured=True, success=True,
                    malicious=False, confidence=0,
                    threat_category='clean',
                    reputation_score=90,
                    risk_level='info',
                    summary='Not found in VirusTotal database',
                )
            if resp.status_code == 429:
                return self._error(indicator, indicator_type, 'VirusTotal rate limit exceeded')
            resp.raise_for_status()
            attrs = resp.json().get('data', {}).get('attributes', {})
        except requests.RequestException as exc:
            return self._error(indicator, indicator_type, f'VirusTotal request failed: {exc}')

        stats = attrs.get('last_analysis_stats') or {}
        malicious_count = int(stats.get('malicious', 0))
        suspicious = int(stats.get('suspicious', 0))
        harmless = int(stats.get('harmless', 0))
        total = malicious_count + suspicious + harmless + int(stats.get('undetected', 0))
        confidence = round((malicious_count + suspicious * 0.5) / total * 100, 1) if total else 0
        malicious = malicious_count > 0 or suspicious >= 3

        observations = [
            f"Engines: {malicious_count} malicious, {suspicious} suspicious, {harmless} harmless (of {total})",
        ]
        if attrs.get('country'):
            observations.append(f"Country: {attrs['country']}")
        if attrs.get('as_owner'):
            observations.append(f"AS owner: {attrs['as_owner']}")
        if attrs.get('meaningful_name'):
            observations.append(f"Sample name: {attrs['meaningful_name']}")
        if attrs.get('type_description'):
            observations.append(f"Type: {attrs['type_description']}")
        if attrs.get('last_analysis_date'):
            observations.append(f"Last analysis: {attrs['last_analysis_date']}")

        threat_cat = 'malicious'
        if indicator_type in ('hash_sha256', 'hash_md5'):
            results = attrs.get('last_analysis_results') or {}
            for engine, result in list(results.items())[:3]:
                if result.get('result'):
                    threat_cat = result['result']
                    break
        elif attrs.get('categories'):
            cats = attrs['categories']
            threat_cat = ', '.join(cats.values()) if isinstance(cats, dict) else str(cats)

        reputation = int(attrs.get('reputation', 0))
        rep_score = max(0, min(100, 50 - reputation)) if reputation else max(0, 100 - int(confidence))

        risk = 'critical' if malicious_count >= 5 else 'high' if malicious else 'medium' if suspicious else 'info'

        related = []
        for rel_type, rel_key in [('contacted_domains', 'domain'), ('contacted_ips', 'ip'),
                                   ('subdomains', 'domain'), ('communicating_files', 'hash_sha256')]:
            items = attrs.get(rel_type) or []
            for item in items[:5]:
                val = item if isinstance(item, str) else item.get('id', str(item))
                related.append({'type': rel_key, 'value': val, 'source': 'VirusTotal'})

        return self._result(
            indicator, indicator_type,
            configured=True, success=True,
            malicious=malicious,
            confidence=confidence,
            threat_category=threat_cat,
            reputation_score=rep_score,
            risk_level=risk,
            summary=f"VirusTotal: {malicious_count}/{total} engines flagged malicious",
            related_indicators=related,
            observations=observations,
            raw={'last_analysis_stats': stats, 'reputation': reputation},
        )
