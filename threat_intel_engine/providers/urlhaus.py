"""URLHaus malicious URL intelligence provider."""

import requests
from urllib.parse import urlparse
from threat_intel_engine.config import get_api_key, is_configured
from threat_intel_engine.providers.base import BaseTIProvider

API_URL = 'https://urlhaus-api.abuse.ch/v1'
TIMEOUT = 12


class URLHausProvider(BaseTIProvider):
    provider_id = 'urlhaus'
    provider_name = 'URLHaus'
    supported_types = ['url', 'domain']

    def _headers(self):
        key = get_api_key(self.provider_id)
        if key:
            return {'Auth-Key': key}
        return {}

    def lookup(self, indicator: str, indicator_type: str) -> dict:
        if not is_configured(self.provider_id):
            return self._not_configured(indicator, indicator_type, 'URLHAUS_API_KEY')

        try:
            if indicator_type == 'domain':
                resp = requests.post(
                    f'{API_URL}/host/',
                    data={'host': indicator},
                    headers=self._headers(),
                    timeout=TIMEOUT,
                )
            else:
                resp = requests.post(
                    f'{API_URL}/url/',
                    data={'url': indicator},
                    headers=self._headers(),
                    timeout=TIMEOUT,
                )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            return self._error(indicator, indicator_type, f'URLHaus request failed: {exc}')

        query_status = data.get('query_status', '')
        if query_status in ('no_results', 'invalid_host', 'invalid_url'):
            return self._result(
                indicator, indicator_type,
                configured=True, success=True,
                malicious=False, confidence=0,
                threat_category='clean',
                reputation_score=90,
                risk_level='info',
                summary=f'URLHaus: no malicious listing for this {indicator_type}',
                observations=[f'Query status: {query_status}'],
            )

        if indicator_type == 'domain':
            urls = data.get('urls') or []
            url_count = data.get('url_count', len(urls))
            threat = data.get('blacklists') or {}
            malicious = url_count > 0
            observations = [
                f"Malicious URLs on host: {url_count}",
                f"Blacklisted: {threat}",
            ]
            related = [
                {'type': 'url', 'value': u.get('url', ''), 'source': 'URLHaus', 'status': u.get('url_status', '')}
                for u in urls[:10]
            ]
            threat_cat = (urls[0].get('threat', 'malware_distribution') if urls else 'malware_distribution')
            summary = f"URLHaus: {url_count} malicious URL(s) on host {indicator}"
        else:
            threat_cat = data.get('threat', 'malware_distribution')
            status = data.get('url_status', 'unknown')
            tags = data.get('tags') or []
            malicious = status in ('online', 'offline') or bool(threat_cat)
            url_count = 1
            observations = [
                f"URL status: {status}",
                f"Threat: {threat_cat}",
                f"Date added: {data.get('dateadded', 'N/A')}",
                f"Reporter: {data.get('reporter', 'N/A')}",
            ]
            if tags:
                observations.append(f"Tags: {', '.join(tags)}")
            if data.get('urlhaus_reference'):
                observations.append(f"Reference: {data['urlhaus_reference']}")
            related = []
            host = urlparse(indicator).hostname
            if host:
                related.append({'type': 'domain', 'value': host, 'source': 'URLHaus'})
            summary = f"URLHaus: {threat_cat} — status {status}"

        confidence = 90 if malicious else 0
        risk = 'critical' if malicious and threat_cat == 'malware_download' else 'high' if malicious else 'info'

        return self._result(
            indicator, indicator_type,
            configured=True, success=True,
            malicious=malicious,
            confidence=confidence,
            threat_category=threat_cat,
            reputation_score=10 if malicious else 85,
            risk_level=risk,
            summary=summary,
            related_indicators=related,
            observations=observations,
            raw={'query_status': query_status, 'url_count': url_count if indicator_type == 'domain' else 1},
        )
