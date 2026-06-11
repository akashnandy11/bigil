"""AbuseIPDB IP reputation provider."""

import requests
from threat_intel_engine.config import get_api_key, is_configured
from threat_intel_engine.providers.base import BaseTIProvider

API_URL = 'https://api.abuseipdb.com/api/v2/check'
TIMEOUT = 12


class AbuseIPDBProvider(BaseTIProvider):
    provider_id = 'abuseipdb'
    provider_name = 'AbuseIPDB'
    supported_types = ['ip']

    def lookup(self, indicator: str, indicator_type: str) -> dict:
        if not is_configured(self.provider_id):
            return self._not_configured(indicator, indicator_type, 'ABUSEIPDB_API_KEY')

        try:
            resp = requests.get(
                API_URL,
                headers={'Key': get_api_key(self.provider_id), 'Accept': 'application/json'},
                params={'ipAddress': indicator, 'maxAgeInDays': 90, 'verbose': ''},
                timeout=TIMEOUT,
            )
            if resp.status_code == 401:
                return self._error(indicator, indicator_type, 'Invalid AbuseIPDB API key')
            if resp.status_code == 429:
                return self._error(indicator, indicator_type, 'AbuseIPDB rate limit exceeded')
            resp.raise_for_status()
            data = resp.json().get('data', {})
        except requests.RequestException as exc:
            return self._error(indicator, indicator_type, f'AbuseIPDB request failed: {exc}')

        score = int(data.get('abuseConfidenceScore', 0))
        reports = int(data.get('totalReports', 0))
        malicious = score >= 25 or reports > 0
        reputation = max(0, 100 - score)

        observations = []
        if data.get('countryCode'):
            observations.append(f"Country: {data['countryCode']}")
        if data.get('isp'):
            observations.append(f"ISP: {data['isp']}")
        if data.get('domain'):
            observations.append(f"Domain: {data['domain']}")
        if reports:
            observations.append(f"Total abuse reports: {reports}")
        if data.get('lastReportedAt'):
            observations.append(f"Last reported: {data['lastReportedAt']}")

        categories = []
        for report in (data.get('reports') or [])[:5]:
            cats = report.get('categories') or []
            categories.extend([str(c) for c in cats])

        threat_cat = 'abuse' if malicious else 'clean'
        if categories:
            threat_cat = f"abuse (categories: {', '.join(sorted(set(categories))[:5])})"

        risk = 'critical' if score >= 75 else 'high' if score >= 50 else 'medium' if score >= 25 else 'low'

        return self._result(
            indicator, indicator_type,
            configured=True, success=True,
            malicious=malicious,
            confidence=score,
            threat_category=threat_cat,
            reputation_score=reputation,
            risk_level=risk if malicious else 'info',
            summary=f"Abuse confidence {score}% — {reports} report(s) in last 90 days",
            observations=observations,
            raw={'abuseConfidenceScore': score, 'totalReports': reports, 'isWhitelisted': data.get('isWhitelisted')},
        )

    def bulk_lookup(self, ips: list) -> list:
        return [self.lookup(ip, 'ip') for ip in ips[:25]]
