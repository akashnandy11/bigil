"""Threat Intelligence Aggregation Engine — queries, merges, and scores multi-source TI."""

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from threat_intel_engine.detector import detect_indicator_type, normalize_indicator
from threat_intel_engine.providers import ALL_PROVIDERS
from threat_intel_engine.providers.abuseipdb import AbuseIPDBProvider
from threat_intel_engine.config import get_provider_status

PROVIDER_WEIGHTS = {
    'abuseipdb': 1.0,
    'virustotal': 1.2,
    'otx': 0.9,
    'malwarebazaar': 1.1,
    'urlhaus': 1.0,
}

RISK_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0, 'unknown': 0}


class ThreatIntelAggregator:
    """Query multiple TI providers and produce a unified enrichment report."""

    def __init__(self, timeout: int = 25):
        self.timeout = timeout
        self.providers = [cls() for cls in ALL_PROVIDERS]

    def enrich(self, indicator: str, indicator_type: Optional[str] = None) -> dict:
        indicator = (indicator or '').strip()
        if not indicator:
            return self._empty_report(indicator, 'unknown')

        if not indicator_type:
            indicator_type = detect_indicator_type(indicator)
        indicator = normalize_indicator(indicator, indicator_type)

        applicable = [p for p in self.providers if p.supports(indicator_type)]
        provider_results = self._query_providers(applicable, indicator, indicator_type)
        local_matches = []  # filled by caller via enrich_with_local()

        return self._aggregate(indicator, indicator_type, provider_results, local_matches)

    def enrich_with_local(self, indicator: str, local_iocs: list,
                          indicator_type: Optional[str] = None) -> dict:
        report = self.enrich(indicator, indicator_type)
        report['local_matches'] = [
            {
                'id': ioc.id,
                'type': ioc.ioc_type,
                'value': ioc.value,
                'severity': ioc.severity,
                'threat_actor': ioc.threat_actor or '',
                'confidence': ioc.confidence,
                'description': ioc.description or '',
                'source': 'BIGIL Database',
            }
            for ioc in local_iocs
        ]
        if local_iocs:
            max_conf = max(i.confidence for i in local_iocs)
            report['unified_risk_score'] = min(100, max(report['unified_risk_score'], max_conf))
            if report['unified_risk_level'] == 'info':
                report['unified_risk_level'] = local_iocs[0].severity
        return report

    def bulk_enrich_ips(self, ips: List[str]) -> List[dict]:
        ips = [ip.strip() for ip in ips if ip.strip()][:25]
        abuse = AbuseIPDBProvider()
        results = []
        for ip in ips:
            if detect_indicator_type(ip) != 'ip':
                results.append(self._empty_report(ip, 'unknown'))
                continue
            provider_results = [abuse.lookup(ip, 'ip')]
            for p in self.providers:
                if p.provider_id != 'abuseipdb' and p.supports('ip'):
                    try:
                        provider_results.append(p.lookup(ip, 'ip'))
                    except Exception:
                        pass
            results.append(self._aggregate(ip, 'ip', provider_results, []))
        return results

    def _query_providers(self, providers, indicator: str, indicator_type: str) -> list:
        results = []
        if not providers:
            return results

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(p.lookup, indicator, indicator_type): p
                for p in providers
            }
            try:
                for future in as_completed(futures, timeout=self.timeout):
                    p = futures[future]
                    try:
                        results.append(future.result())
                    except Exception as exc:
                        results.append(p._error(indicator, indicator_type, str(exc)))
            except TimeoutError:
                for future, p in futures.items():
                    if future.done():
                        try:
                            results.append(future.result())
                        except Exception as exc:
                            results.append(p._error(indicator, indicator_type, str(exc)))
                    else:
                        future.cancel()
                        results.append(
                            p._error(indicator, indicator_type, f'{p.provider_name} request timed out')
                        )
        return results

    def _aggregate(self, indicator: str, indicator_type: str,
                   provider_results: list, local_matches: list) -> dict:
        successful = [r for r in provider_results if r.get('success')]
        configured = [r for r in provider_results if r.get('configured')]
        malicious_votes = sum(1 for r in successful if r.get('malicious'))

        weighted_score = 0.0
        weight_sum = 0.0
        for r in successful:
            w = PROVIDER_WEIGHTS.get(r.get('provider_id', ''), 1.0)
            conf = float(r.get('confidence') or 0)
            if r.get('malicious'):
                weighted_score += conf * w
            weight_sum += w * 100

        unified_score = round(weighted_score / weight_sum * 100, 1) if weight_sum else 0
        if malicious_votes and unified_score < 25:
            unified_score = max(unified_score, 25.0)

        risk_levels = [r.get('risk_level', 'unknown') for r in successful if r.get('malicious')]
        unified_risk = max(risk_levels, key=lambda x: RISK_ORDER.get(x, 0)) if risk_levels else 'info'

        categories = list({
            r.get('threat_category', '')
            for r in successful
            if r.get('threat_category') and r.get('threat_category') != 'clean'
        })

        related = self._dedupe_related(provider_results)
        observations = []
        for r in successful:
            for obs in r.get('observations', []):
                observations.append({'source': r['provider'], 'text': obs})
        observations = observations[:25]

        return {
            'indicator': indicator,
            'indicator_type': indicator_type,
            'unified_risk_score': unified_score,
            'unified_risk_level': unified_risk,
            'malicious_consensus': malicious_votes,
            'providers_queried': len(provider_results),
            'providers_successful': len(successful),
            'providers_configured': len(configured),
            'threat_categories': categories,
            'provider_results': provider_results,
            'related_indicators': related,
            'observations': observations,
            'local_matches': local_matches,
            'provider_status': get_provider_status(),
            'summary': self._build_summary(indicator, successful, malicious_votes, unified_score),
        }

    def _dedupe_related(self, provider_results: list) -> list:
        seen = set()
        related = []
        for r in provider_results:
            for item in r.get('related_indicators', []):
                key = (item.get('type', ''), item.get('value', '').lower())
                if key in seen or not key[1]:
                    continue
                seen.add(key)
                related.append(item)
        return related[:30]

    def _build_summary(self, indicator: str, successful: list,
                       malicious_votes: int, score: float) -> str:
        if not successful:
            return f'No threat intelligence providers returned data for {indicator}. Configure API keys in environment.'
        if malicious_votes == 0:
            return f'{len(successful)} source(s) queried — no malicious classification consensus for {indicator}.'
        names = [r['provider'] for r in successful if r.get('malicious')]
        return (
            f'{malicious_votes}/{len(successful)} sources classify {indicator} as malicious '
            f'({", ".join(names)}). Unified risk score: {score}/100.'
        )

    def _empty_report(self, indicator: str, indicator_type: str) -> dict:
        return {
            'indicator': indicator,
            'indicator_type': indicator_type,
            'unified_risk_score': 0,
            'unified_risk_level': 'unknown',
            'malicious_consensus': 0,
            'providers_queried': 0,
            'providers_successful': 0,
            'providers_configured': 0,
            'threat_categories': [],
            'provider_results': [],
            'related_indicators': [],
            'observations': [],
            'local_matches': [],
            'provider_status': get_provider_status(),
            'summary': 'Invalid or empty indicator.',
        }

    @staticmethod
    def to_json(report: dict) -> str:
        safe = {k: v for k, v in report.items() if k != 'provider_status'}
        return json.dumps(safe, default=str)
