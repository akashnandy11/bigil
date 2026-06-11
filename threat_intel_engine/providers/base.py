"""Base class for threat intelligence providers."""

from abc import ABC, abstractmethod
from typing import List, Optional


class BaseTIProvider(ABC):
    provider_id: str = 'base'
    provider_name: str = 'Base'
    supported_types: List[str] = []

    @abstractmethod
    def lookup(self, indicator: str, indicator_type: str) -> dict:
        pass

    def supports(self, indicator_type: str) -> bool:
        return indicator_type in self.supported_types

    def _result(self, indicator: str, indicator_type: str, *, configured: bool,
                success: bool, **kwargs) -> dict:
        return {
            'provider': self.provider_name,
            'provider_id': self.provider_id,
            'configured': configured,
            'success': success,
            'indicator': indicator,
            'indicator_type': indicator_type,
            'malicious': kwargs.get('malicious'),
            'confidence': kwargs.get('confidence', 0),
            'threat_category': kwargs.get('threat_category', ''),
            'reputation_score': kwargs.get('reputation_score', 50),
            'risk_level': kwargs.get('risk_level', 'unknown'),
            'summary': kwargs.get('summary', ''),
            'related_indicators': kwargs.get('related_indicators', []),
            'observations': kwargs.get('observations', []),
            'error': kwargs.get('error', ''),
            'raw': kwargs.get('raw', {}),
        }

    def _not_configured(self, indicator: str, indicator_type: str, env_var: str) -> dict:
        return self._result(
            indicator, indicator_type,
            configured=False, success=False,
            summary=f'API key not configured. Set {env_var} in environment.',
            error='missing_api_key',
        )

    def _error(self, indicator: str, indicator_type: str, message: str) -> dict:
        return self._result(
            indicator, indicator_type,
            configured=True, success=False,
            summary=message, error=message,
        )
