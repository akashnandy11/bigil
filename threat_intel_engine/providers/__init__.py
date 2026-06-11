from threat_intel_engine.providers.abuseipdb import AbuseIPDBProvider
from threat_intel_engine.providers.otx import OTXProvider
from threat_intel_engine.providers.malwarebazaar import MalwareBazaarProvider
from threat_intel_engine.providers.urlhaus import URLHausProvider
from threat_intel_engine.providers.virustotal import VirusTotalProvider

ALL_PROVIDERS = [
    AbuseIPDBProvider,
    OTXProvider,
    MalwareBazaarProvider,
    URLHausProvider,
    VirusTotalProvider,
]
