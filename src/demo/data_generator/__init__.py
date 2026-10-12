"""
Synthetic Data Generator Package.
"""
from .log_generator import SyntheticLogEngine
from .models import NetworkEvent, UserAccessEvent
from .sinks import BaseSink, BigQuerySink, GoogleCloudStorageSink, LocalSink, PubSubSink
from .threat_scenarios import (
    generate_false_positive_threat_scenario,
    generate_malicious_threat_scenario,
)

__all__ = [
    "BaseSink",
    "BigQuerySink",
    "GoogleCloudStorageSink",
    "LocalSink",
    "NetworkEvent",
    "PubSubSink",
    "SyntheticLogEngine",
    "UserAccessEvent",
    "generate_false_positive_threat_scenario",
    "generate_malicious_threat_scenario"
]

