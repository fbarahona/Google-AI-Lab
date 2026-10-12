"""
Pytest global configuration and fixtures.
Disables OpenTelemetry cloud export during automated testing when ADC may be unauthenticated.
"""
import os

os.environ["OTEL_SDK_DISABLED"] = "true"
os.environ["OTEL_TO_CLOUD"] = "false"

