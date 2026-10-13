"""
Data models and schemas for synthetic cybersecurity event logs.
"""

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


class UserAccessEvent(BaseModel):
    """Schema matching BigQuery Cymbal_Cyber.user_access_events table."""

    event_timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO 8601 UTC timestamp of the access event.",
    )
    event_type: Literal[
        "login_success", "login_failure", "logout", "session_refresh"
    ] = Field(..., description="Type of access event.")
    user_id: str = Field(..., description="Unique enterprise user identifier.")
    source_ip: str = Field(..., description="External or public client IP address.")
    assigned_internal_ip: str | None = Field(
        None, description="Internal IP leased during active VPN/corporate session."
    )
    device_id: str = Field(
        ..., description="Unique client workstation or server device ID."
    )
    device_os: str = Field(..., description="Operating system version.")
    user_agent: str = Field(..., description="User agent string.")
    application_name: str = Field(
        default="Corporate-VPN", description="SSO or VPN application name."
    )


class NetworkEvent(BaseModel):
    """Schema matching BigQuery Cymbal_Cyber.network_events table."""

    event_timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO 8601 UTC timestamp of the network activity.",
    )
    event_type: Literal[
        "dns_query", "connection_established", "file_transfer", "policy_violation"
    ] = Field(..., description="Network event category.")
    user_id: str = Field(
        ..., description="User responsible for or associated with the session."
    )
    source_ip: str = Field(..., description="Internal host IP initiating the request.")
    source_port: int = Field(..., ge=1, le=65535, description="Source port number.")
    destination_ip: str = Field(..., description="Target server IP address.")
    destination_port: int = Field(
        ..., ge=1, le=65535, description="Target port number."
    )
    protocol: Literal["TCP", "UDP", "ICMP"] = Field(
        "TCP", description="Network protocol."
    )
    bytes_transferred: int = Field(..., ge=0, description="Payload byte count.")
    source_process_name: str | None = Field(
        None, description="Binary or process originating the network socket."
    )
    network_domain: str | None = Field(
        None, description="DNS queried domain or HTTP Host header."
    )
    file_name: str | None = Field(
        None, description="Transferred file name if applicable."
    )
    file_type: str | None = Field(None, description="Transferred file extension.")
    command_line: str | None = Field(
        None, description="CLI command or script executed."
    )
    permission_level_requested: str | None = Field(
        None, description="Privilege requested, e.g. root/admin."
    )
    file_hash_sha256: str | None = Field(
        None, description="Cryptographic SHA256 file hash."
    )
