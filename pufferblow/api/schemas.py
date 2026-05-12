"""
Pydantic models for API request/response validation.

This module contains all Pydantic schemas used for validating
API requests and responses across all routes.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator


# ============================================================================
# User Authentication Schemas
# ============================================================================


class SignupRequest(BaseModel):
    """SignupRequest class."""
    username: str
    password: str


class SigninRequest(BaseModel):
    """SigninRequest class."""
    username: str
    password: str


class SigninQuery(BaseModel):
    """SigninQuery class."""
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class AuthTokenQuery(BaseModel):
    """AuthTokenQuery class."""
    auth_token: str = Field(min_length=1)


class RefreshTokenRequest(BaseModel):
    """RefreshTokenRequest class."""
    refresh_token: str = Field(min_length=1)


class DecentralizedChallengeRequest(BaseModel):
    """DecentralizedChallengeRequest class."""
    auth_token: str = Field(min_length=1)
    node_id: str = Field(min_length=1, max_length=255)


class DecentralizedVerifyRequest(BaseModel):
    """DecentralizedVerifyRequest class."""
    challenge_id: str = Field(min_length=1)
    node_public_key: str = Field(min_length=1)
    challenge_signature: str = Field(min_length=1)
    shared_secret: str = Field(min_length=8)


class DecentralizedSessionIntrospectRequest(BaseModel):
    """DecentralizedSessionIntrospectRequest class."""
    session_token: str = Field(min_length=1)


class DecentralizedSessionRevokeRequest(BaseModel):
    """DecentralizedSessionRevokeRequest class."""
    auth_token: str = Field(min_length=1)
    session_id: str = Field(min_length=1)


# ============================================================================
# User Profile Schemas
# ============================================================================


class UserProfileRequest(BaseModel):
    """UserProfileRequest class."""
    auth_token: str = Field(min_length=1)
    user_id: str | None = None  # Optional for current user profile


class UserProfileQuery(BaseModel):
    """UserProfileQuery class."""
    user_id: str = Field(min_length=1)
    auth_token: str = Field(min_length=1)


class EditProfileRequest(BaseModel):
    """EditProfileRequest class."""
    auth_token: str
    new_username: str | None = None
    status: str | None = None
    new_password: str | None = None
    old_password: str | None = None
    about: str | None = None


class EditProfileQuery(BaseModel):
    """EditProfileQuery class."""
    auth_token: str = Field(min_length=1)
    new_username: str | None = None
    status: str | None = None
    new_password: str | None = None
    old_password: str | None = None
    about: str | None = None


class ResetTokenRequest(BaseModel):
    """ResetTokenRequest class."""
    auth_token: str
    password: str


class ListUsersRequest(BaseModel):
    """ListUsersRequest class."""
    auth_token: str


class ListUsersResponse(BaseModel):
    """ListUsersResponse class."""
    status_code: int
    users: list[dict]  # Keep as dict for now since complex nested user structure


# ============================================================================
# Channel Schemas
# ============================================================================


class ListChannelsRequest(BaseModel):
    """ListChannelsRequest class."""
    auth_token: str


class ListChannelsResponse(BaseModel):
    """ListChannelsResponse class."""
    status_code: int
    channels: list = []  # Keep as list for now since complex nested channel structure


class CreateChannelRequest(BaseModel):
    """CreateChannelRequest class."""
    auth_token: str = Field(min_length=1)
    channel_name: str = Field(min_length=1)
    is_private: bool = False
    channel_type: str = Field(default="text", pattern="^(text|voice|mixed)$")


class CreateChannelResponse(BaseModel):
    """CreateChannelResponse class."""
    status_code: int
    message: str
    channel_data: dict  # Keep complex dict structure for channel data


class CreateChannelQuery(BaseModel):
    """CreateChannelQuery class."""
    auth_token: str = Field(min_length=1)
    channel_name: str = Field(min_length=1)
    is_private: bool = False


class ChannelOperationsQuery(BaseModel):
    """ChannelOperationsQuery class."""
    auth_token: str = Field(min_length=1)
    target_user_id: str = Field(min_length=1)


# ============================================================================
# Voice Channel Schemas
# ============================================================================


class VoiceChannelJoinRequest(BaseModel):
    """VoiceChannelJoinRequest class."""
    auth_token: str


class VoiceChannelJoinResponse(BaseModel):
    """VoiceChannelJoinResponse class."""
    status_code: int
    channel_id: str | None = None
    user_id: str | None = None
    participants: int | None = None
    participant_count: int | None = None
    webrtc_config: dict | None = None
    token: str | None = None
    room_name: str | None = None
    proxy: bool | None = None
    error: str | None = None


class VoiceChannelStatusResponse(BaseModel):
    """VoiceChannelStatusResponse class."""
    status_code: int
    channel_id: str
    room_name: str | None = None
    participants: list = []
    participant_count: int = 0
    error: str | None = None


class VoiceSessionCreateRequest(BaseModel):
    """Create or join a voice session request."""

    auth_token: str = Field(min_length=1)
    quality_profile: str = Field(default="balanced", pattern="^(low|balanced|high)$")


class VoiceSessionLeaveRequest(BaseModel):
    """Leave voice session request."""

    auth_token: str = Field(min_length=1)


class VoiceSessionActionRequest(BaseModel):
    """Apply participant action inside voice session."""

    auth_token: str = Field(min_length=1)
    action: str = Field(min_length=1)
    payload: dict = Field(default_factory=dict)


class VoiceJoinTokenConsumeRequest(BaseModel):
    """Internal request payload for one-time join-token consume."""

    join_token: str = Field(min_length=1)


class InternalVoiceEventRequest(BaseModel):
    """Internal signed event payload emitted by SFU."""

    event_type: str = Field(min_length=1)
    payload: dict = Field(default_factory=dict)


class InternalVoiceBootstrapRequest(BaseModel):
    """Signed bootstrap request emitted by media-sfu at startup."""

    service: str = Field(min_length=1)
    nonce: str = Field(min_length=1)


# ============================================================================
# Message Schemas
# ============================================================================


class MessageAttachment(BaseModel):
    """Pydantic model for message attachments"""

    url: str
    filename: str
    type: str
    size: int | None = None


class MessageData(BaseModel):
    """Pydantic model for individual message data"""

    message_id: str
    channel_id: str | None = None
    conversation_id: str | None = None
    sender_id: str
    message: str
    sent_at: str
    attachments: list[MessageAttachment] = []
    username: str
    # User profile fields for reducing frontend requests
    sender_user_id: str | None = None
    sender_avatar_url: str | None = None
    sender_banner_url: str | None = None
    sender_status: str | None = None
    sender_roles: list | None = None
    sender_about: str | None = None
    sender_last_seen: str | None = None
    sender_created_at: str | None = None


class LoadMessagesQuery(BaseModel):
    """LoadMessagesQuery class."""
    auth_token: str = Field(min_length=1)
    page: int = Field(default=1, ge=1)
    messages_per_page: int = Field(default=20, ge=1, le=50)


class LoadMessagesResponse(BaseModel):
    """Pydantic model for load messages API response"""

    status_code: int
    messages: list[MessageData]


class SearchMessagesResponse(BaseModel):
    """Pydantic model for channel message search API response."""

    status_code: int
    messages: list[MessageData]
    query: str
    scanned: int
    truncated_scan: bool


class SendMessageQuery(BaseModel):
    """SendMessageQuery class."""
    auth_token: str = Field(min_length=1)
    message: str = Field(min_length=1)


class SendMessageForm(BaseModel):
    """Message send request model for validation using Pydantic data classes"""

    auth_token: str = Field(
        ..., min_length=1, description="User's authentication token"
    )
    message: str = Field("", description="Message content")
    sent_at: str = Field(
        "", description="ISO timestamp when message was sent by client"
    )
    attachments: list = Field(
        default_factory=list, description="File attachments (optional)"
    )

    @field_validator("auth_token")
    @classmethod
    def validate_auth_token(cls, v):
        """Validate auth token."""
        if not v or not v.strip():
            raise ValueError("auth_token cannot be empty")
        return v.strip()

    @field_validator("sent_at")
    @classmethod
    def validate_sent_at(cls, v):
        """Validate sent at."""
        if v and v.strip():
            # Validate ISO timestamp format if provided
            try:
                from datetime import datetime

                datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError("sent_at must be a valid ISO timestamp")
        return v


class MessageOperationsQuery(BaseModel):
    """MessageOperationsQuery class."""
    auth_token: str = Field(min_length=1)
    message_id: str = Field(min_length=1)


class MessageReportRequest(BaseModel):
    """Submit one or more message reports."""

    auth_token: str = Field(min_length=1)
    message_ids: list[str] = Field(min_length=1)
    category: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)


class UserReportRequest(BaseModel):
    """Submit a report against a user."""

    auth_token: str = Field(min_length=1)
    target_user_id: str = Field(min_length=1)
    category: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)


class UserBanRequest(BaseModel):
    """Ban a user from the current home instance."""

    auth_token: str = Field(min_length=1)
    reason: str | None = Field(default=None, max_length=500)


class UserTimeoutRequest(BaseModel):
    """Apply a temporary communication timeout to a user."""

    auth_token: str = Field(min_length=1)
    duration_minutes: int = Field(ge=1, le=40320)
    reason: str | None = Field(default=None, max_length=500)


class GetReportsRequest(BaseModel):
    """Fetch moderation reports."""

    auth_token: str = Field(min_length=1)
    limit: int = Field(default=100, ge=1, le=500)


class ResolveReportRequest(BaseModel):
    """Resolve a moderation report."""

    auth_token: str = Field(min_length=1)
    action: str = Field(min_length=1, max_length=50)
    reason: str | None = Field(default=None, max_length=500)


class DirectMessageSendRequest(BaseModel):
    """Send direct message to local or remote peer."""

    auth_token: str = Field(min_length=1)
    peer: str = Field(
        min_length=1,
        description="Peer user_id/username for local DM, or remote handle user@domain, or actor URI",
    )
    message: str = Field(min_length=1)
    sent_at: str | None = Field(
        default=None, description="Optional ISO timestamp sent by client"
    )
    attachments: list[str] = Field(
        default_factory=list, description="Optional attachment URLs for federated Note"
    )


class DirectMessageLoadQuery(BaseModel):
    """Load direct message conversation with a peer."""

    auth_token: str = Field(min_length=1)
    peer: str = Field(min_length=1)
    page: int = Field(default=1, ge=1)
    messages_per_page: int = Field(default=20, ge=1, le=50)


class ActivityPubFollowRequest(BaseModel):
    """Federated follow request."""

    auth_token: str = Field(min_length=1)
    remote_handle: str = Field(
        min_length=3, description="Remote account handle like user@example.org"
    )


class ActivityPubInboxRequest(BaseModel):
    """Incoming ActivityPub activity payload wrapper for typed routes."""

    activity: dict


# ============================================================================
# File Upload Schemas
# ============================================================================


class UploadAuthForm(BaseModel):
    """Pydantic model for authenticated file uploads"""

    auth_token: str = Field(
        ..., min_length=1, description="User's authentication token"
    )

    @field_validator("auth_token")
    @classmethod
    def validate_auth_token(cls, v):
        """Validate auth token."""
        if not v or not v.strip():
            raise ValueError("auth_token cannot be empty")
        return v.strip()


# ============================================================================
# Storage Schemas
# ============================================================================


class StorageFilesRequest(BaseModel):
    """StorageFilesRequest class."""
    auth_token: str = Field(min_length=1)
    directory: str = Field(default="uploads", min_length=1)


class StorageDeleteFileRequest(BaseModel):
    """StorageDeleteFileRequest class."""
    auth_token: str = Field(min_length=1)
    file_url: str = Field(min_length=1)


class StorageFileInfoRequest(BaseModel):
    """StorageFileInfoRequest class."""
    auth_token: str = Field(min_length=1)
    file_url: str = Field(min_length=1)


class CleanupOrphanedRequest(BaseModel):
    """CleanupOrphanedRequest class."""
    auth_token: str = Field(min_length=1)
    subdirectory: str = Field(default="", min_length=0)


# ============================================================================
# Admin/System Schemas
# ============================================================================


class BlockIPRequest(BaseModel):
    """BlockIPRequest class."""
    auth_token: str = Field(min_length=1)
    ip: str = Field(min_length=7, max_length=45)  # IPv4/IPv6 range
    reason: str = Field(min_length=1, max_length=500)


class UnblockIPRequest(BaseModel):
    """UnblockIPRequest class."""
    auth_token: str = Field(min_length=1)
    ip: str = Field(min_length=7, max_length=45)


class ServerSettingsRequest(BaseModel):
    """ServerSettingsRequest class."""
    auth_token: str = Field(min_length=1)
    server_name: str | None = None
    server_description: str | None = None
    is_private: bool | None = None
    max_users: int | None = None
    max_message_length: int | None = None
    max_image_size: int | None = Field(default=None, ge=1)
    max_video_size: int | None = Field(default=None, ge=1)
    max_sticker_size: int | None = Field(default=None, ge=1)
    max_gif_size: int | None = Field(default=None, ge=1)
    allowed_image_types: list[str] | None = None
    allowed_video_types: list[str] | None = None
    allowed_file_types: list[str] | None = None
    allowed_sticker_types: list[str] | None = None
    allowed_gif_types: list[str] | None = None


class RunTaskRequest(BaseModel):
    """RunTaskRequest class."""
    auth_token: str = Field(min_length=1)
    task_id: str = Field(min_length=1)


class ToggleTaskRequest(BaseModel):
    """Enable or disable a background task."""

    auth_token: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    enabled: bool


class BackupConfigRequest(BaseModel):
    """Update database backup configuration."""

    auth_token: str = Field(min_length=1)
    enabled: bool
    mode: str = Field(default="file", pattern="^(file|mirror)$")
    path: str | None = Field(default=None)
    mirror_dsn: str | None = Field(default=None)
    schedule_hours: int = Field(default=24, ge=1, le=168)
    max_files: int = Field(default=7, ge=1, le=100)


class ChartRequest(BaseModel):
    """ChartRequest class."""
    auth_token: str = Field(min_length=1)
    period: str | None = Field(
        default=None, description="Time period (daily, weekly, monthly, 24h, 7d)"
    )


class UserStatusChartRequest(BaseModel):
    """UserStatusChartRequest class."""
    auth_token: str = Field(min_length=1)


class RecentActivityRequest(BaseModel):
    """RecentActivityRequest class."""
    auth_token: str
    limit: int = 10


class ServerLogsRequest(BaseModel):
    """ServerLogsRequest class."""
    auth_token: str = Field(min_length=1)
    lines: int = Field(default=50, ge=1, le=1000)
    search: str | None = Field(default=None)
    level: str | None = Field(
        default=None,
        description="Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )


class RuntimeConfigRequest(BaseModel):
    """RuntimeConfigRequest class."""

    auth_token: str = Field(min_length=1)
    include_secrets: bool = False


class RuntimeConfigUpdateRequest(BaseModel):
    """RuntimeConfigUpdateRequest class."""

    auth_token: str = Field(min_length=1)
    settings: dict[str, Any] = Field(default_factory=dict)


class RoleListRequest(BaseModel):
    """List instance roles."""

    auth_token: str = Field(min_length=1)


class PrivilegeListRequest(BaseModel):
    """List available privileges for role composition."""

    auth_token: str = Field(min_length=1)


class RoleCreateRequest(BaseModel):
    """Create a custom instance role."""

    auth_token: str = Field(min_length=1)
    role_name: str = Field(min_length=1, max_length=64)
    privileges_ids: list[str] = Field(default_factory=list)


class RoleUpdateRequest(BaseModel):
    """Update an existing custom instance role."""

    auth_token: str = Field(min_length=1)
    role_name: str = Field(min_length=1, max_length=64)
    privileges_ids: list[str] = Field(default_factory=list)


class UserRolesUpdateRequest(BaseModel):
    """Replace a user's role assignments."""

    auth_token: str = Field(min_length=1)
    roles_ids: list[str] = Field(default_factory=list)


# ============================================================================
# Ping Schemas
# ============================================================================


class PingSendRequest(BaseModel):
    """Send a ping to a local or remote user."""

    auth_token: str = Field(min_length=1)
    target: str = Field(
        min_length=1,
        description=(
            "Recipient identifier: local user_id (UUID), local username, "
            "remote handle (user@domain), or remote actor URI."
        ),
    )
    message: str | None = Field(
        default=None,
        max_length=200,
        description="Optional short message body attached to the ping.",
    )


class PingInstanceRequest(BaseModel):
    """Probe a remote PufferBlow instance for reachability."""

    auth_token: str = Field(min_length=1)
    target_instance_url: str = Field(
        min_length=1,
        description="Base URL of the remote instance (e.g. https://other.example.com).",
    )


class PingAckRequest(BaseModel):
    """Acknowledge a received ping."""

    auth_token: str = Field(min_length=1)


class PingHistoryQuery(BaseModel):
    """Query parameters for paginated ping history."""

    auth_token: str = Field(min_length=1)
    direction: str = Field(
        default="both",
        pattern="^(sent|received|both)$",
        description="Filter pings by direction: sent, received, or both.",
    )
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=50)


class PingData(BaseModel):
    """Serialized representation of a single ping record."""

    ping_id: str
    ping_type: str
    sender_id: str
    target_user_id: str | None = None
    target_actor_uri: str | None = None
    target_instance_url: str | None = None
    status: str
    latency_ms: int | None = None
    instance_http_status: int | None = None
    instance_latency_ms: int | None = None
    activity_uri: str | None = None
    is_sender: bool
    message: str | None = None
    sent_at: str
    acked_at: str | None = None
    expires_at: str
    metadata: dict = Field(default_factory=dict)


class PingHistoryResponse(BaseModel):
    """Paginated ping history response."""

    status_code: int
    direction: str
    page: int
    per_page: int
    pings: list[PingData]


class PingPendingResponse(BaseModel):
    """Response listing pending (unacknowledged) inbound pings."""

    status_code: int
    pending_count: int
    pings: list[PingData]


class PingStatsResponse(BaseModel):
    """Aggregated ping statistics for a user."""

    status_code: int
    user_id: str
    sent_total: int
    received_total: int
    acked_count: int
    timeout_count: int
    avg_latency_ms: float | None = None

