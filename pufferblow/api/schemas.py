"""
Pydantic models for API request/response validation.

This module contains all Pydantic schemas used for validating
API requests and responses across all routes.
"""

from pydantic import BaseModel, Field, field_validator


# ============================================================================
# User Authentication Schemas
# ============================================================================


class SignupRequest(BaseModel):
    username: str
    password: str


class SigninRequest(BaseModel):
    username: str
    password: str


class SigninQuery(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class AuthTokenQuery(BaseModel):
    auth_token: str = Field(min_length=1)


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class DecentralizedChallengeRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    node_id: str = Field(min_length=1, max_length=255)


class DecentralizedVerifyRequest(BaseModel):
    challenge_id: str = Field(min_length=1)
    node_public_key: str = Field(min_length=1)
    challenge_signature: str = Field(min_length=1)
    shared_secret: str = Field(min_length=8)


class DecentralizedSessionIntrospectRequest(BaseModel):
    session_token: str = Field(min_length=1)


class DecentralizedSessionRevokeRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    session_id: str = Field(min_length=1)


# ============================================================================
# User Profile Schemas
# ============================================================================


class UserProfileRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    user_id: str | None = None  # Optional for current user profile


class UserProfileQuery(BaseModel):
    user_id: str = Field(min_length=1)
    auth_token: str = Field(min_length=1)


class EditProfileRequest(BaseModel):
    auth_token: str
    new_username: str | None = None
    status: str | None = None
    new_password: str | None = None
    old_password: str | None = None
    about: str | None = None


class EditProfileQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    new_username: str | None = None
    status: str | None = None
    new_password: str | None = None
    old_password: str | None = None
    about: str | None = None


class ResetTokenRequest(BaseModel):
    auth_token: str
    password: str


class ListUsersRequest(BaseModel):
    auth_token: str


class ListUsersResponse(BaseModel):
    status_code: int
    users: list[dict]  # Keep as dict for now since complex nested user structure


# ============================================================================
# Channel Schemas
# ============================================================================


class ListChannelsRequest(BaseModel):
    auth_token: str


class ListChannelsResponse(BaseModel):
    status_code: int
    channels: list = []  # Keep as list for now since complex nested channel structure


class CreateChannelRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    channel_name: str = Field(min_length=1)
    is_private: bool = False
    channel_type: str = Field(default="text", pattern="^(text|voice|mixed)$")


class CreateChannelResponse(BaseModel):
    status_code: int
    message: str
    channel_data: dict  # Keep complex dict structure for channel data


class CreateChannelQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    channel_name: str = Field(min_length=1)
    is_private: bool = False


class ChannelOperationsQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    target_user_id: str = Field(min_length=1)


# ============================================================================
# Voice Channel Schemas
# ============================================================================


class VoiceChannelJoinRequest(BaseModel):
    auth_token: str


class VoiceChannelJoinResponse(BaseModel):
    status_code: int
    token: str | None = None
    room_name: str | None = None
    livekit_url: str | None = None
    proxy: bool | None = None
    error: str | None = None


class VoiceChannelStatusResponse(BaseModel):
    status_code: int
    channel_id: str
    room_name: str | None = None
    participants: list = []
    participant_count: int = 0
    error: str | None = None


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
    auth_token: str = Field(min_length=1)
    page: int = Field(default=1, ge=1)
    messages_per_page: int = Field(default=20, ge=1, le=50)


class LoadMessagesResponse(BaseModel):
    """Pydantic model for load messages API response"""

    status_code: int
    messages: list[MessageData]


class SendMessageQuery(BaseModel):
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
        if not v or not v.strip():
            raise ValueError("auth_token cannot be empty")
        return v.strip()

    @field_validator("sent_at")
    @classmethod
    def validate_sent_at(cls, v):
        if v and v.strip():
            # Validate ISO timestamp format if provided
            try:
                from datetime import datetime

                datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError("sent_at must be a valid ISO timestamp")
        return v


class MessageOperationsQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    message_id: str = Field(min_length=1)


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
        if not v or not v.strip():
            raise ValueError("auth_token cannot be empty")
        return v.strip()


# ============================================================================
# Storage/CDN Schemas
# ============================================================================


class CDNFilesRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    directory: str = Field(default="uploads", min_length=1)


class CDNDeleteFileRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    file_url: str = Field(min_length=1)


class CDNFileInfoRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    file_url: str = Field(min_length=1)


class CleanupOrphanedRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    subdirectory: str = Field(default="", min_length=0)


# ============================================================================
# Admin/System Schemas
# ============================================================================


class BlockIPRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    ip: str = Field(min_length=7, max_length=45)  # IPv4/IPv6 range
    reason: str = Field(min_length=1, max_length=500)


class UnblockIPRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    ip: str = Field(min_length=7, max_length=45)


class ServerSettingsRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    server_name: str | None = None
    server_description: str | None = None
    is_private: bool | None = None
    max_users: int | None = None
    max_message_length: int | None = None


class RunTaskRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    task_id: str = Field(min_length=1)


class ChartRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    period: str | None = Field(
        default=None, description="Time period (daily, weekly, monthly, 24h, 7d)"
    )


class UserStatusChartRequest(BaseModel):
    auth_token: str = Field(min_length=1)


class RecentActivityRequest(BaseModel):
    auth_token: str
    limit: int = 10


class ServerLogsRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    lines: int = Field(default=50, ge=1, le=1000)
    search: str | None = Field(default=None)
    level: str | None = Field(
        default=None,
        description="Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
