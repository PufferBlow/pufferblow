import asyncio
import re
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta

from fastapi.responses import ORJSONResponse
from loguru import logger
from pydantic import BaseModel, Field, ValidationError
from starlette.middleware.base import BaseHTTPMiddleware

# Tables
from pufferblow.api.database.tables.blocked_ips import BlockedIPS

# Log messages
from pufferblow.api.logger.msgs import info, warnings
from pufferblow.core.bootstrap import api_initializer


# Pydantic models for query parameters validation in middleware
class AuthTokenQuery(BaseModel):
    """AuthTokenQuery class."""
    auth_token: str = Field(min_length=1)


class SigninQuery(BaseModel):
    """SigninQuery class."""
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class UserProfileQuery(BaseModel):
    """UserProfileQuery class."""
    user_id: str = Field(min_length=1)
    auth_token: str = Field(min_length=1)


class EditProfileQuery(BaseModel):
    """EditProfileQuery class."""
    auth_token: str = Field(min_length=1)
    new_username: str | None = None
    status: str | None = None
    new_password: str | None = None
    old_password: str | None = None
    about: str | None = None


class ChannelOperationsQuery(BaseModel):
    """ChannelOperationsQuery class."""
    auth_token: str = Field(min_length=1)
    target_user_id: str = Field(min_length=1)


class CreateChannelQuery(BaseModel):
    """CreateChannelQuery class."""
    auth_token: str = Field(min_length=1)
    channel_name: str = Field(min_length=1)
    is_private: bool = False


class LoadMessagesQuery(BaseModel):
    """LoadMessagesQuery class."""
    auth_token: str = Field(min_length=1)
    page: int = Field(default=1, ge=1)
    messages_per_page: int = Field(default=20, ge=1, le=50)


class SendMessageQuery(BaseModel):
    """SendMessageQuery class."""
    auth_token: str = Field(min_length=1)
    message: str = Field(min_length=1)


class MessageOperationsQuery(BaseModel):
    """MessageOperationsQuery class."""
    auth_token: str = Field(min_length=1)
    message_id: str = Field(min_length=1)


# TODO: add a mecanisame to detect hand crafted parameters that are associated with a SQL injection attack,
# and block the client ip


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiting middleware with endpoint tiers and cooldowns.
    """

    def __init__(self, app):
        """Initialize the instance."""
        super().__init__(app)
        self.request_timestamps_per_ip = defaultdict(deque)
        self.cooldowns_per_ip = {}
        self.warning_counts_per_ip = defaultdict(int)
        self.rate_limit_lock = asyncio.Lock()

    async def dispatch(self, request, call_next):
        """Dispatch."""
        if request.client is None:
            return await call_next(request)

        client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if not client_ip:
            client_ip = request.client.host

        if api_initializer.database_handler.check_is_ip_blocked(ip=client_ip):
            return ORJSONResponse(
                status_code=403,
                content={
                    "message": "Malicious activities detected, you have been blocked. To get unblocked you can try reaching out to the server owner to manually unblock you."
                },
            )

        server_settings = api_initializer.database_handler.get_server_settings()
        if server_settings is None:
            base_window_minutes = api_initializer.config.RATE_LIMIT_DURATION
            base_max_requests = api_initializer.config.MAX_RATE_LIMIT_REQUESTS
            max_rate_limit_warnings = api_initializer.config.MAX_RATE_LIMIT_WARNINGS
        else:
            base_window_minutes = server_settings.rate_limit_duration
            base_max_requests = server_settings.max_rate_limit_requests
            max_rate_limit_warnings = server_settings.max_rate_limit_warnings

        endpoint_bucket = self._get_bucket(request.url.path)
        bucket_multiplier = {
            "auth": 0.2,
            "uploads": 0.15,
            "messages": 0.5,
            "default": 1.0,
        }.get(endpoint_bucket, 1.0)

        window = timedelta(minutes=max(base_window_minutes, 1))
        max_requests = max(5, int(base_max_requests * bucket_multiplier))

        async with self.rate_limit_lock:
            now = datetime.now()
            warnings_count = self.warning_counts_per_ip[client_ip]

            cooldown_until = self.cooldowns_per_ip.get(client_ip)
            if cooldown_until and now < cooldown_until:
                retry_after_seconds = int((cooldown_until - now).total_seconds())
                return ORJSONResponse(
                    status_code=429,
                    headers={"Retry-After": str(max(retry_after_seconds, 1))},
                    content={
                        "message": "Rate limit exceeded. Cooldown active.",
                        "retry_after_seconds": retry_after_seconds,
                    },
                )

            timestamps = self.request_timestamps_per_ip[client_ip]
            window_start = now - window
            while timestamps and timestamps[0] < window_start:
                timestamps.popleft()

            if len(timestamps) >= max_requests:
                self.warning_counts_per_ip[client_ip] += 1
                warnings_count = self.warning_counts_per_ip[client_ip]
                logger.warning(
                    warnings.IP_REACHED_RATE_LIMIT(
                        ip=client_ip,
                        request_count=len(timestamps),
                        rate_limit_warnings=warnings_count,
                    )
                )

                if warnings_count > max_rate_limit_warnings:
                    logger.info(
                        info.CLIENT_IP_BLOCKED(
                            client_ip=client_ip,
                            requests_count=len(timestamps),
                            rate_limit_warnings=warnings_count,
                        )
                    )

                    blocked_ip = BlockedIPS(
                        ip=client_ip,
                        block_reason="The IP has exceeded the rate limit warnings threshold, indicating potential DDOS attack.",
                        ip_id=str(uuid.uuid4()),
                    )

                    api_initializer.database_handler.save_blocked_ip_to_blocked_ips(
                        blocked_ip=blocked_ip
                    )

                    return ORJSONResponse(
                        status_code=403,
                        content={
                            "message": "Malicious activities detected, you have been blocked. To get unblocked you can try reaching out to the server owner to manually unblock you."
                        },
                    )

                if warnings_count >= 2 and warnings_count <= max_rate_limit_warnings:
                    cooldown_seconds = min(300, 30 * warnings_count)
                    self.cooldowns_per_ip[client_ip] = now + timedelta(
                        seconds=cooldown_seconds
                    )
                    return ORJSONResponse(
                        status_code=429,
                        headers={"Retry-After": str(cooldown_seconds)},
                        content={
                            "message": "Rate limit exceeded. Please try again later.",
                            "retry_after_seconds": cooldown_seconds,
                        },
                    )

                return ORJSONResponse(
                    status_code=429,
                    content={"message": "Rate limit exceeded. Please try again later."},
                )

            timestamps.append(now)

        return await call_next(request)

    @staticmethod
    def _get_bucket(path: str) -> str:
        """Get bucket."""
        if "/signin" in path or "/signup" in path or "/auth/" in path:
            return "auth"
        if "/upload" in path or "/storage/" in path:
            return "uploads"
        if "/send_message" in path or "/load_messages" in path or "/ws" in path:
            return "messages"
        return "default"


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Centralized security middleware for privileged API routes.

    The middleware applies request-level checks in a deterministic order:
    1. Skip rules (test clients, CORS preflight, non-privileged routes)
    2. Route-specific query validation with Pydantic (when configured)
    3. Parameter-level security checks delegated to `security_checks_handler`
    """

    PRIVILEGED_API_ROUTES: tuple[str, ...] = (
        "/api/v1/users/signup",
        "/api/v1/users/profile",
        "/api/v1/users/profile/reset-auth-token",
        "/api/v1/users/list",
        "/api/v1/channel/list/",
        "/api/v1/channel/create/",
        "/api/v1/channel/*/delete",
        "/api/v1/channel/*/addUser",
        "/api/v1/channel/*/removeUser",
        "/api/v1/channel/*/load_messages",
        "/api/v1/channel/*/send_message",
        "/api/v1/channel/*/mark_message_as_read",
        "/api/v1/channel/*/delete_message",
    )

    ROUTE_TO_MODEL: dict[str, type[BaseModel]] = {
        "/api/v1/users/signin": SigninQuery,
        "/api/v1/users/list": AuthTokenQuery,
        "/api/v1/channels/list/": AuthTokenQuery,
        "/api/v1/channels/create/": CreateChannelQuery,
    }

    FORM_DATA_ROUTE_PATTERNS: tuple[str, ...] = (
        "/api/v1/channels/*/send_message",
        "/api/v1/users/profile/avatar",
        "/api/v1/users/profile/banner",
        "/api/v1/storage/upload",
        "/api/v1/system/upload-avatar",
        "/api/v1/system/upload-banner",
    )

    def __init__(self, app) -> None:
        """Initialize the instance."""
        super().__init__(app)
        self._privileged_route_regexes = self._compile_route_patterns(
            self.PRIVILEGED_API_ROUTES
        )
        self._form_data_route_regexes = self._compile_route_patterns(
            self.FORM_DATA_ROUTE_PATTERNS
        )
        self._param_check_handlers = {
            "auth_token": self._check_auth_token,
            "user_id": self._check_user_id,
            "username": self._check_username,
            "password": self._check_password,
            "old_password": self._check_old_password,
            "status": self._check_status,
            "channel_name": self._check_channel_name,
            "channel_id": self._check_channel_id,
            "to_add_user_id": self._check_to_add_user_id,
            "to_remove_user_id": self._check_to_remove_user_id,
        }

    @staticmethod
    def _compile_route_patterns(route_patterns: list[str] | tuple[str, ...]) -> list:
        """Compile wildcard route patterns (`*`) to anchored regex patterns."""
        compiled_patterns = []
        for route_pattern in route_patterns:
            escaped_route = re.escape(route_pattern).replace(r"\*", ".*")
            compiled_patterns.append(re.compile(rf"^{escaped_route}$"))
        return compiled_patterns

    def is_form_data_route(self, url: str) -> bool:
        """Check whether route uses form data and should skip query validation."""
        return any(pattern.match(url) for pattern in self._form_data_route_regexes)

    def _is_privileged_route(self, url: str) -> bool:
        """Check whether route requires middleware security checks."""
        return any(pattern.match(url) for pattern in self._privileged_route_regexes)

    def _validate_query_params(self, request_url: str, query_params):
        """Validate query parameters with route-bound Pydantic models."""
        model = self.ROUTE_TO_MODEL.get(request_url)
        if model is None:
            return None
        try:
            model(**dict(query_params))
        except ValidationError as e:
            return ORJSONResponse(
                status_code=422, content={"message": f"Validation error: {e}"}
            )
        return None

    def _run_param_checks(self, request_url: str, query_params):
        """Run configured security checks for each known query parameter."""
        for param_name in query_params:
            handler = self._param_check_handlers.get(param_name)
            if handler is None:
                continue

            exception = handler(request_url, query_params)
            if exception is not None:
                return exception
        return None

    async def dispatch(self, request, call_next):
        """Dispatch."""
        if request.client is None:
            return await call_next(request)

        if request.method == "OPTIONS":
            return await call_next(request)

        request_url = request.url.path

        if not self._is_privileged_route(request_url):
            return await call_next(request)

        if self.is_form_data_route(request_url):
            return await call_next(request)

        query_params = request.query_params

        validation_error = self._validate_query_params(request_url, query_params)
        if validation_error is not None:
            return validation_error

        exception = self._run_param_checks(request_url, query_params)
        if exception is not None:
            return exception

        return await call_next(request)

    def _check_auth_token(self, request_url: str, query_params):
        """Validate auth token format, then validate user existence by token."""
        auth_token = query_params.get("auth_token")
        exception = api_initializer.security_checks_handler.check_auth_token_format(
            auth_token=auth_token
        )
        if exception is not None:
            return exception
        return api_initializer.security_checks_handler.check_user(auth_token=auth_token)

    def _check_user_id(self, request_url: str, query_params):
        """Validate `user_id` existence."""
        return api_initializer.security_checks_handler.check_user(
            user_id=query_params.get("user_id")
        )

    def _check_username(self, request_url: str, query_params):
        """Validate username existence."""
        return api_initializer.security_checks_handler.check_username_existence(
            username=query_params.get("username")
        )

    def _check_password(self, request_url: str, query_params):
        """Validate password against auth token, excluding signup endpoint."""
        if "/signup" in request_url:
            return None
        auth_token = query_params.get("auth_token")
        exception = api_initializer.security_checks_handler.check_auth_token_format(
            auth_token=auth_token
        )
        if exception is not None:
            return exception
        return api_initializer.security_checks_handler.check_user_password(
            auth_token=auth_token,
            password=query_params.get("password"),
        )

    def _check_old_password(self, request_url: str, query_params):
        """Validate `old_password` against token-bound user."""
        return api_initializer.security_checks_handler.check_user_password(
            auth_token=query_params.get("auth_token"),
            password=query_params.get("old_password"),
        )

    def _check_status(self, request_url: str, query_params):
        """Validate status against allowed enum values."""
        return api_initializer.security_checks_handler.check_user_status_value(
            status=query_params.get("status")
        )

    def _check_channel_name(self, request_url: str, query_params):
        """Validate channel name format/constraints."""
        return api_initializer.security_checks_handler.check_channel_name(
            channel_name=query_params.get("channel_name")
        )

    def _check_channel_id(self, request_url: str, query_params):
        """Validate channel existence by id."""
        return api_initializer.security_checks_handler.check_channel_id(
            channel_id=query_params.get("channel_id")
        )

    def _check_to_add_user_id(self, request_url: str, query_params):
        """Validate target user for add-user channel operation."""
        return api_initializer.security_checks_handler.check_user(
            user_id=query_params.get("to_add_user_id")
        )

    def _check_to_remove_user_id(self, request_url: str, query_params):
        """Validate target user for remove-user channel operation."""
        return api_initializer.security_checks_handler.check_user(
            user_id=query_params.get("to_remove_user_id")
        )
