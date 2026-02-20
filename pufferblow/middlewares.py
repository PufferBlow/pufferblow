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
from pufferblow.api_initializer import api_initializer


# Pydantic models for query parameters validation in middleware
class AuthTokenQuery(BaseModel):
    auth_token: str = Field(min_length=1)


class SigninQuery(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class UserProfileQuery(BaseModel):
    user_id: str = Field(min_length=1)
    auth_token: str = Field(min_length=1)


class EditProfileQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    new_username: str | None = None
    status: str | None = None
    new_password: str | None = None
    old_password: str | None = None
    about: str | None = None


class ChannelOperationsQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    target_user_id: str = Field(min_length=1)


class CreateChannelQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    channel_name: str = Field(min_length=1)
    is_private: bool = False


class LoadMessagesQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    page: int = Field(default=1, ge=1)
    messages_per_page: int = Field(default=20, ge=1, le=50)


class SendMessageQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    message: str = Field(min_length=1)


class MessageOperationsQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    message_id: str = Field(min_length=1)


# TODO: add a mecanisame to detect hand crafted parameters that are associated with a SQL injection attack,
# and block the client ip


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiting middleware with endpoint tiers and cooldowns.
    """

    def __init__(self, app):
        super().__init__(app)
        self.request_timestamps_per_ip = defaultdict(deque)
        self.cooldowns_per_ip = {}
        self.warning_counts_per_ip = defaultdict(int)
        self.rate_limit_lock = asyncio.Lock()

    async def dispatch(self, request, call_next):
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
        if "/signin" in path or "/signup" in path or "/auth/" in path:
            return "auth"
        if "/upload" in path or "/storage/" in path or "/cdn/" in path:
            return "uploads"
        if "/send_message" in path or "/load_messages" in path or "/ws" in path:
            return "messages"
        return "default"


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    This is a security middleware that handles checks related to auth_token, user_id, user's password ...etc
    before, these checks were done at each api route level, which creates alot of code repitition and it's hard
    to maintain, but now all the requests that are going to the api routes that can be accessed only by users, admins,
    or server owner will be protected from outsiders and non server users.
    """

    PREVELEIDGED_API_ROUTES: list[str] = [
        "/api/v1/users/signup",
        "/api/v1/users/profile",
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
    ]

    route_to_model = {
        "/api/v1/users/signin": SigninQuery,
        "/api/v1/users/list": AuthTokenQuery,
        "/api/v1/channels/list/": AuthTokenQuery,
        "/api/v1/channels/create/": CreateChannelQuery,
    }

    # Routes that should skip query parameter validation (they use form data)
    form_data_routes = [
        "/api/v1/channels/*/send_message",
        "/api/v1/users/profile/avatar",
        "/api/v1/users/profile/banner",
        "/api/v1/cdn/upload",
        "/api/v1/system/upload-avatar",
        "/api/v1/system/upload-banner",
    ]

    def __init__(self, app) -> None:
        super().__init__(app)

    def is_form_data_route(self, url: str) -> bool:
        """
        Check if a route uses form data instead of query parameters.
        """
        for route_pattern in self.form_data_routes:
            route_regex = route_pattern.replace("*", ".*")
            if re.match(route_regex, url):
                return True
        return False

    async def dispatch(self, request, call_next):
        # This statements will get triggered when running
        # tests, beside that, it will just continue.
        if request.client is None:
            return await call_next(request)

        # Skip OPTIONS requests entirely - let CORS middleware handle preflight requests
        if request.method == "OPTIONS":
            return await call_next(request)

        request_url = request.url.path

        url_match = self.match_request_url(url=request_url, method=request.method)

        if not url_match:
            return await call_next(request)

        # Skip query parameter validation for form data routes (they handle validation at endpoint level)
        if self.is_form_data_route(request_url):
            return await call_next(request)

        query_params = request.query_params

        # Validate query params with pydantic if a model is defined for the route
        if request_url in self.route_to_model:
            model = self.route_to_model[request_url]
            try:
                model(**dict(query_params))
            except ValidationError as e:
                return ORJSONResponse(
                    status_code=422, content={"message": f"Validation error: {e}"}
                )

        for param in query_params:
            exception = None

            match param:
                case "auth_token":
                    exception = (
                        api_initializer.security_checks_handler.check_auth_token_format(
                            auth_token=query_params.get("auth_token")
                        )
                    )
                    # Return the exception right away to break the loop
                    # and to not continue to the next check
                    if exception is not None:
                        return exception

                    exception = api_initializer.security_checks_handler.check_user(
                        auth_token=query_params.get("auth_token")
                    )
                case "user_id":
                    exception = api_initializer.security_checks_handler.check_user(
                        user_id=query_params.get("user_id")
                    )
                case "username":
                    exception = api_initializer.security_checks_handler.check_username_existence(
                        username=query_params.get("username")
                    )
                case "password":
                    if "/signup" in request_url:
                        continue
                    exception = (
                        api_initializer.security_checks_handler.check_auth_token_format(
                            auth_token=query_params.get("auth_token")
                        )
                    )

                    if exception is not None:
                        return exception

                    exception = (
                        api_initializer.security_checks_handler.check_user_password(
                            auth_token=query_params.get("auth_token"),
                            password=query_params.get("password"),
                        )
                    )
                case "old_password":
                    exception = (
                        api_initializer.security_checks_handler.check_user_password(
                            auth_token=query_params.get("auth_token"),
                            password=query_params.get("old_password"),
                        )
                    )
                case "status":
                    exception = (
                        api_initializer.security_checks_handler.check_user_status_value(
                            status=query_params.get("status")
                        )
                    )
                case "channel_name":
                    exception = (
                        api_initializer.security_checks_handler.check_channel_name(
                            channel_name=query_params.get("channel_name")
                        )
                    )
                case "channel_id":
                    exception = (
                        api_initializer.security_checks_handler.check_channel_id(
                            channel_id=query_params.get("channel_id")
                        )
                    )
                case "to_add_user_id":
                    exception = api_initializer.security_checks_handler.check_user(
                        user_id=query_params.get("to_add_user_id")
                    )
                case "to_remove_user_id":
                    exception = api_initializer.security_checks_handler.check_user(
                        user_id=query_params.get("to_remove_user_id")
                    )

            if exception is not None:
                return exception

        return await call_next(request)

    def match_request_url(self, url: str, method: str) -> bool:
        """
        Tries to retrive the index of the matched url from
        self.PREVELEIDGED_API_ROUTES

        Args:
            url (str): The url to check if we have a match for.

        Returns:
            bool: True if the url matches, otherwise False.
        """
        for route in self.PREVELEIDGED_API_ROUTES:
            route_pattern = route.replace("*", ".*")

            pattern = re.compile(route_pattern)

            if pattern.match(url) or url == route:
                return True

        return False
