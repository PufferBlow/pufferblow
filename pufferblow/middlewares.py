import re
import uuid
import asyncio

from loguru import logger
from datetime import (
    datetime,
    timedelta
)

from fastapi.responses import ORJSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from pydantic import BaseModel, Field, ValidationError

from pufferblow.api_initializer import api_initializer

# Tables
from pufferblow.api.database.tables.blocked_ips import BlockedIPS

# Log messages
from pufferblow.api.logger.msgs import (
    info,
    warnings
)

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
    Basic rate limiting middleware with thread-safe operations
    """

    def __init__(self, app):
        super().__init__(app)
        self.request_count_per_ip = {}
        self.rate_limit_lock = asyncio.Lock()

    async def dispatch(self, request, call_next):
        # Skip rate limiting for test environments
        if request.client is None:
            response = await call_next(request)
            return response

        # Get the client's IP address
        client_ip = request.client.host

        # Check if IP is already blocked
        if api_initializer.database_handler.check_is_ip_blocked(ip=client_ip):
            return ORJSONResponse(
                status_code=403,
                content={
                    "message": "Malicious activities detected, you have been blocked. To get unblocked you can try reaching out to the server owner to manually unblock you."
                }
            )

        # Get current server settings
        server_settings = api_initializer.database_handler.get_server_settings()
        if server_settings is None:
            # Fallback to config if settings not found
            rate_limit_duration = timedelta(minutes=api_initializer.config.RATE_LIMIT_DURATION)
            max_rate_limit_requests = api_initializer.config.MAX_RATE_LIMIT_REQUESTS
            max_rate_limit_warnings = api_initializer.config.MAX_RATE_LIMIT_WARNINGS
        else:
            rate_limit_duration = timedelta(minutes=server_settings.rate_limit_duration)
            max_rate_limit_requests = server_settings.max_rate_limit_requests
            max_rate_limit_warnings = server_settings.max_rate_limit_warnings

        # Thread-safe rate limiting logic
        async with self.rate_limit_lock:
            # Get current IP stats
            request_count, warnings_count, last_request = self.request_count_per_ip.get(client_ip, (0, 0, datetime.min))

            # Calculate elapsed time since last request
            elapsed_time = datetime.now() - last_request

            # Reset counts if time window has expired
            if elapsed_time > rate_limit_duration:
                request_count = 0  # Will be incremented to 1
                warnings_count = 0  # Reset warnings

            # Check if request limit exceeded
            if request_count >= max_rate_limit_requests:
                # Increment warnings and log the violation
                warnings_count += 1
                logger.warning(
                    warnings.IP_REACHED_RATE_LIMIT(
                        ip=client_ip,
                        request_count=request_count,
                        rate_limit_warnings=warnings_count
                    )
                )
                self.request_count_per_ip[client_ip] = (request_count, warnings_count, datetime.now())

                return ORJSONResponse(
                    status_code=429,
                    content={"message": "Rate limit exceeded. Please try again later."}
                )
            else:
                # Increment request count
                request_count += 1

            # Update IP stats
            self.request_count_per_ip[client_ip] = (request_count, warnings_count, datetime.now())

            # Check if warnings exceed threshold (block permanently)
            if warnings_count > max_rate_limit_warnings:
                logger.info(
                    info.CLIENT_IP_BLOCKED(
                        client_ip=client_ip,
                        requests_count=request_count,
                        rate_limit_warnings=warnings_count
                    )
                )

                blocked_ip = BlockedIPS(
                    ip=client_ip,
                    block_reason="The IP has exceeded the rate limit warnings threshold, indicating potential DDOS attack.",
                    ip_id=str(uuid.uuid4())
                )

                api_initializer.database_handler.save_blocked_ip_to_blocked_ips(blocked_ip=blocked_ip)

                return ORJSONResponse(
                    status_code=403,
                    content={
                        "message": "Malicious activities detected, you have been blocked. To get unblocked you can try reaching out to the server owner to manually unblock you."
                    }
                )

        # Process the request
        response = await call_next(request)
        return response

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

        url_match = self.match_request_url(
            url=request_url,
            method=request.method
        )

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
                    status_code=422,
                    content={"message": f"Validation error: {e}"}
                )

        for param in query_params:
            exception = None

            match param:
                case "auth_token":
                    exception = api_initializer.security_checks_handler.check_auth_token_format(
                        auth_token=query_params.get("auth_token")
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
                    exception = api_initializer.security_checks_handler.check_auth_token_format(auth_token=query_params.get("auth_token"))

                    if exception is not None:
                        return exception

                    exception = api_initializer.security_checks_handler.check_user_password(
                        auth_token=query_params.get("auth_token"),
                        password=query_params.get("password")
                    )
                case "old_password":
                    exception = api_initializer.security_checks_handler.check_user_password(
                        auth_token=query_params.get("auth_token"),
                        password=query_params.get("old_password")
                    )
                case "status":
                    exception = api_initializer.security_checks_handler.check_user_status_value(
                        status=query_params.get("status")
                    )
                case "channel_name":
                    exception = api_initializer.security_checks_handler.check_channel_name(
                        channel_name=query_params.get("channel_name")
                    )
                case "channel_id":
                    exception = api_initializer.security_checks_handler.check_channel_id(
                        channel_id=query_params.get("channel_id")
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
