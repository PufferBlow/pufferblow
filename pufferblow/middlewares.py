import re

from loguru import logger
from datetime import (
    datetime,
    timedelta
)

from fastapi.responses import ORJSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from pufferblow.api_initializer import api_initializer

# Models
from pufferblow.api.models.blocked_ip_model import BlockedIP

# Log messages
from pufferblow.api.logger.msgs import (
    info,
    warnings
)

# TODO: add a mecanisame to detect hand crafted parameters that are associated with a SQL injection attack,
# and block the client ip

class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Basic rate limiting middleware
    """
    RATE_LIMIT_DURATION: datetime
    MAX_RATE_LIMIT_REQUESTS: int
    MAX_REQUEST_LIMIT_WARNINGS: int
    REQUEST_COUNT_PER_IP: dict = dict()

    def __init__(self, app):
        super().__init__(app)

        self.RATE_LIMIT_DURATION = timedelta(minutes=api_initializer.config.RATE_LIMIT_DURATION)
        self.MAX_RATE_LIMIT_REQUESTS = api_initializer.config.MAX_RATE_LIMIT_REQUESTS
        self.MAX_REQUEST_LIMIT_WARNINGS = api_initializer.config.MAX_RATE_LIMIT_WARNINGS
    
    async def dispatch(self, request, call_next):
        # This statements will get triggered when running
        # tests, beside that, it will just continue.
        if request.client is None:
            response = await call_next(request)

            return response

        # Get the client's IP address
        client_ip = request.client.host
        
        # Check if IP is already blocked
        if api_initializer.database_handler.check_is_ip_blocked(
            ip=client_ip
        ):
            return ORJSONResponse(
                status_code=403,
                content={
                    "message": "Malicious activities detected, you have been blocked. To get unblocked you can try reaching out to the serve owner to manually unblock you."
                }
            )
        
        # Check if IP is already present in request_counts
        request_count, rate_limit_request_warnings, last_request = self.REQUEST_COUNT_PER_IP.get(client_ip, (0, 0,datetime.min))

        # Calculate the time elapsed since the last request
        elapsed_time = datetime.now() - last_request

        if elapsed_time > self.RATE_LIMIT_DURATION:
            # If the elapsed time is greater than the rate limit duration, reset the count
            request_count = 1
        elif request_count >= self.MAX_RATE_LIMIT_REQUESTS:
            # If the request count exceeds the rate limit, return a JSON response with an error message
            logger.warning(
                warnings.IP_REACHED_RATE_LIMIT(
                    ip=client_ip,
                    request_count=request_count,
                    rate_limit_warnings=rate_limit_request_warnings
                )
            )
            self.REQUEST_COUNT_PER_IP[client_ip] = (request_count, rate_limit_request_warnings + 1, datetime.now())

            return ORJSONResponse(
                status_code=429,
                content={"message": "Rate limit exceeded. Please try again later."}
            )
        else:
            request_count += 1

        # Update the request count, request warning cout and last request timestamp for the IP
        self.REQUEST_COUNT_PER_IP[client_ip] = (request_count, rate_limit_request_warnings, datetime.now())
        
        # Block the IP address in case it exceeds the MAX_REQUEST_LIMIT_WARNINGS
        if rate_limit_request_warnings > self.MAX_REQUEST_LIMIT_WARNINGS:
            logger.info(
                info.CLIENT_IP_BLOCKED(
                    client_ip=client_ip,
                    requests_count=request_count,
                    rate_limit_warnings=rate_limit_request_warnings
                )
            )

            blocked_ip = BlockedIP()

            blocked_ip.ip               =   client_ip
            blocked_ip.block_reason     =   "The IP has exceeded the rate limit request warnings for over 100 times, which indicates a probability of a DDOS attack."
            blocked_ip.ip_id            =   blocked_ip._generate_message_id(data=blocked_ip.block_reason)

            api_initializer.database_handler.save_blocked_ip_to_blocked_ips(
                blocked_ip=blocked_ip
            )
            
            return ORJSONResponse(
                status_code=403,
                content={
                    "message": "Malicious activities detected, you have been blocked. To get unblocked you can try reaching out to the serve owner to manually unblock you."
                }
            )
        
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

    def __init__(self, app) -> None:
        super().__init__(app)

    async def dispatch(self, request, call_next):
        # This statements will get triggered when running
        # tests, beside that, it will just continue.
        if request.client is None:
            return await call_next(request)
        
        request_url = request.url.path
        
        url_match = self.match_request_url(
            url=request_url,
            method=request.method
        )

        if not url_match:
            return await call_next(request)
        
        query_params = request.query_params

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
