from loguru import logger
from datetime import datetime

from fastapi.responses import ORJSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from pufferblow.api_initializer import api_initializer

# Models
from pufferblow.src.models.blocked_ip_model import BlockedIP

# Log messages
from pufferblow.src.logger.msgs import (
    info,
    warnings
)

# TODO: add a mecanisame to detect hand crafted parametars that are associated with a SQL injection attack,
# and block the client ip

class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Basic rate limiting middleware
    """
    RATE_LIMIT_DURATION: datetime = None
    MAX_RATE_LIMIT_REQUESTS: int = None
    MAX_REQUEST_LIMIT_WARNINGS: int = None

    def __init__(self, app):
        super().__init__(app)
        self.request_counts_per_ip = {} # Dictionary to store request counts for each IP

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
        request_count, rate_limit_request_warnings, last_request = self.request_counts_per_ip.get(client_ip, (0, 0,datetime.min))

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
            self.request_counts_per_ip[client_ip] = (request_count, rate_limit_request_warnings + 1, datetime.now())

            return ORJSONResponse(
                status_code=429,
                content={"message": "Rate limit exceeded. Please try again later."}
            )
        else:
            request_count += 1

        # Update the request count, request warning cout and last request timestamp for the IP
        self.request_counts_per_ip[client_ip] = (request_count, rate_limit_request_warnings, datetime.now())
        
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
