def IP_REACHED_RATE_LIMIT(ip: str, request_count: int, rate_limit_warnings: int) -> str:
    """IP REACHED RATE LIMIT."""
    msg = f"The client IP: '{ip}' has exceeded the rate limit with a request count of '{request_count}' and a number of rate limit warnings of '{rate_limit_warnings}'."

    return msg


def SQL_INJECTION_PATTERN_DETECTED(
    ip: str, route: str, param: str, pattern: str, warnings_count: int
) -> str:
    """SQL INJECTION PATTERN DETECTED."""
    msg = (
        f"SQL injection signature '{pattern}' detected from client IP: '{ip}' "
        f"on route '{route}' in parameter '{param}'. Warning count: '{warnings_count}'."
    )
    return msg
