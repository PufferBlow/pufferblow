
def IP_REACHED_RATE_LIMIT(ip: str, request_count: int, rate_limit_warnings: int) -> str:
    msg = f"The client IP: '{ip}' has exceeded the rate limit with a request count of '{request_count}' and a number of rate limit warnings of '{rate_limit_warnings}'."

    return msg
