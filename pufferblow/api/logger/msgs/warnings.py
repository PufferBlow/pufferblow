"""Warning-level log message builders.

Short, scannable sentences. Subject first ("IP rate-limited"), then a
`key=value` tail with the relevant counters. Operators reading a
production log should be able to tell at a glance whether they are
looking at one heated client or a coordinated burst.
"""


def IP_REACHED_RATE_LIMIT(ip: str, request_count: int, rate_limit_warnings: int) -> str:
    """Log a rate-limit threshold hit for one client IP."""
    return (
        f"IP rate-limited: ip={ip} "
        f"requests={request_count} warnings={rate_limit_warnings}"
    )


def SQL_INJECTION_PATTERN_DETECTED(
    ip: str, route: str, param: str, pattern: str, warnings_count: int
) -> str:
    """Log a SQL-injection signature hit, naming pattern + parameter + route."""
    return (
        f"SQL injection signature: ip={ip} route={route} "
        f"param={param!r} pattern={pattern!r} warnings={warnings_count}"
    )
