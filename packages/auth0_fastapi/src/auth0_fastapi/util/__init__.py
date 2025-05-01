from urllib.parse import urljoin, urlparse
from typing import Optional

from fastapi.responses import RedirectResponse


def ensure_no_leading_slash(url: str) -> str:
    """
    Removes any leading slash from the given URL string.
    """
    return url.lstrip('/')


def ensure_trailing_slash(base: str) -> str:
    """
    Ensures that the base URL ends with a slash.
    """
    base_str = str(base)
    return base_str if base_str.endswith('/') else base_str + '/'


def create_route_url(url: str, base: str) -> str:
    """
    Ensures route URLs are created correctly by removing the leading slash from the
    provided URL and ensuring the base URL has a trailing slash. Then uses urljoin
    to combine them.

    Args:
        url: The URL (or path) to use.
        base: The base URL to use.

    Returns:
        A complete URL string combining the base and url.
    """
    base_fixed = ensure_trailing_slash(base)
    url_fixed = ensure_no_leading_slash(url)
    return urljoin(base_fixed, url_fixed)


def to_safe_redirect(dangerous_redirect: str, safe_base_url: str) -> Optional[str]:
    """
    Ensures that the redirect URL is safe to use by verifying that its origin matches
    the origin of the safe_base_url.

    Args:
        dangerous_redirect: The redirect URL to check.
        safe_base_url: The base URL to check against.

    Returns:
        A safe redirect URL string if the origins match, or None otherwise.
    """
    try:
        # Ensure safe_base_url is a string.
        safe_base_url_str = str(safe_base_url)
        route_url = create_route_url(dangerous_redirect, safe_base_url_str)
    except Exception:
        return None

    # Build origins from string values
    safe_origin = urlparse(safe_base_url_str).scheme + \
        "://" + urlparse(safe_base_url_str).netloc
    route_origin = urlparse(route_url).scheme + "://" + \
        urlparse(route_url).netloc

    if route_origin == safe_origin:
        return route_url
    return None
