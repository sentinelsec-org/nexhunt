"""
Scope enforcement utility.
Patterns support wildcards: *.example.com, example.com, api.example.com
Out-of-scope takes priority over in-scope.
"""
from fnmatch import fnmatch
from urllib.parse import urlparse


def extract_host(url_or_host: str) -> str:
    """Extract bare hostname from URL or host:port string."""
    s = url_or_host.strip()
    if "://" in s:
        try:
            return urlparse(s).hostname or s
        except Exception:
            pass
    return s.split(":")[0].split("/")[0]


def matches_pattern(host: str, pattern: str) -> bool:
    """Check if host matches a scope pattern (supports * wildcard)."""
    pattern = pattern.strip().lstrip("*.")
    return host == pattern or host.endswith("." + pattern) or fnmatch(host, pattern)


def is_in_scope(
    url: str,
    in_scope: list[str],
    out_of_scope: list[str],
) -> bool:
    """
    Returns True if url is in scope.
    - out_of_scope patterns take priority
    - empty in_scope = everything is in scope
    """
    host = extract_host(url)
    if not host:
        return True

    for pattern in out_of_scope:
        if pattern.strip() and matches_pattern(host, pattern):
            return False

    if not in_scope:
        return True

    for pattern in in_scope:
        if pattern.strip() and matches_pattern(host, pattern):
            return True

    return False


def filter_urls(
    urls: list[str],
    in_scope: list[str],
    out_of_scope: list[str],
) -> tuple[list[str], list[str]]:
    """Split urls into (in_scope_list, out_of_scope_list)."""
    ins, outs = [], []
    for u in urls:
        (ins if is_in_scope(u, in_scope, out_of_scope) else outs).append(u)
    return ins, outs
