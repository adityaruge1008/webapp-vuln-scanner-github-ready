"""Analyzer wrapper which uses the scanner to perform tests and return structured results."""

from scanner import Scanner
from urllib.parse import urlparse


def _ensure_scheme(u: str) -> str:
    if not u:
        return u
    p = urlparse(u)
    if not p.scheme:
        return 'http://' + u
    return u


def run_scan(url: str):
    """Run a scan and return list of issues found.
    Returns a dict: { 'url': url, 'issues': [...] }
    """
    url = _ensure_scheme(url)
    s = Scanner(url, max_pages=25)
    reports = s.scan()
    return {'url': url, 'issues': reports}
