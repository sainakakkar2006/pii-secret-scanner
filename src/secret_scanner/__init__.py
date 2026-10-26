"""pii-secret-scanner: find committed secrets and personal data."""

from .scanner import Finding, scan_path

__all__ = ["Finding", "scan_path"]
