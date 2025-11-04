#!/usr/bin/env python3
"""Utility functions for challenge builder"""

import hashlib
from pathlib import Path


def sanitize_slug(raw: str) -> str:
    """Sanitize a string to be used as a slug"""
    sanitized = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in raw.lower())
    return sanitized.strip("-") or "challenge"


def sha256_file(path: Path) -> str:
    """Calculate SHA256 hash of a file"""
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()
