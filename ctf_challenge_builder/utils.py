#!/usr/bin/env python3
"""Utility functions for challenge builder"""

import hashlib
from pathlib import Path


def get_version() -> str:
    """Read version from pyproject.toml"""
    try:
        # Get the path to pyproject.toml (relative to this file)
        project_root = Path(__file__).parent.parent
        pyproject_path = project_root / "pyproject.toml"
        
        if pyproject_path.exists():
            with open(pyproject_path, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith('version =') or stripped.startswith('version='):
                        version_part = stripped.split('=', 1)[1].strip()
                        return version_part.strip('"\'')
    except Exception:
        pass
    
    # Fallback version if we can't read from pyproject.toml
    return "unknown"


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
