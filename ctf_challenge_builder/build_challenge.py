#!/usr/bin/env python3
"""
Challenge Builder Script

This script builds challenge images and creates OCI deployment packages.
Usage: build-challenge --ctfd-domain <ctfd-domain>
"""

import argparse
import getpass
import os
import sys

from urllib.parse import urlsplit

import requests

from .challenge_builder import ChallengeBuilder
from .logger import Logger

import importlib.metadata
__version__ = importlib.metadata.version("ctf-challenge-builder")


def check_for_updates():
    """Check if a new version of the tool is available on GitHub"""
    try:
        response = requests.get(
            "https://raw.githubusercontent.com/STulling/challenge-builder/refs/heads/main/pyproject.toml",
            timeout=5
        )
        if response.status_code == 200:
            # Parse version from pyproject.toml content
            for line in response.text.split('\n'):
                if line.strip().startswith('version = '):
                    # Extract version string (format: version = "0.2.12")
                    latest_version = line.split('=')[1].strip().strip('"\'')
                    if latest_version != __version__:
                        Logger.warning(f"A new version ({latest_version}) is available. You are using version {__version__}.")
                        Logger.info(f"Update with: pipx upgrade ctf-challenge-builder")
                        print()
                        exit(0)
                    else:
                        Logger.info(f"You are using the latest version ({__version__})")
                        print()
                    break
    except Exception:
        # Silently fail if we can't check for updates
        pass


def _env_or_default(value: str, default: bool) -> bool:
    lowered = value.lower()
    if lowered in ("1", "true", "yes", "y", "on"):
        return True
    if lowered in ("0", "false", "no", "n", "off"):
        return False
    return default


def _parse_ctfd_url(ctfd_url: str) -> tuple:
    """
    Parse CTFd URL to extract subdomain and base domain.
    
    Args:
        ctfd_url: Full CTFd URL (e.g., https://challenge.ctf.example or challenge.ctf.example)
    
    Returns:
        tuple: (subdomain, ctf_domain, full_challenge_url)
        Example: ("challenge", "ctf.example", "https://challenge.ctf.example")
    """
    # Add scheme if not present
    if not ctfd_url.startswith(("http://", "https://")):
        ctfd_url = f"https://{ctfd_url}"
    
    parsed = urlsplit(ctfd_url)
    netloc = parsed.netloc.strip("/")
    
    if not netloc:
        raise ValueError("Invalid CTFd URL: no domain found")
    
    host_parts = netloc.split(".")
    if len(host_parts) < 2:
        raise ValueError("Expected CTFd URL to contain at least a subdomain and domain (e.g., challenge.ctf.example)")
    
    subdomain = host_parts[0]
    ctf_domain = ".".join(host_parts[1:])
    
    # Reconstruct full URL with proper scheme
    scheme = parsed.scheme or "https"
    full_url = f"{scheme}://{netloc}"
    
    return subdomain, ctf_domain, full_url




def main():
    # Check for updates first
    check_for_updates()
    
    parser = argparse.ArgumentParser(description="Build challenge images and create OCI deployment packages")
    parser.add_argument("--ctfd-domain", required=True, help="CTFd domain (e.g., https://challenge.ctf.example or challenge.ctf.example)")
    parser.add_argument("--challenge-dir", default=".", help="Path to challenge directory (default: current directory)")
    parser.add_argument("--ctfd-username", help="CTFd username (will be prompted if not provided)")
    parser.add_argument("--ctfd-password", help="CTFd password (will be prompted if not provided)")
    parser.add_argument("--oci-username", help="OCI registry username (will be prompted if not provided and needed)")
    parser.add_argument("--oci-password", help="OCI registry password (will be prompted if not provided and needed)")
    parser.add_argument(
        "--ctfd-no-verify",
        action="store_true",
        help="Disable TLS certificate verification when talking to CTFd",
    )

    args = parser.parse_args()
    
    # Parse CTFd URL to extract subdomain and domain
    ctfd_url = args.ctfd_domain or os.getenv("CTFD_DOMAIN")
    if not ctfd_url:
        Logger.error("CTFd domain is required. Provide it via --ctfd-domain or CTFD_DOMAIN environment variable.")
        sys.exit(1)
    
    try:
        subdomain, ctf_domain, full_ctfd_url = _parse_ctfd_url(ctfd_url.strip())
    except ValueError as e:
        Logger.error(str(e))
        sys.exit(1)

    # Prompt for CTFd credentials if not provided
    ctfd_username = args.ctfd_username or os.getenv("CTFD_USERNAME")
    ctfd_password = args.ctfd_password or os.getenv("CTFD_PASSWORD")
    
    if not ctfd_username:
        ctfd_username = input(f"🔐 Enter CTFd username for {full_ctfd_url}: ").strip()
    
    if not ctfd_password:
        ctfd_password = getpass.getpass(f"🔐 Enter CTFd password for {full_ctfd_url}: ")

    # OCI credentials (will be prompted later if needed for docker login)
    oci_username = args.oci_username or os.getenv("OCI_USERNAME")
    oci_password = args.oci_password or os.getenv("OCI_PASSWORD")

    ctfd_verify_ssl = not args.ctfd_no_verify
    env_verify = os.getenv("CTFD_VERIFY_SSL")
    if env_verify is not None:
        ctfd_verify_ssl = _env_or_default(env_verify, ctfd_verify_ssl)

    builder = ChallengeBuilder(
        challenge_dir=args.challenge_dir,
        subdomain=subdomain,
        ctf_domain=ctf_domain,
        ctfd_url=full_ctfd_url,
        ctfd_username=ctfd_username,
        ctfd_password=ctfd_password,
        ctfd_verify_ssl=ctfd_verify_ssl,
        oci_username=oci_username,
        oci_password=oci_password,
    )

    # challenge.yml is mandatory; docker-compose.yml is optional (only needed for dynamic_iac scenarios)
    if not builder.has_challenge:
        Logger.warning("challenge.yml not found in the current directory. Nothing to do.")
        sys.exit(0)

    try:
        builder.build()
    except Exception as e:
        Logger.error(f"Build failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
