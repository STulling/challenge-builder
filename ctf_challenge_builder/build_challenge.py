#!/usr/bin/env python3
"""
Challenge Builder Script

This script builds challenge images and creates OCI deployment packages.
Usage: build-challenge --ctf-domain <ctf-domain>
"""

import argparse
import os
import sys

from urllib.parse import urlsplit

from .challenge_builder import ChallengeBuilder
from .logger import Logger


def _env_or_default(value: str, default: bool) -> bool:
    lowered = value.lower()
    if lowered in ("1", "true", "yes", "y", "on"):
        return True
    if lowered in ("0", "false", "no", "n", "off"):
        return False
    return default


def _strip_scheme(domain: str) -> str:
    parsed = urlsplit(domain if domain.startswith(("http://", "https://")) else f"https://{domain}")
    return parsed.netloc


def _normalize_url(value: str) -> str:
    if not value:
        return value
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value.rstrip("/")


def main():
    parser = argparse.ArgumentParser(description="Build challenge images and create OCI deployment packages")
    parser.add_argument("--ctf-domain", required=True, help="CTF domain for the challenge (scheme optional)")
    parser.add_argument("--challenge-dir", default=".", help="Path to challenge directory (default: current directory)")
    parser.add_argument("--ctfd-url", help="Base URL of the CTFd instance for automatic updates (defaults to https://<ctf-domain>)")
    parser.add_argument("--ctfd-token", help="CTFd API token (takes precedence over username/password)")
    parser.add_argument("--ctfd-username", help="CTFd username used to request an API token")
    parser.add_argument("--ctfd-password", help="CTFd password used to request an API token")
    parser.add_argument(
        "--ctfd-no-verify",
        action="store_true",
        help="Disable TLS certificate verification when talking to CTFd",
    )

    args = parser.parse_args()
    raw_domain = args.ctf_domain.strip()
    netloc = _strip_scheme(raw_domain).strip("/")
    if not netloc:
        Logger.error("Invalid --ctf-domain value.")
        sys.exit(1)
    host_parts = netloc.split(".")
    if len(host_parts) < 2:
        Logger.error("Expected --ctf-domain to contain at least a subdomain and domain (e.g., challenge.ctf.example)")
        sys.exit(1)
    subdomain = host_parts[0]
    ctf_domain = ".".join(host_parts[1:])

    ctfd_url = args.ctfd_url or os.getenv("CTFD_URL")
    if ctfd_url:
        ctfd_url = _normalize_url(ctfd_url.strip())
    else:
        ctfd_url = _normalize_url(raw_domain)

    ctfd_token = args.ctfd_token or os.getenv("CTFD_TOKEN")
    ctfd_username = args.ctfd_username or os.getenv("CTFD_USERNAME")
    ctfd_password = args.ctfd_password or os.getenv("CTFD_PASSWORD")

    ctfd_verify_ssl = not args.ctfd_no_verify
    env_verify = os.getenv("CTFD_VERIFY_SSL")
    if env_verify is not None:
        ctfd_verify_ssl = _env_or_default(env_verify, ctfd_verify_ssl)

    builder = ChallengeBuilder(
        challenge_dir=args.challenge_dir,
        subdomain=subdomain,
        ctf_domain=ctf_domain,
        ctfd_url=ctfd_url,
        ctfd_token=ctfd_token,
        ctfd_username=ctfd_username,
        ctfd_password=ctfd_password,
        ctfd_verify_ssl=ctfd_verify_ssl,
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
