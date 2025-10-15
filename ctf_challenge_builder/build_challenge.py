#!/usr/bin/env python3
"""
Challenge Builder Script

This script builds challenge images and creates OCI deployment packages.
Usage: build-challenge --ctf-domain <ctf-domain>
"""

import argparse
import os
import sys

from .challenge_builder import ChallengeBuilder
from .logger import Logger


def _env_or_default(value: str, default: bool) -> bool:
    lowered = value.lower()
    if lowered in ("1", "true", "yes", "y", "on"):
        return True
    if lowered in ("0", "false", "no", "n", "off"):
        return False
    return default


def main():
    parser = argparse.ArgumentParser(description="Build challenge images and create OCI deployment packages")
    parser.add_argument("--ctf-domain", required=True, help="CTF domain for the challenge")
    parser.add_argument("--challenge-dir", default=".", help="Path to challenge directory (default: current directory)")
    parser.add_argument("--ctfd-url", help="Base URL of the CTFd instance for automatic updates")
    parser.add_argument("--ctfd-token", help="CTFd API token (takes precedence over username/password)")
    parser.add_argument("--ctfd-username", help="CTFd username used to request an API token")
    parser.add_argument("--ctfd-password", help="CTFd password used to request an API token")
    parser.add_argument(
        "--ctfd-no-verify",
        action="store_true",
        help="Disable TLS certificate verification when talking to CTFd",
    )

    args = parser.parse_args()
    subdomain = args.ctf_domain.split('.')[0]
    ctf_domain = ".".join(args.ctf_domain.split('.')[1:])

    ctfd_url = args.ctfd_url or os.getenv("CTFD_URL")
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

    # Both docker-compose.yml and challenge.yml must be present to build a challenge
    if not (builder.has_compose and builder.has_challenge):
        Logger.warning("docker-compose.yml and/or challenge.yml not found in the current directory. Nothing to do.")
        sys.exit(0)

    try:
        builder.build()
    except Exception as e:
        Logger.error(f"Build failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
