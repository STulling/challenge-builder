#!/usr/bin/env python3
"""
Challenge Builder Script

This script builds challenge images and creates OCI deployment packages.
Usage: build-challenge --ctfd-domain <ctfd-domain>
"""

import argparse
import getpass
import logging
import os
import sys
from pathlib import Path

from .challenge_builder import ChallengeBuilder
from .logger import setup_logging
from .utils import get_version, check_for_updates, parse_ctfd_url

__version__ = get_version()


def _env_or_default(value: str, default: bool) -> bool:
    lowered = value.lower()
    if lowered in ("1", "true", "yes", "y", "on"):
        return True
    if lowered in ("0", "false", "no", "n", "off"):
        return False
    return default


def main():
    # Configure logging
    setup_logging()
    logger = logging.getLogger(__name__)

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
        "--oci-registry",
        help=(
            "OCI registry hostname override. Defaults to registry.<ctf-domain> for "
            "nested event domains and registry.<ctfd-host> for apex event domains."
        ),
    )
    parser.add_argument(
        "--ctfd-no-verify",
        action="store_true",
        help="Disable TLS certificate verification when talking to CTFd",
    )
    parser.add_argument(
        "--ctfd-timeout",
        type=int,
        default=None,
        help="Timeout in seconds for CTFd operations (default: 60; can also be set via CTFD_TIMEOUT)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging for CTFd requests and responses",
    )
    parser.add_argument(
        "--skip-bundle-flag-check",
        action="store_true",
        help="Allow challenge flags to appear in bundled files",
    )

    args = parser.parse_args()
    
    # Parse CTFd URL to extract subdomain and domain
    ctfd_url = args.ctfd_domain or os.getenv("CTFD_DOMAIN")
    if not ctfd_url:
        logger.error("CTFd domain is required. Provide it via --ctfd-domain or CTFD_DOMAIN environment variable.")
        sys.exit(1)
    
    try:
        subdomain, ctf_domain, full_ctfd_url = parse_ctfd_url(ctfd_url.strip())
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    # Prompt for CTFd credentials if not provided
    ctfd_username = args.ctfd_username or os.getenv("CTFD_USERNAME")
    ctfd_password = args.ctfd_password or os.getenv("CTFD_PASSWORD")
    
    if not ctfd_username:
        ctfd_username = input(f"Enter CTFd username for {full_ctfd_url}: ").strip()
    
    if not ctfd_password:
        ctfd_password = getpass.getpass(f"Enter CTFd password for {full_ctfd_url}: ")

    # OCI credentials (will be prompted later if needed for docker login)
    oci_username = args.oci_username or os.getenv("OCI_USERNAME")
    oci_password = args.oci_password or os.getenv("OCI_PASSWORD")
    oci_registry = args.oci_registry or os.getenv("OCI_REGISTRY")

    ctfd_verify_ssl = not args.ctfd_no_verify
    env_verify = os.getenv("CTFD_VERIFY_SSL")
    if env_verify is not None:
        ctfd_verify_ssl = _env_or_default(env_verify, ctfd_verify_ssl)

    # Timeout configuration (CLI flag overrides env; default 60s)
    ctfd_timeout = args.ctfd_timeout
    if ctfd_timeout is None:
        env_timeout = os.getenv("CTFD_TIMEOUT")
        try:
            ctfd_timeout = int(env_timeout) if env_timeout else 60
        except ValueError:
            logger.warning("Invalid CTFD_TIMEOUT value; falling back to 60 seconds")
            ctfd_timeout = 60

    builder = ChallengeBuilder(
        challenge_dir=args.challenge_dir,
        subdomain=subdomain,
        ctf_domain=ctf_domain,
        ctfd_url=full_ctfd_url,
        ctfd_username=ctfd_username,
        ctfd_password=ctfd_password,
        ctfd_verify_ssl=ctfd_verify_ssl,
        ctfd_timeout=ctfd_timeout,
        ctfd_verbose=args.verbose,
        skip_bundle_flag_check=args.skip_bundle_flag_check,
        oci_username=oci_username,
        oci_password=oci_password,
        oci_registry=oci_registry,
    )

    # challenge.yml is mandatory; docker-compose.yml is optional (only needed for dynamic_iac scenarios)
    if not builder.has_challenge:
        logger.warning("challenge.yml not found in the current directory. Nothing to do.")
        sys.exit(0)

    try:
        builder.build()
    except Exception as e:
        logger.error(f"Build failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
