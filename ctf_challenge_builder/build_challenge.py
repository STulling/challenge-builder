#!/usr/bin/env python3
"""
Challenge Builder Script

This script builds challenge images and creates OCI deployment packages.
Usage: build-challenge --ctf-domain <ctf-domain>
"""

import argparse
import sys

from .challenge_builder import ChallengeBuilder
from .logger import Logger


def main():
    parser = argparse.ArgumentParser(description="Build challenge images and create OCI deployment packages")
    parser.add_argument("--ctf-domain", required=True, help="CTF domain for the challenge")
    parser.add_argument("--challenge-dir", default=".", help="Path to challenge directory (default: current directory)")

    args = parser.parse_args()
    subdomain = args.ctf_domain.split('.')[0]
    ctf_domain = ".".join(args.ctf_domain.split('.')[1:])
    
    builder = ChallengeBuilder(
        challenge_dir=args.challenge_dir,
        subdomain=subdomain,
        ctf_domain=ctf_domain
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
