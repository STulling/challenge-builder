#!/usr/bin/env python3
"""Utility functions for challenge builder"""

import hashlib
import logging
import sys
from pathlib import Path
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings(
    category=requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# GitHub repository for version checks
GITHUB_REPO = "STulling/challenge-builder"
VERSION_CHECK_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/refs/heads/main/pyproject.toml"


def check_connectivity(registry: str, subdomain: str, ctf_domain: str) -> bool:
    """Check if registry and CTF website are reachable"""
    logger.info("Performing sanity checks...")
    all_ok = True
    
    # Check registry
    try:
        response = requests.get(f"https://{registry}/v2/", timeout=10, verify=False)
        if response.status_code in [200, 401]:
            logger.info(f"Registry {registry} is reachable.")
        else:
            logger.warning(f"Registry {registry} is not reachable. Build may fail.")
            all_ok = False
    except requests.RequestException:
        logger.warning(f"Registry {registry} is not reachable. Build may fail.")
        all_ok = False
    
    # Check CTF website
    try:
        website = f"{subdomain}.{ctf_domain}"
        response = requests.get(f"https://{website}", timeout=10, verify=False)
        if response.status_code == 200:
            logger.info(f"CTF website {website} is up.")
        else:
            logger.warning(f"CTF website {website} is not responding. Build may fail.")
            all_ok = False
    except requests.RequestException:
        logger.warning(f"CTF website {subdomain}.{ctf_domain} is not responding.")
        all_ok = False

    if not all_ok:
        logger.error("One or more sanity checks failed. Please resolve the issues and try again.")
        sys.exit(1)
    
    print()
    return all_ok


def derive_registry_host(subdomain: str, ctf_domain: str, explicit_registry: str = None) -> str:
    """Derive the OCI registry hostname from the CTFd host.

    Historically the registry lived at ``registry.<ctf_domain>`` when the
    public CTFd host looked like ``<event>.<base-domain>``. When the public
    host itself is an apex domain such as ``<event>.com``, the registry instead
    lives at ``registry.<event>.com``.

    Args:
        subdomain: Left-most host label extracted from the CTFd URL.
        ctf_domain: Remaining host labels extracted from the CTFd URL.
        explicit_registry: Optional explicit registry override.

    Returns:
        The registry hostname to use.
    """
    if explicit_registry:
        return explicit_registry.strip()

    normalized_subdomain = subdomain.strip().strip(".")
    normalized_domain = ctf_domain.strip().strip(".")

    if not normalized_subdomain:
        raise ValueError("Subdomain is required to derive the registry host")
    if not normalized_domain:
        raise ValueError("CTF domain is required to derive the registry host")

    # If the remaining domain has no dot, the public CTFd host is likely an
    # apex domain such as ``event.com`` and the registry lives at
    # ``registry.event.com``.
    if "." not in normalized_domain:
        return f"registry.{normalized_subdomain}.{normalized_domain}"

    return f"registry.{normalized_domain}"


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


def check_for_updates():
    """Check if a new version of the tool is available on GitHub"""
    current_version = get_version()
    try:
        response = requests.get(VERSION_CHECK_URL, timeout=5)
        response.raise_for_status()
        
        # Parse version from pyproject.toml content
        latest_version = None
        for line in response.text.splitlines():
            stripped = line.strip()
            if stripped.startswith('version =') or stripped.startswith('version='):
                # Extract version string (handles: version = "0.2.12" or version="0.2.12")
                version_part = stripped.split('=', 1)[1].strip()
                latest_version = version_part.strip('"\'')
                break
        
        if not latest_version:
            return  # Could not parse version from remote file
        
        if latest_version != current_version:
            logger.warning(f"A new version ({latest_version}) is available. You are using version {current_version}.")
            logger.info("Update with: pipx upgrade ctf-challenge-builder")
            print()
        else:
            logger.info(f"You are using the latest version ({current_version})")
            print()
            
    except requests.RequestException:
        # Silently fail if we can't reach GitHub (offline, network issues, etc.)
        pass
    except Exception as e:
        # Log unexpected errors but don't crash
        logger.warning(f"Could not check for updates: {e}")


def parse_ctfd_url(ctfd_url: str) -> tuple:
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


def sanitize_slug(raw: str) -> str:
    """Sanitize a string to be used as a slug"""
    sanitized = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in raw.lower())
    return sanitized.strip("-")


def validate_port_protocols(compose_data: dict) -> None:
    """
    Validate that all ports in docker-compose have proper protocol designations.
    
    Protocol must be specified and must be either:
    - ALL UPPERCASE (HTTP, TCP) - port will be shown in ConnectionInfo
    - all lowercase (http, tcp) - port will NOT be shown in ConnectionInfo
    
    Mixed case (e.g., Http, Tcp) is ambiguous and will raise an error.
    
    Args:
        compose_data: Parsed docker-compose.yml dictionary
        
    Raises:
        ValueError: If any port has missing, invalid, or ambiguous protocol
    """
    services = compose_data.get("services", {})
    errors = []
    
    for service_name, service_config in services.items():
        ports = service_config.get("ports", [])
        for port_spec in ports:
            port_str = str(port_spec)
            
            # Check if protocol is specified
            if "/" not in port_str:
                errors.append(
                    f"Service '{service_name}': Port '{port_str}' is missing protocol. "
                    f"Specify as '{port_str}/TCP' or '{port_str}/HTTP' (uppercase to show in ConnectionInfo, lowercase to hide)"
                )
                continue
            
            # Extract protocol part
            protocol = port_str.split("/")[-1]
            
            # Check for valid protocols
            valid_protocols = ["http", "tcp", "HTTP", "TCP"]
            if protocol not in valid_protocols:
                errors.append(
                    f"Service '{service_name}': Port '{port_str}' has invalid protocol '{protocol}'. "
                    f"Use HTTP/http for web services or TCP/tcp for raw TCP connections"
                )
                continue
            
            # Check for ambiguous case (mixed case)
            if protocol not in ["http", "tcp", "HTTP", "TCP"]:
                # This shouldn't happen due to the check above, but for clarity
                pass
            elif protocol != protocol.lower() and protocol != protocol.upper():
                errors.append(
                    f"Service '{service_name}': Port '{port_str}' has ambiguous protocol case '{protocol}'. "
                    f"Use ALL UPPERCASE (TCP/HTTP) to show in ConnectionInfo, or all lowercase (tcp/http) to hide"
                )
    
    if errors:
        error_msg = "Docker-compose port validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        raise ValueError(error_msg)


def sha256_file(path: Path) -> str:
    """Calculate SHA256 hash of a file"""
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()
