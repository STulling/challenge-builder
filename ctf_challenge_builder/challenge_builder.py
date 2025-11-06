#!/usr/bin/env python3
"""
Challenge Builder - Main orchestrator
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import requests
import yaml

from .build_pipeline import BuildPipeline
from .ctfd_sync import CTFdSync
from .docker_manager import DockerManager
from .logger import Logger
from .utils import sanitize_slug

requests.packages.urllib3.disable_warnings(
    category=requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class ChallengeBuilder:
    """Main orchestrator for challenge building and deployment"""

    def __init__(
        self,
        challenge_dir: str,
        subdomain: str,
        ctf_domain: str,
        ctfd_url: Optional[str] = None,
        ctfd_username: Optional[str] = None,
        ctfd_password: Optional[str] = None,
        ctfd_verify_ssl: bool = True,
        ctfd_timeout: int = 60,
        ctfd_verbose: bool = False,
        oci_username: Optional[str] = None,
        oci_password: Optional[str] = None,
    ):
        self.challenge_dir = Path(challenge_dir).resolve()
        self.subdomain = subdomain
        self.ctf_domain = ctf_domain
        self.registry = f"registry.{ctf_domain}"
        
        # Paths
        self.build_dir = self.challenge_dir / ".build"
        self.dist_dir = self.challenge_dir / "dist"
        self.template_folder = Path(__file__).parent / "pulumi-template"
        self.docker_compose_path = self.challenge_dir / "docker-compose.yml"
        self.challenge_yml_path = self.challenge_dir / "challenge.yml"
        
        # File existence checks
        self.has_compose = self.docker_compose_path.exists()
        self.has_challenge = self.challenge_yml_path.exists()
        
        # Detect sudo requirement
        self.use_sudo = False
        try:
            if os.name != 'nt':
                self.use_sudo = (os.geteuid() != 0)
        except Exception:
            pass
        
        # Initialize managers
        self.docker = DockerManager(self.registry, self.subdomain, self.use_sudo)
        self.ctfd_sync = CTFdSync(
            self.challenge_dir, self.dist_dir, ctfd_url, 
            ctfd_username, ctfd_password, ctfd_verify_ssl, ctfd_timeout, ctfd_verbose
        )
        self.build_pipeline = BuildPipeline(
            self.build_dir, self.subdomain, self.ctf_domain, self.registry
        )
        
        # Store OCI credentials for docker login
        self.docker.oci_username = oci_username
        self.docker.oci_password = oci_password

    def _check_connectivity(self) -> bool:
        """Check if registry and CTF website are reachable"""
        Logger.info("Performing sanity checks...")
        all_ok = True
        
        # Check registry
        try:
            response = requests.get(f"https://{self.registry}/v2/", timeout=10, verify=False)
            if response.status_code in [200, 401]:
                Logger.success(f"Registry {self.registry} is reachable.")
            else:
                Logger.warning(f"Registry {self.registry} is not reachable. Build may fail.")
                all_ok = False
        except requests.RequestException:
            Logger.warning(f"Registry {self.registry} is not reachable. Build may fail.")
            all_ok = False
        
        # Check CTF website
        try:
            website = f"{self.subdomain}.{self.ctf_domain}"
            response = requests.get(f"https://{website}", timeout=10, verify=False)
            if response.status_code == 200:
                Logger.success(f"CTF website {website} is up.")
            else:
                Logger.warning(f"CTF website {website} is not responding. Build may fail.")
                all_ok = False
        except requests.RequestException:
            Logger.warning(f"CTF website {self.subdomain}.{self.ctf_domain} is not responding.")
            all_ok = False

        if not all_ok:
            Logger.error("One or more sanity checks failed. Please resolve the issues and try again.")
            sys.exit(1)
        
        print()
        return all_ok

    def _read_challenge_yaml(self) -> Dict[str, Any]:
        """Read and parse challenge.yml"""
        if not self.has_challenge:
            return {}
        with open(self.challenge_yml_path, 'r') as f:
            return yaml.safe_load(f) or {}

    def _read_docker_compose(self) -> Dict[str, Any]:
        """Read and parse docker-compose.yml"""
        with open(self.docker_compose_path, 'r') as f:
            return yaml.safe_load(f)

    def build(self):
        """Execute the complete build process"""
        try:
            Logger.info(f"Building challenge in {self.challenge_dir}")
            Logger.info(f"Subdomain: {self.subdomain}")
            Logger.info(f"Registry: {self.registry}")
            
            if self.use_sudo:
                self.docker._notify_sudo_once()
            
            print()

            # Read challenge configuration
            challenge_data = {}
            if self.has_challenge:
                try:
                    challenge_data = self._read_challenge_yaml()
                except Exception as exc:
                    Logger.warning(f"Failed to parse challenge.yml: {exc}")

            # Determine package name
            package_name = challenge_data.get("name") or self.subdomain or "challenge"
            scenario_slug = sanitize_slug(
                (challenge_data.get("ctfd") or {}).get("slug") or package_name
            )

            # Handle non-Docker challenges
            if not self.has_compose:
                Logger.info("No docker-compose.yml detected; skipping Docker build steps.")
                self.ctfd_sync.sync(challenge_data, package_name, None)
                Logger.success("Challenge synchronisation completed successfully!")
                return

            # Perform sanity checks
            self._check_connectivity()

            # Build and push Docker images
            compose_data = self._read_docker_compose()
            self.docker.login(self.docker.oci_username, self.docker.oci_password)
            image_substitutions = self.docker.build_and_push_images(compose_data, self.challenge_dir)
            updated_compose_data = DockerManager.substitute_images(compose_data, image_substitutions)
            updated_compose_data = DockerManager.update_ports(updated_compose_data)

            # Verify services exist
            services = list(compose_data.get("services", {}).keys())
            if not services:
                raise ValueError("No services found in docker-compose.yml")

            # Update package name if needed
            if challenge_data.get("name"):
                package_name = challenge_data["name"]
            else:
                package_name = services[0]
            
            scenario_slug = sanitize_slug(
                (challenge_data.get("ctfd") or {}).get("slug") or package_name
            )

            # Build pipeline: prepare, compile, push
            self.build_pipeline.prepare_build_directory(
                self.template_folder, self.challenge_yml_path, updated_compose_data
            )
            self.build_pipeline.build_go_program()
            self.build_pipeline.push_to_oci_registry(scenario_slug)

            # Construct OCI reference
            complete_package = None
            if self.build_pipeline.oci_digest:
                oci_tag = f"{self.registry}/{self.subdomain}/{scenario_slug}-scenario:latest"
                complete_package = f"{oci_tag}@{self.build_pipeline.oci_digest}"
            else:
                Logger.warning("Could not capture OCI digest from push output")

            # Sync with CTFd
            self.ctfd_sync.sync(challenge_data, package_name, complete_package)

            Logger.success("Challenge build completed successfully!")
            if complete_package:
                Logger.final(f"Complete registry package: {complete_package}")

        except Exception as e:
            Logger.error(f"Build failed: {e}")
            raise
        finally:
            self.build_pipeline.cleanup()
