#!/usr/bin/env python3
"""
Challenge Builder - Main orchestrator
"""

import os
import sys
import logging
from pathlib import Path
from typing import Any, Dict, Optional
import traceback

import yaml

from .build_pipeline import BuildPipeline
from .ctfd_sync import CTFdSync
from .docker_manager import DockerManager
from .utils import (
    sanitize_slug,
    check_connectivity,
    derive_registry_host,
    validate_port_protocols,
)

logger = logging.getLogger(__name__)


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
        oci_registry: Optional[str] = None,
    ):
        self.challenge_dir = Path(challenge_dir).resolve()
        self.subdomain = subdomain
        self.ctf_domain = ctf_domain
        self.registry = derive_registry_host(subdomain, ctf_domain, oci_registry)
        
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
            self.build_dir, self.subdomain, self.ctf_domain, self.registry, 
            self.docker
        )
        
        # Store OCI credentials for docker login
        self.docker.oci_username = oci_username
        self.docker.oci_password = oci_password

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
            logger.info(f"Building challenge in {self.challenge_dir}")
            logger.info(f"Subdomain: {self.subdomain}")
            logger.info(f"Registry: {self.registry}")
            
            if self.use_sudo:
                self.docker._notify_sudo_once()
            
            print()

            # Read challenge configuration
            challenge_data = {}
            if self.has_challenge:
                try:
                    challenge_data = self._read_challenge_yaml()
                except Exception as exc:
                    logger.error(f"Failed to parse challenge.yml: {exc}")
                    raise

            # Validate required fields
            required_fields = ["name", "category", "type", "description", "attribution", "flags"]
            missing = [f for f in required_fields if not challenge_data.get(f)]
            if missing:
                raise ValueError(f"Missing required fields in challenge.yml: {', '.join(missing)}")

            scenario_slug = sanitize_slug(
                challenge_data.get("slug") or challenge_data["name"]
            )
            challenge_type = challenge_data.get("type")

            if challenge_type != "dynamic_iac":
                logger.info(
                    "Challenge type '%s' does not use Docker/OCI packaging; syncing to CTFd only.",
                    challenge_type,
                )
                self.ctfd_sync.sync(challenge_data, None, scenario_slug)
                logger.info("Challenge synchronisation completed successfully!")
                return

            # Handle non-Docker challenges
            if not self.has_compose:
                logger.info("No docker-compose.yml detected; skipping Docker build steps.")
                self.ctfd_sync.sync(challenge_data, None, scenario_slug)
                logger.info("Challenge synchronisation completed successfully!")
                return

            # Perform sanity checks
            check_connectivity(self.registry, self.subdomain, self.ctf_domain)

            # Build and push Docker images
            compose_data = self._read_docker_compose()
            
            # Validate port protocol designations
            validate_port_protocols(compose_data)
            
            self.docker.login(self.docker.oci_username, self.docker.oci_password)
            image_substitutions = self.docker.build_and_push_images(compose_data, self.challenge_dir, scenario_slug)
            updated_compose_data = DockerManager.substitute_images(compose_data, image_substitutions)
            updated_compose_data = DockerManager.update_ports(updated_compose_data)

            # Verify services exist
            services = list(compose_data.get("services", {}).keys())
            if not services:
                raise ValueError("No services found in docker-compose.yml")

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
                logger.warning("Could not capture OCI digest from push output")

            # Sync with CTFd
            self.ctfd_sync.sync(challenge_data, complete_package, scenario_slug)

            logger.info("Challenge build completed successfully!")
            if complete_package:
                logger.info(f"Complete registry package: {complete_package}")

        except Exception as e:
            logger.error(f"Build failed: {e}")
            traceback.print_exc()
            raise
        finally:
            self.build_pipeline.cleanup()
