#!/usr/bin/env python3
"""Build pipeline for Go programs and OCI registry"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import yaml

from .logger import Logger


class BuildPipeline:
    """Handles Go compilation and OCI registry operations"""

    def __init__(self, build_dir: Path, subdomain: str, ctf_domain: str, registry: str):
        self.build_dir = build_dir
        self.subdomain = subdomain
        self.ctf_domain = ctf_domain
        self.registry = registry
        self.oci_digest: Optional[str] = None

    def prepare_build_directory(self, template_folder: Path, challenge_yml_path: Path, 
                                updated_compose_data: dict):
        """Create and populate build directory"""
        if self.build_dir.exists():
            shutil.rmtree(self.build_dir)
        self.build_dir.mkdir()
        Logger.info(f"Created build directory: {self.build_dir}")

        # Copy docker-compose
        with open(self.build_dir / "docker-compose.yaml", 'w') as f:
            yaml.dump(updated_compose_data, f, default_flow_style=False)
        
        # Copy challenge.yml
        shutil.copy2(challenge_yml_path, self.build_dir / "challenge.yaml")
        
        # Copy Pulumi template files
        for filename in ['Pulumi.yaml', 'main.go', 'go.mod', 'go.sum']:
            src = template_folder / filename
            if src.exists():
                shutil.copy2(src, self.build_dir / filename)
            else:
                Logger.warning(f"Template file not found: {src}")

    def build_go_program(self):
        """Compile the Go program"""
        Logger.build("Building Go program...")
        
        # Go mod tidy
        subprocess.run(['go', 'mod', 'tidy'], cwd=self.build_dir, check=True, 
                      capture_output=True, text=True)
        
        # Build binary
        os.environ['CGO_ENABLED'] = '0'
        build_cmd = [
            'go', 'build', '-o', 'main',
            '-ldflags', f"-s -w -X main.Subdomain={self.subdomain} -X main.CtfDomain={self.ctf_domain}",
            "main.go"
        ]
        subprocess.run(build_cmd, cwd=self.build_dir, check=True, capture_output=True, text=True)
        
        if not (self.build_dir / "main").exists():
            raise RuntimeError("Go build failed: main binary not found")
        
        Logger.success("Go program built successfully")

    def push_to_oci_registry(self, package_name: str):
        """Push build artifacts to OCI registry"""
        Logger.push("Pushing to OCI registry...")

        oci_tag = f"{self.registry}/{self.subdomain}/{package_name}-scenario:latest"
        # using docker
        push_cmd = [
            'docker', 'run', '-it', '--rm',
            '-v', f"{self.build_dir}:/workspace",
            'ghcr.io/oras-project/oras:v1.3.0', 'push', '--insecure', oci_tag,
            '--artifact-type', 'application/vnd.ctfer-io.scenario',
            'main:application/vnd.ctfer-io.file',
            'Pulumi.yaml:application/vnd.ctfer-io.file'
        ]
        
        try:
            result = subprocess.run(push_cmd, cwd=self.build_dir, check=True,
                                   capture_output=True, text=True)
            
            # Parse digest
            for line in result.stdout.split('\n'):
                if line.startswith('Digest:'):
                    self.oci_digest = line.split(':', 1)[1].strip()
                    break
            
            Logger.success(f"Successfully pushed to {oci_tag}")
        except subprocess.CalledProcessError:
            Logger.warning("OCI push failed. You may need to install OCI CLI tools.")
            Logger.info(f"Manual push: cd {self.build_dir} && oras push --insecure {oci_tag} "
                       "main:application/vnd.ctfer-io.file Pulumi.yaml:application/vnd.ctfer-io.file")
            raise

    def cleanup(self):
        """Remove build directory"""
        if self.build_dir.exists():
            shutil.rmtree(self.build_dir)
