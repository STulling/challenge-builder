#!/usr/bin/env python3
"""Docker operations management"""

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .logger import Logger


class DockerManager:
    """Handles Docker build, push, and authentication operations"""

    def __init__(self, registry: str, subdomain: str, use_sudo: bool = False):
        self.registry = registry
        self.subdomain = subdomain
        self.use_sudo = use_sudo
        self._sudo_notified = False
        self.oci_username: Optional[str] = None
        self.oci_password: Optional[str] = None

    def _notify_sudo_once(self):
        """Notify user about sudo usage once"""
        if not self._sudo_notified and self.use_sudo:
            Logger.info("🔒 Docker commands will run with sudo. You may be prompted for your password.")
            self._sudo_notified = True

    def _prepare_command(self, cmd: List[str]) -> List[str]:
        """Add sudo prefix if needed"""
        if self.use_sudo and cmd and cmd[0] == "docker":
            self._notify_sudo_once()
            return ["sudo"] + cmd
        return cmd

    def run_docker_command(self, cmd: List[str], cwd: Optional[Path] = None, 
                          input_text: Optional[str] = None, silent: bool = False) -> subprocess.CompletedProcess:
        """Execute a docker command"""
        prepared_cmd = self._prepare_command(cmd)
        
        if not silent:
            display_cmd = ' '.join(cmd)
            if len(display_cmd) > 100:
                display_cmd = display_cmd[:97] + "..."
            Logger.step(f"Running: {display_cmd}")

        try:
            return subprocess.run(
                prepared_cmd, cwd=cwd, input=input_text, text=True if input_text else False,
                capture_output=silent, check=True
            )
        except subprocess.CalledProcessError as exc:
            Logger.error(f"Command failed ({exc.returncode}): {' '.join(cmd)}")
            if exc.stdout:
                Logger.error(exc.stdout.strip())
            if exc.stderr:
                Logger.error(exc.stderr.strip())
            raise

    def is_logged_in(self) -> bool:
        """Check if logged into the registry"""
        # Check docker config
        config_path = '/root/.docker/config.json' if self.use_sudo else os.path.expanduser('~/.docker/config.json')
        cat_cmd = ['sudo', 'cat', config_path] if self.use_sudo else ['cat', config_path]
        
        try:
            cp = subprocess.run(cat_cmd, capture_output=True, text=True)
            if cp.returncode == 0 and self.registry in cp.stdout:
                return True
        except Exception:
            pass

        # Fallback: test pull
        docker_cmd = self._prepare_command(['docker', 'pull', f"{self.registry}/__login_test__:nope"])
        try:
            cp = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=10)
            combined = (cp.stdout or '') + (cp.stderr or '')
            lower = combined.lower()
            
            if any(p in lower for p in ['unauthorized', 'authentication required', 'no basic auth credentials']):
                return False
            if any(p in lower for p in ['not found', 'manifest unknown']):
                return True
        except (subprocess.TimeoutExpired, Exception):
            pass

        return False

    def login(self, username: Optional[str] = None, password: Optional[str] = None):
        """Login to the Docker registry"""
        try:
            if self.is_logged_in():
                Logger.success(f"Authenticated to {self.registry}")
                return
        except Exception as e:
            Logger.warning(f"Could not verify login status: {e}")

        Logger.warning(f"Not logged into {self.registry}.")
        if self.use_sudo:
            Logger.info("Note: Credentials will be stored for the root user (sudo required)")
        
        print()
        
        import getpass
        
        # Use provided credentials or stored ones or prompt
        username = username or self.oci_username
        password = password or self.oci_password
        
        if not username:
            username = input(f"🔐 Username for {self.registry}: ").strip()
        if not password:
            password = getpass.getpass(f"🔐 Password for {self.registry}: ")
        
        login_cmd = ['docker', 'login', '--username', username, '--password-stdin', self.registry]
        try:
            self.run_docker_command(login_cmd, input_text=password, silent=True)
            Logger.success("Successfully logged into Docker registry.")
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            Logger.error(f"Docker login failed: {error_msg}")
            raise RuntimeError(f"Docker login failed: {error_msg}")

    def build_and_push_images(self, compose_data: Dict[str, Any], challenge_dir: Path) -> Dict[str, str]:
        """Build and push Docker images from docker-compose"""
        Logger.build("Building and pushing Docker images...")
        services = compose_data.get('services', {})
        image_substitutions = {}
        
        for service_name, service_config in services.items():
            new_image_tag = f"{self.registry}/{self.subdomain}/{service_name}:latest"
            
            # Determine if build is needed
            if 'build' in service_config:
                Logger.info(f"\n📦 Building service: {service_name}")
                
                build_context = service_config.get('build', '.')
                if isinstance(build_context, dict):
                    build_path = build_context.get('context', '.')
                    dockerfile = build_context.get('dockerfile', 'Dockerfile')
                    build_cmd = ['docker', 'build', '-t', new_image_tag, '-f', dockerfile, build_path]
                else:
                    build_cmd = ['docker', 'build', '-t', new_image_tag, build_context]
                
                self.run_docker_command(build_cmd, cwd=challenge_dir)
                
                Logger.info(f"📤 Pushing {service_name}")
                self.run_docker_command(['docker', 'push', new_image_tag], silent=True)
                image_substitutions[service_name] = new_image_tag
                
            elif 'image' in service_config:
                current_image = service_config['image']
                if current_image.startswith(self.registry):
                    image_substitutions[service_name] = current_image
                else:
                    # Retag external image
                    Logger.info(f"📦 Retagging external image: {service_name}")
                    Logger.info(f"  {current_image} → {new_image_tag}")
                    
                    self.run_docker_command(['docker', 'pull', current_image], silent=True)
                    self.run_docker_command(['docker', 'tag', current_image, new_image_tag], silent=True)
                    self.run_docker_command(['docker', 'push', new_image_tag], silent=True)
                    image_substitutions[service_name] = new_image_tag
            else:
                raise ValueError(f"Service {service_name} has neither 'build' nor 'image' specified")
        
        return image_substitutions

    @staticmethod
    def substitute_images(compose_data: Dict[str, Any], image_substitutions: Dict[str, str]) -> Dict[str, Any]:
        """Update docker-compose with new image tags"""
        updated_compose = yaml.safe_load(yaml.dump(compose_data))
        
        for service_name, new_image in image_substitutions.items():
            if service_name in updated_compose['services']:
                service_config = updated_compose['services'][service_name]
                if 'build' in service_config:
                    del service_config['build']
                service_config['image'] = new_image
        
        return updated_compose
    
    @staticmethod
    def update_ports(compose_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update docker-compose with new port mappings"""
        updated_compose = yaml.safe_load(yaml.dump(compose_data))
        
        for service in updated_compose.get('services', {}).values():
            ports = service.get('ports', [])
            new_ports = []
            for port in ports:
                if isinstance(port, str) and ':' in port:
                    host_port, container_port = port.split(':', 1)
                    new_ports.append(container_port)
                else:
                    new_ports.append(port)
            service['ports'] = new_ports
        return updated_compose
