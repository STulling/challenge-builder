#!/usr/bin/env python3
"""
Challenge Builder Script

This script builds challenge images and creates OCI deployment packages.
Usage: build-challenge --ctf-domain <ctf-domain>
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional


class ChallengeBuilder:
    def __init__(self, challenge_dir: str, subdomain: str, ctf_domain: str):
        self.challenge_dir = Path(challenge_dir).resolve()
        self.subdomain = subdomain
        self.ctf_domain = ctf_domain
        self.registry = "registry." + ctf_domain  # e.g., registry.ctf.christmas
        self.build_dir = self.challenge_dir / ".build"
        # Detect if we should prefix docker commands with sudo (non-Windows, non-root)
        self.use_sudo = False
        try:
            # On Windows, assume no sudo; on Unix check uid
            if os.name != 'nt':
                self.use_sudo = (os.geteuid() != 0)
        except Exception:
            # If os.geteuid isn't available or any error occurs, default to False
            self.use_sudo = False
        
        # Default template folder
        self.template_folder = Path(__file__).parent / "pulumi-template"
            
        # Paths to expected files (we will check existence later and exit gracefully)
        self.docker_compose_path = self.challenge_dir / "docker-compose.yml"
        self.challenge_yml_path = self.challenge_dir / "challenge.yml"
        self.has_compose = self.docker_compose_path.exists()
        self.has_challenge = self.challenge_yml_path.exists()

    def run_command(self, cmd: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        """Run a shell command and return the result"""
        print(f"Running: {' '.join(cmd)}")
        if cwd:
            print(f"  in directory: {cwd}")
        # If this is a docker command and sudo is required, prepend sudo
        if self.use_sudo and cmd and cmd[0] == 'docker':
            cmd = ['sudo'] + cmd

        try:
            # Allow interactive commands (like docker login) to use the real stdio when needed
            interactive = cmd and cmd[0:2] == ['docker', 'login'] if len(cmd) >= 2 else False
            if interactive:
                result = subprocess.run(cmd, cwd=cwd, check=True)
            else:
                result = subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)
            if result.stdout:
                print(f"Output: {result.stdout.strip()}")
            return result
        except subprocess.CalledProcessError as e:
            print(f"Error running command: {' '.join(cmd)}")
            print(f"Return code: {e.returncode}")
            print(f"Stdout: {e.stdout}")
            print(f"Stderr: {e.stderr}")
            raise

    def read_docker_compose(self) -> Dict[str, Any]:
        """Read and parse the docker-compose.yml file"""
        print("Reading docker-compose.yml...")
        with open(self.docker_compose_path, 'r') as f:
            compose_data = yaml.safe_load(f)
        return compose_data

    def read_challenge_yaml(self) -> Dict[str, Any]:
        """Read and parse challenge.yml if present"""
        if not self.has_challenge:
            return {}
        with open(self.challenge_yml_path, 'r') as f:
            return yaml.safe_load(f) or {}

    def get_service_image_info(self, service_name: str, service_config: Dict[str, Any]) -> tuple:
        """
        Determine if a service needs to be built or uses a pre-built image
        Returns: (needs_build, current_image_name, new_image_tag)
        """
        new_image_tag = f"{self.registry}/{self.subdomain}/{service_name}:latest"
        
        if 'build' in service_config:
            # Service has a build context, needs to be built
            return True, None, new_image_tag
        elif 'image' in service_config:
            # Service uses a pre-built image, check if it's already from our registry
            current_image = service_config['image']
            if current_image.startswith(self.registry):
                # Already using our registry, no build needed
                return False, current_image, current_image
            else:
                # External image, should probably be retagged but not built
                return False, current_image, new_image_tag
        else:
            raise ValueError(f"Service {service_name} has neither 'build' nor 'image' specified")

    def build_and_push_images(self, compose_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Build and push Docker images for services that need it
        Returns a mapping of service_name -> new_image_tag for substitution
        """
        print("Building and pushing Docker images...")
        services = compose_data.get('services', {})
        image_substitutions = {}
        
        for service_name, service_config in services.items():
            print(f"\nProcessing service: {service_name}")
            
            needs_build, current_image, new_image_tag = self.get_service_image_info(service_name, service_config)
            
            if needs_build:
                # Build the image
                build_context = service_config.get('build', '.')
                if isinstance(build_context, dict):
                    build_path = build_context.get('context', '.')
                    dockerfile = build_context.get('dockerfile', 'Dockerfile')
                    build_cmd = ['docker', 'build', '-t', new_image_tag, '-f', dockerfile, build_path]
                else:
                    build_cmd = ['docker', 'build', '-t', new_image_tag, build_context]
                
                self.run_command(build_cmd, cwd=self.challenge_dir)
                
                # Push the image
                push_cmd = ['docker', 'push', new_image_tag]
                self.run_command(push_cmd)
                
                image_substitutions[service_name] = new_image_tag
                
            elif current_image and not current_image.startswith(self.registry):
                # External image that should be retagged and pushed
                print(f"Retagging external image {current_image} to {new_image_tag}")
                
                # Pull, tag, and push
                self.run_command(['docker', 'pull', current_image])
                self.run_command(['docker', 'tag', current_image, new_image_tag])
                self.run_command(['docker', 'push', new_image_tag])
                
                image_substitutions[service_name] = new_image_tag
            else:
                # Image is already from our registry or doesn't need changes
                if 'image' in service_config:
                    image_substitutions[service_name] = service_config['image']
        
        return image_substitutions

    def is_logged_in_to_registry(self) -> bool:
        """Check whether docker is logged in to the target registry.

        Strategy: run `docker info --format '{{json .}}'` and search for the registry in the AuthConfig (best-effort),
        but since docker doesn't expose a simple API for this, we'll fall back to attempting a `docker pull` of a non-existent
        image manifest using the registry to provoke an unauthorized error. To avoid slow network calls, first try `docker info`.
        """
        # First quick check: docker info
        try:
            cp = subprocess.run(['docker', 'info'], capture_output=True, text=True)
            out = (cp.stdout or '') + (cp.stderr or '')
            # If Authentication info or Username appears, assume logged in somewhere; we specifically check for our registry
            if self.registry in out:
                return True
        except Exception:
            pass

        # Fallback: try to get a token by attempting to pull a clearly non-existent image from the registry
        test_image = f"{self.registry}/__ctf_builder_login_test__:nope"
        try:
            # docker pull will return non-zero if not authorized; capture output
            cp = subprocess.run(['docker', 'pull', test_image], capture_output=True, text=True)
            combined = (cp.stdout or '') + (cp.stderr or '')
            # If the output contains 'unauthorized' or 'authentication required' consider not logged in
            lower = combined.lower()
            if 'unauthorized' in lower or 'authentication required' in lower or 'no basic auth credentials' in lower:
                return False
            # If it says not found or manifest unknown, it's likely we are authenticated but image doesn't exist
            if 'not found' in lower or 'manifest unknown' in lower:
                return True
        except Exception:
            pass

        # If all else fails, return False to trigger login
        return False

    def ensure_logged_in(self):
        """Ensure the user is logged into the configured registry. If not, prompt for docker login."""
        print(f"Checking Docker login status for registry: {self.registry}")
        try:
            if self.is_logged_in_to_registry():
                print("Docker appears to be logged in to the registry.")
                return
        except Exception as e:
            print(f"Warning while checking login status: {e}")

        # Prompt the user to login
        print(f"You are not logged into {self.registry}. Attempting interactive 'docker login'.")
        login_cmd = ['docker', 'login', self.registry]
        # run_command will add sudo if necessary and will run interactively
        try:
            self.run_command(login_cmd, cwd=self.challenge_dir)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Docker login failed: {e}")

    def substitute_docker_compose_images(self, compose_data: Dict[str, Any], image_substitutions: Dict[str, str]) -> Dict[str, Any]:
        """Update the docker-compose data with new image tags"""
        print("Substituting docker-compose with new image tags...")
        
        # Make a deep copy to avoid modifying original
        updated_compose = yaml.safe_load(yaml.dump(compose_data))
        
        for service_name, new_image in image_substitutions.items():
            if service_name in updated_compose['services']:
                service_config = updated_compose['services'][service_name]
                
                # Remove build section if it exists and set image
                if 'build' in service_config:
                    del service_config['build']
                
                service_config['image'] = new_image
                print(f"  {service_name}: {new_image}")
        
        return updated_compose

    def create_build_directory(self):
        """Create and populate the .build directory"""
        print("Creating .build directory...")
        
        # Remove existing build directory if it exists
        if self.build_dir.exists():
            shutil.rmtree(self.build_dir)
        
        # Create new build directory
        self.build_dir.mkdir()
        print(f"Created {self.build_dir}")

    def copy_files_to_build(self, updated_compose_data: Dict[str, Any]):
        """Copy necessary files to the .build directory"""
        print("Copying files to .build directory...")
        
        # Copy docker-compose.yml as docker-compose.yaml
        docker_compose_dest = self.build_dir / "docker-compose.yaml"
        with open(docker_compose_dest, 'w') as f:
            yaml.dump(updated_compose_data, f, default_flow_style=False)
        print(f"Copied docker-compose.yml -> {docker_compose_dest}")
        
        # Copy challenge.yml as challenge.yaml
        challenge_dest = self.build_dir / "challenge.yaml"
        shutil.copy2(self.challenge_yml_path, challenge_dest)
        print(f"Copied challenge.yml -> {challenge_dest}")
        
        # Copy Pulumi template files
        template_files = ['Pulumi.yaml', 'main.go', 'go.mod', 'go.sum']
        for filename in template_files:
            src = self.template_folder / filename
            dest = self.build_dir / filename
            if src.exists():
                shutil.copy2(src, dest)
                print(f"Copied {src} -> {dest}")
            else:
                print(f"Warning: {src} not found, skipping")

    def build_go_program(self):
        """Compile the Go program in the .build directory"""
        print("Building Go program...")
        self.run_command(['go', 'mod', 'tidy'], cwd=self.build_dir)
        # CGO_ENABLED=0 for static binary
        os.environ['CGO_ENABLED'] = '0'
        build_cmd = ['go', 'build', '-o', 'main',
                        '-ldflags', f"-X main.Subdomain={self.subdomain} -X main.CtfDomain={self.ctf_domain}", "main.go"] 
        self.run_command(build_cmd, cwd=self.build_dir)
        
        # Verify the binary was created
        main_binary = self.build_dir / "main"
        if not main_binary.exists():
            raise RuntimeError("Go build failed: main binary not found")
        print("Go program built successfully")

    def push_to_oci_registry(self):
        """Push the build directory to OCI registry"""
        print("Pushing to OCI registry...")
        
        # Use the first service name from docker-compose for the OCI package name
        # This is a simplification - you might want to use the challenge name instead
        with open(self.docker_compose_path, 'r') as f:
            compose_data = yaml.safe_load(f)
        
        services = list(compose_data.get('services', {}).keys())
        if not services:
            raise ValueError("No services found in docker-compose.yml")
        
        # Use challenge name from challenge.yml if available, otherwise first service name
        try:
            with open(self.challenge_yml_path, 'r') as f:
                challenge_data = yaml.safe_load(f)
            package_name = challenge_data.get('name', services[0])
        except:
            package_name = services[0]
        
        oci_tag = f"{self.registry}/{self.subdomain}/{package_name}-scenario:latest"
        
        # Note: This assumes you have an OCI CLI tool. You might need to adjust this
        # depending on your specific OCI registry and tooling
        push_cmd = ['oras', 'push', '--insecure', oci_tag, 
                    '--artifact-type', 'application/vnd.ctfer-io.scenario',
                    'main:application/vnd.ctfer-io.file',
                    'Pulumi.yaml:application/vnd.ctfer-io.file']
        
        try:
            self.run_command(push_cmd, cwd=self.build_dir)
            print(f"Successfully pushed to {oci_tag}")
        except subprocess.CalledProcessError as e:
            print(f"Warning: OCI push failed. You may need to install OCI CLI tools or adjust the command.")
            print(f"Manual push command: cd {self.build_dir} && oci push {oci_tag} .")
            raise

    def cleanup(self):
        """Remove the .build directory"""
        print("Cleaning up...")
        if self.build_dir.exists():
            shutil.rmtree(self.build_dir)
            print(f"Removed {self.build_dir}")

    def build(self):
        """Execute the complete build process"""
        try:
            print(f"Building challenge in {self.challenge_dir}")
            print(f"Subdomain: {self.subdomain}")
            print(f"Registry: {self.registry}")
            print(f"Template: {self.template_folder}")
            print()
            
            # Step 1-3: Read docker-compose, build images, push images, substitute
            compose_data = self.read_docker_compose()
            # Ensure we're logged in to the registry before building/pushing images
            self.ensure_logged_in()
            image_substitutions = self.build_and_push_images(compose_data)
            updated_compose_data = self.substitute_docker_compose_images(compose_data, image_substitutions)
            
            # Step 4-8: Create .build directory and copy files
            self.create_build_directory()
            self.copy_files_to_build(updated_compose_data)
            
            # Step 9-10: Build Go program
            self.build_go_program()
            
            # Step 11: Push to OCI registry
            self.push_to_oci_registry()
            
            print("\n✅ Challenge build completed successfully!")
            
        except Exception as e:
            print(f"\n❌ Build failed: {e}")
            raise
        finally:
            # Step 12: Cleanup
            self.cleanup()


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
        print("docker-compose.yml and/or challenge.yml not found in the current directory. Nothing to do.")
        sys.exit(0)

    try:
        builder.build()
    except Exception as e:
        print(f"Build failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
