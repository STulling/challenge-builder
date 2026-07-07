#!/usr/bin/env python3
"""Bundle creation for offline challenges"""

import zipfile
import logging
from pathlib import Path
from typing import List

import yaml

from .utils import sha256_file

logger = logging.getLogger(__name__)


class BundleManager:
    """Creates offline challenge bundles"""

    def __init__(self, challenge_dir: Path, dist_dir: Path):
        self.challenge_dir = challenge_dir
        self.dist_dir = dist_dir

    def _check_file_for_flags(self, file_path: Path, flags: List[str]):
        """Check if file contains any of the flags"""
        if not flags:
            return
        try:
            content = file_path.read_bytes()
            for flag in flags:
                if flag.encode("utf-8") in content:
                    logger.error(f"Flag found in {file_path.name}!")
                    raise ValueError(f"Security check failed: Flag '{flag}' detected in bundle file '{file_path.name}'.")
        except (OSError, IOError) as e:
            logger.warning(f"Could not read {file_path.name} for flag check: {e}")

    def _is_compose_file(self, file_path: Path) -> bool:
        """Return true for docker-compose.yml / docker-compose.yaml files."""
        return file_path.name in {"docker-compose.yml", "docker-compose.yaml"}

    def _strip_compose_port_suffixes(self, content: bytes, file_path: Path) -> bytes:
        """Strip player-only compose protocol suffixes from ports entries."""
        try:
            compose = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"Could not parse compose file '{file_path.name}': {e}") from e

        if not isinstance(compose, dict):
            return content

        services = compose.get("services")
        if not isinstance(services, dict):
            return content

        changed = False
        suffixes = ("/HTTP", "/TCP", "/http", "/tcp")

        for service in services.values():
            if not isinstance(service, dict):
                continue
            ports = service.get("ports")
            if not isinstance(ports, list):
                continue
            for index, port in enumerate(ports):
                if not isinstance(port, str):
                    continue
                for suffix in suffixes:
                    if port.endswith(suffix):
                        ports[index] = port[: -len(suffix)]
                        changed = True
                        break

        if not changed:
            return content

        return yaml.safe_dump(compose, sort_keys=False).encode("utf-8")

    def _read_bundle_file(self, file_path: Path) -> bytes:
        """Read a bundle file, sanitizing docker-compose ports when needed."""
        content = file_path.read_bytes()
        if self._is_compose_file(file_path):
            return self._strip_compose_port_suffixes(content, file_path)
        return content

    def _add_path_to_zip(
        self,
        zip_handle: zipfile.ZipFile,
        source: Path,
        slug_prefix: str,
        flags: List[str] = None,
        skip_flag_check: bool = False,
    ):
        """Add a file or directory to a zip archive"""
        source = source.resolve()
        if source.is_dir():
            for file_path in sorted(source.rglob("*")):
                if file_path.is_file():
                    if flags and not skip_flag_check:
                        self._check_file_for_flags(file_path, flags)
                    arcname = file_path.relative_to(self.challenge_dir)
                    arcname_with_prefix = Path(slug_prefix) / arcname
                    if self._is_compose_file(file_path):
                        zip_handle.writestr(arcname_with_prefix.as_posix(), self._read_bundle_file(file_path))
                    else:
                        zip_handle.write(file_path, arcname_with_prefix.as_posix())
        elif source.is_file():
            if flags and not skip_flag_check:
                self._check_file_for_flags(source, flags)
            arcname = source.relative_to(self.challenge_dir)
            arcname_with_prefix = Path(slug_prefix) / arcname
            if self._is_compose_file(source):
                zip_handle.writestr(arcname_with_prefix.as_posix(), self._read_bundle_file(source))
            else:
                zip_handle.write(source, arcname_with_prefix.as_posix())
        else:
            raise FileNotFoundError(f"Bundle entry not found: {source}")

    def _select_plain_files(
        self,
        include_items: List[str],
        slug: str,
        flags: List[str] = None,
        skip_flag_check: bool = False,
    ) -> List[Path]:
        """Select existing files for direct upload."""
        bundle_paths = []
        for item in include_items:
            source = (self.challenge_dir / item).resolve()
            if not source.exists():
                raise FileNotFoundError(f"Bundle entry not found: {source}")
            if not source.is_file():
                raise ValueError(f"Non-zip bundle entries must be files: {source}")

            if flags and not skip_flag_check:
                self._check_file_for_flags(source, flags)
            if self._is_compose_file(source):
                bundle_dir = self.dist_dir / f"{slug}-bundle"
                bundle_dir.mkdir(parents=True, exist_ok=True)
                sanitized_path = bundle_dir / "docker-compose.yml"
                sanitized_path.write_bytes(self._read_bundle_file(source))
                bundle_paths.append(sanitized_path)
            else:
                bundle_paths.append(source)

        return bundle_paths

    def create_bundle(
        self,
        include_items: List[str],
        slug: str,
        flags: List[str] = None,
        skip_flag_check: bool = False,
        zip_bundle: bool = True,
    ) -> List[Path]:
        """Create an offline challenge bundle"""
        if not include_items:
            raise ValueError("Bundle must include at least one file or directory")
        if skip_flag_check:
            logger.warning("Skipping bundle flag security check")

        if not zip_bundle:
            bundle_paths = self._select_plain_files(
                include_items,
                slug,
                flags,
                skip_flag_check=skip_flag_check,
            )
            for bundle_path in bundle_paths:
                logger.info(f"Using offline bundle file {bundle_path.relative_to(self.challenge_dir)}")
            return bundle_paths
        
        # Clean previous bundles
        if self.dist_dir.exists():
            for old_zip in self.dist_dir.glob(f"{slug}-*.zip"):
                old_zip.unlink()

        # Create bundle
        self.dist_dir.mkdir(exist_ok=True)
        tmp_zip_path = self.dist_dir / f"{slug}.zip.tmp"
        
        with zipfile.ZipFile(tmp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zip_handle:
            for item in include_items:
                entry_path = (self.challenge_dir / item).resolve()
                self._add_path_to_zip(
                    zip_handle,
                    entry_path,
                    slug,
                    flags,
                    skip_flag_check=skip_flag_check,
                )

        # Rename with hash
        digest = sha256_file(tmp_zip_path)
        final_name = f"{slug}-{digest[:8]}.zip"
        final_path = self.dist_dir / final_name
        tmp_zip_path.replace(final_path)
        
        logger.info(f"Created offline bundle {final_path.relative_to(self.challenge_dir)}")
        return [final_path]
