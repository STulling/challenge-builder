#!/usr/bin/env python3
"""Bundle creation for offline challenges"""

import zipfile
import logging
from pathlib import Path
from typing import List

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
                    zip_handle.write(file_path, arcname_with_prefix.as_posix())
        elif source.is_file():
            if flags and not skip_flag_check:
                self._check_file_for_flags(source, flags)
            arcname = source.relative_to(self.challenge_dir)
            arcname_with_prefix = Path(slug_prefix) / arcname
            zip_handle.write(source, arcname_with_prefix.as_posix())
        else:
            raise FileNotFoundError(f"Bundle entry not found: {source}")

    def _select_plain_file(
        self,
        include_items: List[str],
        flags: List[str] = None,
        skip_flag_check: bool = False,
    ) -> Path:
        """Select a single existing file for direct upload."""
        if len(include_items) != 1:
            raise ValueError("Non-zip bundles must include exactly one file")

        source = (self.challenge_dir / include_items[0]).resolve()
        if not source.exists():
            raise FileNotFoundError(f"Bundle entry not found: {source}")
        if not source.is_file():
            raise ValueError(f"Non-zip bundle entry must be a file: {source}")

        if flags and not skip_flag_check:
            self._check_file_for_flags(source, flags)

        return source

    def create_bundle(
        self,
        include_items: List[str],
        slug: str,
        flags: List[str] = None,
        skip_flag_check: bool = False,
        zip_bundle: bool = True,
    ) -> Path:
        """Create an offline challenge bundle"""
        if not include_items:
            raise ValueError("Bundle must include at least one file or directory")
        if skip_flag_check:
            logger.warning("Skipping bundle flag security check")

        if not zip_bundle:
            bundle_path = self._select_plain_file(
                include_items,
                flags,
                skip_flag_check=skip_flag_check,
            )
            logger.info(f"Using offline bundle file {bundle_path.relative_to(self.challenge_dir)}")
            return bundle_path
        
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
        return final_path
