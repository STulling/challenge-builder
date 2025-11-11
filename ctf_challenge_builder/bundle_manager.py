#!/usr/bin/env python3
"""Bundle creation for offline challenges"""

import zipfile
from pathlib import Path
from typing import List, Tuple

from .logger import Logger
from .utils import sanitize_slug, sha256_file


class BundleManager:
    """Creates offline challenge bundles"""

    def __init__(self, challenge_dir: Path, dist_dir: Path):
        self.challenge_dir = challenge_dir
        self.dist_dir = dist_dir

    def _add_path_to_zip(self, zip_handle: zipfile.ZipFile, source: Path, slug_prefix: str):
        """Add a file or directory to a zip archive"""
        source = source.resolve()
        if source.is_dir():
            for file_path in sorted(source.rglob("*")):
                if file_path.is_file():
                    arcname = file_path.relative_to(self.challenge_dir)
                    arcname_with_prefix = Path(slug_prefix) / arcname
                    zip_handle.write(file_path, arcname_with_prefix.as_posix())
        elif source.is_file():
            arcname = source.relative_to(self.challenge_dir)
            arcname_with_prefix = Path(slug_prefix) / arcname
            zip_handle.write(source, arcname_with_prefix.as_posix())
        else:
            raise FileNotFoundError(f"Bundle entry not found: {source}")

    def create_bundle(self, include_items: List[str], slug: str) -> Tuple[Path, str]:
        """Create an offline challenge bundle"""
        if not include_items:
            raise ValueError("Bundle must include at least one file or directory")

        sanitized = sanitize_slug(slug)
        
        # Clean previous bundles
        if self.dist_dir.exists():
            for old_zip in self.dist_dir.glob(f"{sanitized}-*.zip"):
                old_zip.unlink()

        # Create bundle
        self.dist_dir.mkdir(exist_ok=True)
        tmp_zip_path = self.dist_dir / f"{sanitized}.zip.tmp"
        
        with zipfile.ZipFile(tmp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zip_handle:
            for item in include_items:
                entry_path = (self.challenge_dir / item).resolve()
                self._add_path_to_zip(zip_handle, entry_path, sanitized)

        # Rename with hash
        digest = sha256_file(tmp_zip_path)
        final_name = f"{sanitized}-{digest[:8]}.zip"
        final_path = self.dist_dir / final_name
        tmp_zip_path.replace(final_path)
        
        Logger.success(f"Created offline bundle {final_path.relative_to(self.challenge_dir)}")
        return final_path, sanitized
