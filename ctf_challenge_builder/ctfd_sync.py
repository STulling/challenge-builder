#!/usr/bin/env python3
"""CTFd synchronization logic"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from .bundle_manager import BundleManager
from .ctfd_client import (
    AttachmentSpec,
    CTFdAuthError,
    CTFdClient,
    CTFdClientError,
    ChallengeSyncResult,
    calculate_sync_hash,
)
from .logger import Logger


class CTFdSync:
    """Handles CTFd challenge synchronization"""

    def __init__(self, challenge_dir: Path, dist_dir: Path, ctfd_url: Optional[str],
                 ctfd_username: Optional[str], ctfd_password: Optional[str], 
                 ctfd_verify_ssl: bool = True, ctfd_timeout: int = 60, ctfd_verbose: bool = False):
        self.challenge_dir = challenge_dir
        self.dist_dir = dist_dir
        self.ctfd_url = ctfd_url.rstrip("/") if ctfd_url else None
        self.ctfd_username = ctfd_username
        self.ctfd_password = ctfd_password
        self.ctfd_verify_ssl = ctfd_verify_ssl
        self.ctfd_timeout = ctfd_timeout
        self.ctfd_verbose = ctfd_verbose
        self.bundle_manager = BundleManager(challenge_dir, dist_dir)

    def _collect_attachments(self, ctfd_cfg: Dict[str, Any]) -> List[AttachmentSpec]:
        """Collect file attachments for CTFd"""
        attachments: List[AttachmentSpec] = []
        for entry in ctfd_cfg.get("files", []):
            if isinstance(entry, str):
                rel_path, display_name = entry, None
            elif isinstance(entry, dict):
                rel_path = entry.get("path")
                display_name = entry.get("name")
            else:
                raise ValueError(f"Unsupported attachment entry: {entry}")

            if rel_path:
                candidate = (self.challenge_dir / rel_path).resolve()
                attachments.append(AttachmentSpec.from_path(candidate, display_name))
        return attachments

    def _build_payload(self, challenge_data: Dict[str, Any], ctfd_cfg: Dict[str, Any],
                      package_name: str, oci_reference: Optional[str]) -> Dict[str, Any]:
        """Build CTFd challenge payload"""
        payload: Dict[str, Any] = {}
        payload.update(ctfd_cfg.get("challenge", {}))

        # Merge fields from various sources
        fallback_keys = ["name", "category", "description", "connection_info", "state", 
                        "value", "initial", "minimum", "decay", "requirements", "type",
                        "min", "max", "destroy_on_flag", "updateStrategy"]
        
        for key in fallback_keys:
            if key not in payload:
                payload[key] = ctfd_cfg.get(key) or challenge_data.get(key)

        payload["type"] = ctfd_cfg.get("type", payload.get("type", "dynamic"))

        # Handle dynamic_iac type
        if payload["type"] == "dynamic_iac":
            payload.update(ctfd_cfg.get("dynamic_iac", {}))
            if not payload.get("scenario"):
                payload["scenario"] = oci_reference or challenge_data.get("scenario")
        elif payload["type"] == "dynamic":
            payload.update(ctfd_cfg.get("dynamic", {}))

        # Set defaults
        payload.setdefault("name", challenge_data.get("name") or package_name)
        payload.setdefault("category", challenge_data.get("category"))
        payload.setdefault("description", challenge_data.get("description"))
        payload.setdefault("connection_info", challenge_data.get("connection_info"))
        
        # Flags and hints
        payload["flags"] = ctfd_cfg.get("flags") or challenge_data.get("flags", [])
        payload["hints"] = ctfd_cfg.get("hints", [])
        
        if "requirements" not in payload:
            payload["requirements"] = ctfd_cfg.get("requirements") or challenge_data.get("requirements")

        # Extra fields
        for key, value in ctfd_cfg.get("extra_fields", {}).items():
            if value is not None:
                payload[key] = value

        # Dynamic scoring defaults
        if payload["type"] in ("dynamic", "dynamic_iac"):
            starting_value = payload.get("value") or 500
            if not payload.get("value"):
                payload["value"] = starting_value
            if not payload.get("initial"):
                payload["initial"] = starting_value
            if not payload.get("minimum"):
                payload["minimum"] = 100
            if not payload.get("decay"):
                payload["decay"] = 15

        if payload["type"] == "dynamic_iac":
            if not payload.get("destroy_on_flag"):
                payload["destroy_on_flag"] = True
            if not payload.get("updateStrategy"):
                payload["updateStrategy"] = "recreate"
            if not payload.get("min"):
                payload["min"] = 5
            if not payload.get("max"):
                payload["max"] = 100

        return {k: v for k, v in payload.items() if v is not None}

    def _log_result(self, result: ChallengeSyncResult):
        """Log sync result"""
        if result.status == "skipped":
            Logger.info(f"CTFd challenge unchanged (id={result.challenge_id}).")
        elif result.status == "updated":
            Logger.success(f"CTFd challenge updated (id={result.challenge_id}).")
        elif result.status == "created":
            Logger.success(f"CTFd challenge created (id={result.challenge_id}).")

    def sync(self, challenge_data: Dict[str, Any], package_name: str, oci_reference: Optional[str]):
        """Synchronize challenge with CTFd"""
        ctfd_cfg = challenge_data.get("ctfd")
        if not ctfd_cfg:
            return

        if not self.ctfd_url:
            Logger.warning("CTFd configuration present but no --ctfd-url provided. Skipping sync.")
            return

        if not (self.ctfd_username and self.ctfd_password):
            Logger.warning("CTFd configuration present but no credentials supplied. Skipping sync.")
            return

        # Handle offline bundle
        bundle_cfg = ctfd_cfg.get("bundle")
        if bundle_cfg:
            if not isinstance(bundle_cfg, dict):
                raise ValueError("ctfd.bundle must be a mapping with an 'include' list")
            
            include_items = bundle_cfg.get("include", [])
            if not isinstance(include_items, list):
                raise ValueError("ctfd.bundle.include must be a list of paths")
            
            slug_source = (bundle_cfg.get("slug") or ctfd_cfg.get("slug") or 
                          challenge_data.get("slug") or challenge_data.get("name") or package_name)
            
            bundle_path, sanitized_slug = self.bundle_manager.create_bundle(include_items, slug_source)
            
            # Add bundle to files
            bundle_entry = {
                "path": str(bundle_path.relative_to(self.challenge_dir)),
                "name": bundle_cfg.get("name", bundle_path.name),
            }
            
            existing_files = ctfd_cfg.get("files") or []
            if not isinstance(existing_files, list):
                raise ValueError("ctfd.files must be a list when using bundle support")
            
            # Filter out old bundles
            filtered_files = []
            for item in existing_files:
                item_path_str = item if isinstance(item, str) else item.get("path")
                if item_path_str:
                    normalized = item_path_str.replace("\\", "/")
                    if f"dist/{sanitized_slug}-" in normalized:
                        continue
                filtered_files.append(item)
            
            ctfd_cfg["files"] = [bundle_entry] + filtered_files

        # Collect attachments and build payload
        try:
            attachments = self._collect_attachments(ctfd_cfg)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Attachment not found for CTFd upload: {exc}") from exc

        payload = self._build_payload(challenge_data, ctfd_cfg, package_name, oci_reference)
        builder_hash = calculate_sync_hash(payload, attachments)

        # Sync with CTFd
        client = CTFdClient(
            base_url=self.ctfd_url,
            username=self.ctfd_username,
            password=self.ctfd_password,
            verify_ssl=self.ctfd_verify_ssl,
            timeout=self.ctfd_timeout,
            verbose=self.ctfd_verbose,
        )

        try:
            result = client.sync_challenge(
                payload=payload,
                attachments=attachments,
                builder_hash=builder_hash,
                challenge_id=ctfd_cfg.get("id"),
                slug=ctfd_cfg.get("slug"),
                name=payload.get("name"),
                tags=ctfd_cfg.get("tags"),
            )
            self._log_result(result)
        except (CTFdAuthError, CTFdClientError) as exc:
            raise RuntimeError(f"Failed to synchronise challenge with CTFd: {exc}") from exc
