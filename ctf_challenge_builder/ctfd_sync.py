#!/usr/bin/env python3
"""CTFd synchronization logic"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .ctfd_client import (
    AttachmentSpec,
    CTFdAuthError,
    CTFdClient,
    CTFdClientError,
    ChallengeSyncResult,
    calculate_sync_hash,
)
from .bundle_manager import BundleManager

logger = logging.getLogger(__name__)


class CTFdSync:
    """Handles CTFd challenge synchronization"""

    def __init__(self, challenge_dir: Path, dist_dir: Path, ctfd_url: Optional[str],
                 ctfd_username: Optional[str], ctfd_password: Optional[str], 
                 ctfd_verify_ssl: bool = True, ctfd_timeout: int = 60,
                 ctfd_verbose: bool = False, skip_bundle_flag_check: bool = False):
        self.challenge_dir = challenge_dir
        self.dist_dir = dist_dir
        self.ctfd_url = ctfd_url.rstrip("/") if ctfd_url else None
        self.ctfd_username = ctfd_username
        self.ctfd_password = ctfd_password
        self.ctfd_verify_ssl = ctfd_verify_ssl
        self.ctfd_timeout = ctfd_timeout
        self.ctfd_verbose = ctfd_verbose
        self.skip_bundle_flag_check = skip_bundle_flag_check
        self.bundle_manager = BundleManager(challenge_dir, dist_dir)

    def _collect_attachments(self, challenge_data: Dict[str, Any]) -> List[AttachmentSpec]:
        """Collect file attachments for CTFd"""
        attachments: List[AttachmentSpec] = []
        for entry in challenge_data.get("files", []):
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

    def _normalize_flags(self, raw_flags: Any) -> List[Dict[str, Any]]:
        """Normalize challenge.yml flags into CTFd API flag payloads."""
        if raw_flags is None:
            return []
        if not isinstance(raw_flags, list):
            raise ValueError("ctfd.flags must be a list")

        flags: List[Dict[str, Any]] = []
        for raw in raw_flags:
            if isinstance(raw, str):
                flags.append({"content": raw, "type": "static"})
                continue
            if not isinstance(raw, dict):
                raise ValueError(f"Unsupported flag entry: {raw}")

            content = raw.get("content")
            if not content:
                raise ValueError("flag entries must define content")

            data = raw.get("data")
            if data is None:
                data = (
                    raw.get("format_hint")
                    or raw.get("formatHint")
                    or raw.get("format")
                    or raw.get("placeholder")
                )

            flag = {
                "content": content,
                "type": raw.get("type", "static"),
            }
            if data is not None:
                flag["data"] = data
            flags.append(flag)
        return flags

    def _bundle_zip_enabled(self, bundle_cfg: Dict[str, Any]) -> bool:
        """Read bundle.zip, accepting normal YAML booleans and common strings."""
        raw_value = bundle_cfg.get("zip", True)
        if isinstance(raw_value, bool):
            return raw_value
        if isinstance(raw_value, str):
            lowered = raw_value.strip().lower()
            if lowered in ("1", "true", "yes", "y", "on"):
                return True
            if lowered in ("0", "false", "no", "n", "off"):
                return False
        raise ValueError("ctfd.bundle.zip must be a boolean")

    def _build_payload(self, challenge_data: Dict[str, Any],
                      oci_reference: Optional[str]) -> Dict[str, Any]:
        """Build CTFd challenge payload"""
        
        # 1. Initialize with Basic Information
        payload = {
            "name": challenge_data.get("name"),
            "category": challenge_data.get("category"),
            "description": challenge_data.get("description"),
            "attribution": challenge_data.get("attribution"),
            "connection_info": challenge_data.get("connection_info"),
            "state": challenge_data.get("state", "visible"),
            "type": challenge_data.get(
                "type",
                "multi_dynamic" if challenge_data.get("tasks") else "dynamic",
            ),
        }

        # 2. Copy Lists and Optional Fields
        payload["flags"] = self._normalize_flags(challenge_data.get("flags", []))
        payload["hints"] = challenge_data.get("hints", [])
        payload["tags"] = challenge_data.get("tags")

        # 3. Handle Type-Specific Configuration
        challenge_type = payload["type"]
        
        if challenge_type == "multi_dynamic":
            payload["tasks"] = challenge_data.get("tasks", [])

        if challenge_type == "dynamic_iac":
            # Merge specific dynamic_iac configuration
            payload.update(challenge_data.get("dynamic_iac", {}))
            
            # Set Scenario (OCI Image)
            if not payload.get("scenario"):
                payload["scenario"] = oci_reference or challenge_data.get("scenario")

            # Apply Dynamic IaC Defaults
            if payload.get("destroy_on_flag") is None:
                payload["destroy_on_flag"] = True
            
            payload.setdefault("min", 5)
            payload.setdefault("max", 20)
            payload.setdefault("timeout", 1800)
            
            if payload.get("mana_cost") is None:
                payload["mana_cost"] = 0

        elif challenge_type == "dynamic":
            # Merge specific dynamic configuration
            payload.update(challenge_data.get("dynamic", {}))

        # 4. Handle Scoring Configuration
        if challenge_type in ("dynamic", "dynamic_iac", "multi_dynamic"):
            # Copy scoring fields from root if not already present
            scoring_fields = ["value", "initial", "minimum", "decay", "function"]
            for field in scoring_fields:
                if field not in payload and field in challenge_data:
                    payload[field] = challenge_data[field]

            # Apply Scoring Defaults
            starting_value = payload.get("value") or payload.get("initial") or 500
            payload.setdefault("value", starting_value)
            payload.setdefault("initial", starting_value)
            payload.setdefault("minimum", 50)
            payload.setdefault("decay", 50)
            payload.setdefault("function", "linear")

        # 5. Merge Extra Fields
        extra_fields = challenge_data.get("extra_fields", {})
        for key, value in extra_fields.items():
            if value is not None:
                payload[key] = value

        # 6. Final Cleanup
        return {k: v for k, v in payload.items() if v is not None}

    def _log_result(self, result: ChallengeSyncResult):
        """Log sync result"""
        if result.status == "skipped":
            logger.info(f"CTFd challenge unchanged (id={result.challenge_id}).")
        elif result.status == "updated":
            logger.info(f"CTFd challenge updated (id={result.challenge_id}).")
        elif result.status == "created":
            logger.info(f"CTFd challenge created (id={result.challenge_id}).")

    def sync(self, challenge_data: Dict[str, Any], oci_reference: Optional[str], slug: str):
        """Synchronize challenge with CTFd"""
        if not self.ctfd_url:
            logger.warning("CTFd configuration present but no --ctfd-url provided. Skipping sync.")
            return

        if not (self.ctfd_username and self.ctfd_password):
            logger.warning("CTFd configuration present but no credentials supplied. Skipping sync.")
            return

        # Extract flags for bundle check
        raw_flags = self._normalize_flags(challenge_data.get("flags", []))
        flags = [flag["content"] for flag in raw_flags]

        # Handle offline bundle
        bundle_cfg = challenge_data.get("bundle")
        if bundle_cfg:
            if not isinstance(bundle_cfg, dict):
                raise ValueError("ctfd.bundle must be a mapping with an 'include' list")
            
            include_items = bundle_cfg.get("include", [])
            if not isinstance(include_items, list):
                raise ValueError("ctfd.bundle.include must be a list of paths")

            skip_flag_check = bool(
                self.skip_bundle_flag_check
                or bundle_cfg.get("skip_flag_check")
                or bundle_cfg.get("skip_flag_security_check")
                or bundle_cfg.get("allow_flags")
            )
            zip_bundle = self._bundle_zip_enabled(bundle_cfg)
            
            bundle_path = self.bundle_manager.create_bundle(
                include_items,
                slug,
                flags,
                skip_flag_check=skip_flag_check,
                zip_bundle=zip_bundle,
            )
            
            # Add bundle to files
            bundle_entry = {
                "path": str(bundle_path.relative_to(self.challenge_dir)),
                "name": bundle_cfg.get("name", bundle_path.name),
            }
            
            existing_files = challenge_data.get("files") or []
            if not isinstance(existing_files, list):
                raise ValueError("ctfd.files must be a list when using bundle support")
            
            # Filter out old bundles
            filtered_files = []
            for item in existing_files:
                item_path_str = item if isinstance(item, str) else item.get("path")
                if item_path_str:
                    normalized = item_path_str.replace("\\", "/")
                    if f"dist/{slug}-" in normalized:
                        continue
                filtered_files.append(item)
            
            challenge_data["files"] = [bundle_entry] + filtered_files

        # Collect attachments and build payload
        try:
            attachments = self._collect_attachments(challenge_data)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Attachment not found for CTFd upload: {exc}") from exc

        payload = self._build_payload(challenge_data, oci_reference)
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
                challenge_id=challenge_data.get("id"),
                slug=slug,
                name=payload.get("name"),
                tags=challenge_data.get("tags"),
            )
            self._log_result(result)
        except (CTFdAuthError, CTFdClientError) as exc:
            raise RuntimeError(f"Failed to synchronise challenge with CTFd: {exc}") from exc
