"""
Helper client for interacting with a CTFd instance.

The client focuses on synchronising dynamic and dynamic_iac challenges while
avoiding unnecessary updates when the local definition matches the remote one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests


class CTFdClientError(RuntimeError):
    """Raised when a CTFd operation fails."""


class CTFdAuthError(CTFdClientError):
    """Raised when authentication with CTFd fails."""


@dataclass(frozen=True)
class AttachmentSpec:
    """Represents a file that should be attached to a challenge."""

    path: Path
    name: str
    digest: str
    size: int

    @classmethod
    def from_path(cls, path: Path, name: Optional[str] = None) -> "AttachmentSpec":
        resolved = path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Attachment path does not exist: {resolved}")
        if not resolved.is_file():
            raise FileNotFoundError(f"Attachment must be a file: {resolved}")

        digest = cls._compute_digest(resolved)
        display_name = name or resolved.name
        size = resolved.stat().st_size
        return cls(path=resolved, name=display_name, digest=digest, size=size)

    @staticmethod
    def _compute_digest(path: Path) -> str:
        sha = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                sha.update(chunk)
        return sha.hexdigest()


@dataclass(frozen=True)
class ChallengeSyncResult:
    """Details about a synchronisation attempt."""

    challenge_id: int
    status: str  # "created", "updated", "skipped"
    local_hash: str
    remote_hash: Optional[str]
    detail: str = ""


def calculate_sync_hash(payload: Dict[str, Any], attachments: Iterable[AttachmentSpec]) -> str:
    """
    Produce a deterministic hash of the payload and attachments so that we can
    decide whether an update is required.
    """
    cleaned = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sha = hashlib.sha256()
    sha.update(cleaned.encode("utf-8"))
    for attachment in sorted(attachments, key=lambda spec: spec.name):
        sha.update(attachment.name.encode("utf-8"))
        sha.update(attachment.digest.encode("utf-8"))
    return sha.hexdigest()


class CTFdClient:
    """Small helper for synchronising challenges with CTFd."""

    BUILDER_TAG_PREFIX = "builder-sync:"

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 15,
    ):
        if not base_url:
            raise ValueError("base_url is required to talk to CTFd")

        self.base_url = base_url.rstrip("/")
        self._token = token
        self._username = username
        self._password = password
        self._timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._authenticated = False

    # ------------------------------------------------------------------ #
    # Public entry points
    # ------------------------------------------------------------------ #

    def sync_challenge(
        self,
        payload: Dict[str, Any],
        attachments: List[AttachmentSpec],
        builder_hash: str,
        *,
        challenge_id: Optional[int] = None,
        slug: Optional[str] = None,
        name: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> ChallengeSyncResult:
        """
        Create or update a challenge, only applying remote changes when needed.

        Args:
            payload: Challenge fields compatible with the CTFd API.
            attachments: Files that should be attached to the challenge.
            builder_hash: Deterministic hash representing the local state.
            challenge_id: Optional fixed remote identifier.
            slug: Optional slug for lookup.
            name: Challenge name, used as a lookup fall-back.
            tags: Desired user-defined tags (without the builder hash tag).
        """
        self._authenticate()

        existing = None
        if challenge_id is not None:
            existing = self._get_challenge(challenge_id)
        else:
            existing = self._find_challenge(slug=slug, name=name or payload.get("name"))

        if existing:
            remote_hash = self._extract_builder_hash(existing)
            if remote_hash == builder_hash:
                return ChallengeSyncResult(
                    challenge_id=existing["id"],
                    status="skipped",
                    local_hash=builder_hash,
                    remote_hash=remote_hash,
                    detail="Remote challenge already matches local definition.",
                )

            self._update_challenge(existing["id"], payload, attachments, builder_hash, tags or [])
            return ChallengeSyncResult(
                challenge_id=existing["id"],
                status="updated",
                local_hash=builder_hash,
                remote_hash=remote_hash,
            )

        new_id = self._create_challenge(payload, attachments, builder_hash, tags or [])
        return ChallengeSyncResult(
            challenge_id=new_id,
            status="created",
            local_hash=builder_hash,
            remote_hash=None,
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _authenticate(self):
        if self._authenticated:
            return
        if self._token:
            self._session.headers["Authorization"] = f"Token {self._token}"
            self._authenticated = True
            return
        if self._username and self._password:
            response = self._session.post(
                self._url("/api/v1/tokens"),
                json={"name": self._username, "password": self._password},
                timeout=self._timeout,
            )
            data = self._extract_json(response)
            if not data.get("success"):
                raise CTFdAuthError(f"Authentication failed for user {self._username}")
            token = data.get("data", {}).get("token")
            if not token:
                raise CTFdAuthError("Authentication response did not contain a token")
            self._token = token
            self._session.headers["Authorization"] = f"Token {self._token}"
            self._authenticated = True
            return
        raise CTFdAuthError("Either an API token or username/password must be provided")

    def _create_challenge(
        self,
        payload: Dict[str, Any],
        attachments: List[AttachmentSpec],
        builder_hash: str,
        tags: List[str],
    ) -> int:
        body = self._filter_challenge_payload(payload)
        response = self._session.post(
            self._url("/api/v1/challenges"),
            json=body,
            timeout=self._timeout,
        )
        data = self._extract_json(response)
        if not data.get("success"):
            raise CTFdClientError(f"Failed to create challenge: {data}")

        challenge_id = data.get("data", {}).get("id")
        if challenge_id is None:
            raise CTFdClientError("Challenge creation response missing challenge id")

        self._sync_tags(challenge_id, tags, builder_hash)
        self._sync_flags(challenge_id, payload.get("flags", []))
        self._sync_hints(challenge_id, payload.get("hints", []))
        self._sync_files(challenge_id, attachments)
        return challenge_id

    def _update_challenge(
        self,
        challenge_id: int,
        payload: Dict[str, Any],
        attachments: List[AttachmentSpec],
        builder_hash: str,
        tags: List[str],
    ):
        body = self._filter_challenge_payload(payload)
        response = self._session.patch(
            self._url(f"/api/v1/challenges/{challenge_id}"),
            json=body,
            timeout=self._timeout,
        )
        data = self._extract_json(response)
        if not data.get("success"):
            raise CTFdClientError(f"Failed to update challenge {challenge_id}: {data}")

        self._sync_tags(challenge_id, tags, builder_hash)
        self._sync_flags(challenge_id, payload.get("flags", []))
        self._sync_hints(challenge_id, payload.get("hints", []))
        self._sync_files(challenge_id, attachments)

    def _sync_tags(self, challenge_id: int, user_tags: List[str], builder_hash: str):
        desired_values = set(tag.strip() for tag in user_tags or [] if tag.strip())
        desired_values.add(f"{self.BUILDER_TAG_PREFIX}{builder_hash}")

        existing = self._session.get(
            self._url(f"/api/v1/challenges/{challenge_id}/tags"),
            timeout=self._timeout,
        )
        data = self._extract_json(existing)
        remote_tags = {item["value"]: item["id"] for item in data.get("data", [])}

        for value, tag_id in remote_tags.items():
            if value not in desired_values:
                self._session.delete(
                    self._url(f"/api/v1/tags/{tag_id}"),
                    timeout=self._timeout,
                )

        for value in desired_values:
            if value not in remote_tags:
                self._session.post(
                    self._url(f"/api/v1/challenges/{challenge_id}/tags"),
                    json={"value": value},
                    timeout=self._timeout,
                )

    def _sync_flags(self, challenge_id: int, flags: List[Dict[str, Any]]):
        if flags is None:
            return

        response = self._session.get(
            self._url(f"/api/v1/challenges/{challenge_id}/flags"),
            timeout=self._timeout,
        )
        data = self._extract_json(response)
        existing = data.get("data", [])
        for flag in existing:
            self._session.delete(
                self._url(f"/api/v1/flags/{flag['id']}"),
                timeout=self._timeout,
            )

        for flag in flags:
            payload = {
                "challenge": challenge_id,
                "content": flag.get("content"),
                "type": flag.get("type", "static"),
                "data": flag.get("data"),
            }
            self._session.post(
                self._url(f"/api/v1/challenges/{challenge_id}/flags"),
                json=payload,
                timeout=self._timeout,
            )

    def _sync_hints(self, challenge_id: int, hints: List[Dict[str, Any]]):
        if hints is None:
            return

        response = self._session.get(
            self._url(f"/api/v1/challenges/{challenge_id}/hints"),
            timeout=self._timeout,
        )
        data = self._extract_json(response)
        existing = data.get("data", [])
        for hint in existing:
            self._session.delete(
                self._url(f"/api/v1/hints/{hint['id']}"),
                timeout=self._timeout,
            )

        for hint in hints:
            payload = {
                "challenge": challenge_id,
                "content": hint.get("content"),
                "cost": hint.get("cost", 0),
            }
            if hint.get("type"):
                payload["type"] = hint["type"]
            self._session.post(
                self._url(f"/api/v1/challenges/{challenge_id}/hints"),
                json=payload,
                timeout=self._timeout,
            )

    def _sync_files(self, challenge_id: int, attachments: List[AttachmentSpec]):
        response = self._session.get(
            self._url(f"/api/v1/challenges/{challenge_id}/files"),
            timeout=self._timeout,
        )
        data = self._extract_json(response)
        existing = data.get("data", [])
        for file_info in existing:
            self._session.delete(
                self._url(f"/api/v1/files/{file_info['id']}"),
                timeout=self._timeout,
            )

        for spec in attachments:
            with spec.path.open("rb") as handle:
                files = {"file": (spec.name, handle)}
                response = self._session.post(
                    self._url(f"/api/v1/challenges/{challenge_id}/files"),
                    files=files,
                    timeout=self._timeout,
                )
                upload_data = self._extract_json(response)
                if not upload_data.get("success"):
                    raise CTFdClientError(
                        f"Failed to upload attachment {spec.name}: {upload_data}"
                    )

    def _filter_challenge_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ignored_keys = {"flags", "files", "hints", "tags"}
        filtered = {
            key: value
            for key, value in payload.items()
            if key not in ignored_keys and value is not None
        }
        return filtered

    def _get_challenge(self, challenge_id: int) -> Optional[Dict[str, Any]]:
        response = self._session.get(
            self._url(f"/api/v1/challenges/{challenge_id}"),
            params={"view": "admin"},
            timeout=self._timeout,
        )
        data = self._extract_json(response)
        if not data.get("success"):
            return None
        return data.get("data")

    def _find_challenge(
        self,
        *,
        slug: Optional[str],
        name: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        if slug:
            match = self._find_challenge_by_key("slug", slug)
            if match:
                return match
        if name:
            return self._find_challenge_by_key("name", name)
        return None

    def _find_challenge_by_key(self, key: str, expected: str) -> Optional[Dict[str, Any]]:
        page = 1
        expected_lower = expected.lower()
        while True:
            response = self._session.get(
                self._url("/api/v1/challenges"),
                params={"view": "admin", "per_page": 100, "page": page},
                timeout=self._timeout,
            )
            data = self._extract_json(response)
            if not data.get("success"):
                raise CTFdClientError(f"Failed to list challenges: {data}")
            challenges = data.get("data", [])
            for chal in challenges:
                value = (chal.get(key) or "").lower()
                if value == expected_lower:
                    return self._get_challenge(chal["id"])
            pagination = data.get("meta", {}).get("pagination", {})
            next_page = pagination.get("next")
            if not next_page:
                break
            page = next_page
        return None

    def _extract_builder_hash(self, challenge: Dict[str, Any]) -> Optional[str]:
        tags = challenge.get("tags", [])
        for tag in tags:
            value = tag.get("value", "")
            if value.startswith(self.BUILDER_TAG_PREFIX):
                return value[len(self.BUILDER_TAG_PREFIX) :]
        return None

    # ------------------------------------------------------------------ #
    # Utilities
    # ------------------------------------------------------------------ #

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url}{path}"

    @staticmethod
    def _extract_json(response: requests.Response) -> Dict[str, Any]:
        try:
            return response.json()
        except ValueError as exc:
            raise CTFdClientError(
                f"CTFd response was not valid JSON: {response.text}"
            ) from exc

