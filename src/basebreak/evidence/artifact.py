"""Content-addressed artifact hashing and canonical serialization.

Implements provider-neutral deterministic artifact identity primitives.
Artifact identity derives deterministically from artifact bytes using SHA-256.
Ensures exact byte semantics, canonical serialization reuse, and strict validation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.domain.serialization import to_canonical_bytes

SHA256_HEX_REGEX = re.compile(r"^[0-9a-f]{64}$")


class DigestAlgorithm(str, Enum):
    """Supported cryptographic hash algorithms for content addressing."""

    SHA256 = "sha256"


@dataclass(frozen=True)
class ArtifactDigest:
    """Immutable content-addressed cryptographic digest.

    Attributes:
        algorithm: The cryptographic digest algorithm used.
        value: Lowercase hexadecimal digest string.
        byte_length: Original content length in bytes (non-negative integer).
    """

    algorithm: DigestAlgorithm
    value: str
    byte_length: int

    def __post_init__(self) -> None:
        if not isinstance(self.algorithm, DigestAlgorithm):
            raise TypeError(
                "algorithm must be a DigestAlgorithm enum instance, "
                f"got {type(self.algorithm).__name__}"
            )
        if not isinstance(self.value, str):
            raise TypeError(f"value must be a str, got {type(self.value).__name__}")
        if self.algorithm == DigestAlgorithm.SHA256:
            if not SHA256_HEX_REGEX.match(self.value):
                raise ValueError(
                    f"Invalid SHA-256 digest: {self.value!r}. "
                    "Must be exactly 64 lowercase hexadecimal characters."
                )
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        if isinstance(self.byte_length, bool) or not isinstance(self.byte_length, int):
            raise TypeError(
                f"byte_length must be an int (not bool), got {type(self.byte_length).__name__}"
            )
        if self.byte_length < 0:
            raise ValueError(f"byte_length must be non-negative, got {self.byte_length}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize digest to deterministic dictionary."""
        return {
            "algorithm": self.algorithm.value,
            "byte_length": self.byte_length,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArtifactDigest:
        """Deserialize digest from dictionary with strict validation."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")
        if "algorithm" not in data or "value" not in data or "byte_length" not in data:
            raise KeyError(
                "Missing required keys for ArtifactDigest ('algorithm', 'value', 'byte_length')"
            )
        return cls(
            algorithm=DigestAlgorithm(data["algorithm"]),
            value=data["value"],
            byte_length=data["byte_length"],
        )


@dataclass(frozen=True)
class ArtifactReference:
    """Immutable reference to a content-addressed artifact.

    Distinguishes reference identity from raw content and avoids storing
    arbitrary mutable filesystem paths as authoritative identity.

    Attributes:
        digest: The content-addressed cryptographic digest.
        media_type: Optional IANA media type or MIME string.
    """

    digest: ArtifactDigest
    media_type: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.digest, ArtifactDigest):
            raise TypeError(f"digest must be an ArtifactDigest, got {type(self.digest).__name__}")
        if self.media_type is not None:
            if not isinstance(self.media_type, str):
                raise TypeError(
                    f"media_type must be a str or None, got {type(self.media_type).__name__}"
                )
            if not self.media_type.strip():
                raise ValueError("media_type cannot be empty or whitespace only")

    def to_dict(self) -> dict[str, Any]:
        """Serialize reference to deterministic dictionary."""
        return {
            "digest": self.digest.to_dict(),
            "media_type": self.media_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArtifactReference:
        """Deserialize reference from dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")
        if "digest" not in data:
            raise KeyError("Missing required key 'digest'")
        digest_data = data["digest"]
        if not isinstance(digest_data, dict):
            raise TypeError(f"digest must be a dict, got {type(digest_data).__name__}")
        return cls(
            digest=ArtifactDigest.from_dict(digest_data),
            media_type=data.get("media_type"),
        )


@dataclass(frozen=True)
class Artifact:
    """Immutable content-addressed artifact containing raw content and verified digest.

    Attributes:
        content: Raw binary content bytes.
        digest: Cryptographic digest matching the exact content bytes.
        media_type: Optional media type metadata.
    """

    content: bytes
    digest: ArtifactDigest
    media_type: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.content, (bytes, bytearray)):
            raise TypeError(f"content must be bytes, got {type(self.content).__name__}")
        content_bytes = bytes(self.content)
        if type(self.content) is not bytes:
            object.__setattr__(self, "content", content_bytes)

        if not isinstance(self.digest, ArtifactDigest):
            raise TypeError(f"digest must be an ArtifactDigest, got {type(self.digest).__name__}")

        expected_digest = compute_bytes_digest(content_bytes, algorithm=self.digest.algorithm)
        if self.digest != expected_digest:
            raise ValueError(
                f"Artifact digest mismatch: declared {self.digest.value} "
                f"(len {self.digest.byte_length}) does not match actual "
                f"content digest {expected_digest.value} (len {expected_digest.byte_length})"
            )

        if self.media_type is not None:
            if not isinstance(self.media_type, str):
                raise TypeError(
                    f"media_type must be a str or None, got {type(self.media_type).__name__}"
                )
            if not self.media_type.strip():
                raise ValueError("media_type cannot be empty or whitespace only")

    @property
    def reference(self) -> ArtifactReference:
        """Return the immutable reference identity for this artifact."""
        return ArtifactReference(digest=self.digest, media_type=self.media_type)


def compute_bytes_digest(
    data: bytes | bytearray,
    algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
) -> ArtifactDigest:
    """Compute cryptographic digest from exact raw bytes.

    Never normalizes or alters arbitrary binary bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes or bytearray, got {type(data).__name__}")
    if not isinstance(algorithm, DigestAlgorithm):
        raise TypeError(f"algorithm must be a DigestAlgorithm, got {type(algorithm).__name__}")

    raw_bytes = bytes(data)
    if algorithm == DigestAlgorithm.SHA256:
        hex_digest = hashlib.sha256(raw_bytes).hexdigest()
        return ArtifactDigest(
            algorithm=algorithm,
            value=hex_digest,
            byte_length=len(raw_bytes),
        )
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def compute_text_digest(
    text: str,
    encoding: str = "utf-8",
    algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
) -> ArtifactDigest:
    """Compute cryptographic digest from text, explicitly encoding as specified (default UTF-8)."""
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    if encoding != "utf-8":
        raise ValueError(f"Basebreak canonical text encoding is strictly 'utf-8', got {encoding!r}")
    return compute_bytes_digest(text.encode(encoding), algorithm=algorithm)


def compute_domain_digest(
    domain_obj: Any,
    algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
) -> ArtifactDigest:
    """Compute cryptographic digest for domain object via canonical P-02 serialization.

    Pipeline: domain object -> canonical bytes -> cryptographic digest.
    Guarantees key sorting, envelope versioning, and strict determinism.
    """
    canonical_bytes = to_canonical_bytes(domain_obj)
    return compute_bytes_digest(canonical_bytes, algorithm=algorithm)


def artifact_from_bytes(
    content: bytes | bytearray,
    media_type: str | None = None,
    algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
) -> Artifact:
    """Construct a validated Artifact from raw bytes."""
    raw_bytes = bytes(content)
    digest = compute_bytes_digest(raw_bytes, algorithm=algorithm)
    return Artifact(content=raw_bytes, digest=digest, media_type=media_type)


def artifact_from_text(
    text: str,
    media_type: str = "text/plain; charset=utf-8",
    algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
) -> Artifact:
    """Construct a validated Artifact from text encoded explicitly as UTF-8."""
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    return artifact_from_bytes(text.encode("utf-8"), media_type=media_type, algorithm=algorithm)


def artifact_from_domain_object(
    obj: Any,
    media_type: str = "application/json",
    algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
) -> Artifact:
    """Construct a validated Artifact from a canonical domain object."""
    canonical_bytes = to_canonical_bytes(obj)
    return artifact_from_bytes(canonical_bytes, media_type=media_type, algorithm=algorithm)


def to_canonical_artifact_json(item: ArtifactDigest | ArtifactReference) -> str:
    """Serialize an artifact digest or reference to canonical JSON."""
    if isinstance(item, (ArtifactDigest, ArtifactReference)):
        data = item.to_dict()
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    raise TypeError(f"Unsupported artifact item type: {type(item).__name__}")
