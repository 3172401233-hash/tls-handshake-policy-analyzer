"""Policy configuration for the handshake analyzer.

Weak-cipher classification is entirely config-driven: the analyzer ships
a default policy, and callers may load their own from a JSON document.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_POLICY: dict = {
    "minimum_version": 0x0303,
    "weak_categories": {
        "null_encryption": ["TLS_NULL_WITH_NULL_NULL"],
        "rc4": [
            "TLS_RSA_WITH_RC4_128_MD5",
            "TLS_RSA_WITH_RC4_128_SHA",
        ],
        "des_3des": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
        "static_rsa_key_transport": [
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
        ],
        "cbc_mode": [
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        ],
    },
    "extra_known_suites": {},
}


@dataclass
class PolicyConfig:
    """Runtime policy: weak-suite categories, version floor, suite registry."""

    minimum_version: int = 0x0303
    weak_categories: dict[str, list[str]] = field(default_factory=dict)
    extra_known_suites: dict[int, str] = field(default_factory=dict)

    def categories_for(self, suite: str) -> list[str]:
        """Weak categories that classify the given suite name."""
        return sorted(
            category
            for category, members in self.weak_categories.items()
            if suite in members
        )

    @classmethod
    def default(cls) -> "PolicyConfig":
        return cls.from_dict(DEFAULT_POLICY)

    @classmethod
    def from_dict(cls, raw: dict) -> "PolicyConfig":
        minimum = raw.get("minimum_version", 0x0303)
        if isinstance(minimum, str):
            minimum = int(minimum, 0)
        extra = {
            (int(key, 0) if isinstance(key, str) else int(key)): value
            for key, value in raw.get("extra_known_suites", {}).items()
        }
        return cls(
            minimum_version=minimum,
            weak_categories={
                str(category): list(members)
                for category, members in raw.get("weak_categories", {}).items()
            },
            extra_known_suites=extra,
        )

    @classmethod
    def from_json_file(cls, path: str | Path) -> "PolicyConfig":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))
