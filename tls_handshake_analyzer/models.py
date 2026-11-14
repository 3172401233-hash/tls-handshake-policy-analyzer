"""Structured representations of offline TLS handshake records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


TLS_VERSION_NAMES = {
    0x0300: "SSL3.0",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}


def version_name(value: int) -> str:
    return TLS_VERSION_NAMES.get(value, f"0x{value:04x}")


EXTENSION_NAMES = {
    0: "server_name",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp",
    21: "padding",
    23: "session_ticket",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
    65281: "renegotiation_info",
}


@dataclass
class Extension:
    """A single extension as observed on the wire."""

    ext_type: int
    data: bytes = b""

    @property
    def name(self) -> str:
        return EXTENSION_NAMES.get(self.ext_type, f"unknown({self.ext_type})")


@dataclass
class ClientHello:
    """Structured ClientHello extracted from a handshake record."""

    legacy_version: int
    cipher_suites: list[int]
    extensions: list[Extension] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    random: bytes = b""
    session_id: bytes = b""
    compression_methods: list[int] = field(default_factory=list)

    @property
    def max_version(self) -> int:
        """Highest version the client claims to support."""
        if self.supported_versions:
            return max(self.supported_versions)
        return self.legacy_version

    def extension_types(self) -> list[int]:
        return [ext.ext_type for ext in self.extensions]


@dataclass
class ServerHello:
    """Structured ServerHello extracted from a handshake record."""

    version: int
    cipher_suite: int
    extensions: list[Extension] = field(default_factory=list)
    random: bytes = b""
    session_id_echo: bytes = b""
    compression_method: int = 0

    def extension_types(self) -> list[int]:
        return [ext.ext_type for ext in self.extensions]


@dataclass
class HandshakeEvent:
    """A free-form process event observed between the two hello messages.

    ``kind`` is a short tag such as ``"alert"``, ``"retransmit"`` or
    ``"middlebox_note"``; ``detail`` carries arbitrary structured context.
    """

    kind: str
    detail: dict[str, Any] = field(default_factory=dict)
    sequence: int = 0


@dataclass
class HandshakeRecord:
    """One complete offline handshake observation."""

    client_hello: ClientHello
    server_hello: Optional[ServerHello] = None
    events: list[HandshakeEvent] = field(default_factory=list)
    server_max_version: Optional[int] = None
    label: str = ""

    def server_declared_max(self) -> Optional[int]:
        """Highest version the server side claims to support, if known."""
        if self.server_max_version is not None:
            return self.server_max_version
        if self.server_hello is not None:
            return self.server_hello.version
        return None
