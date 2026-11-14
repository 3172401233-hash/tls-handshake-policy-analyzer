"""Parsers that turn captured hex handshake records into structured models.

Only record analysis is performed — nothing here opens sockets or speaks
TLS to a peer.
"""

from __future__ import annotations

from .models import ClientHello, Extension, ServerHello


class RecordParseError(ValueError):
    """Base error for malformed handshake records."""


class TruncatedRecordError(RecordParseError):
    """Raised when a record ends before a declared length is satisfied."""

    def __init__(self, context: str, offset: int, needed: int, available: int):
        self.context = context
        self.offset = offset
        self.needed = needed
        self.available = available
        super().__init__(
            f"truncated record while reading {context} at offset {offset}: "
            f"need {needed} byte(s), only {available} available"
        )


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, count: int, context: str) -> bytes:
        if self.remaining() < count:
            raise TruncatedRecordError(context, self.pos, count, self.remaining())
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def uint8(self, context: str) -> int:
        return self.take(1, context)[0]

    def uint16(self, context: str) -> int:
        return int.from_bytes(self.take(2, context), "big")

    def uint24(self, context: str) -> int:
        return int.from_bytes(self.take(3, context), "big")


def _decode_hex(record_hex: str) -> bytes:
    text = "".join(record_hex.split())
    if text.startswith("0x"):
        text = text[2:]
    if len(text) % 2 != 0:
        raise RecordParseError(
            f"hex record has odd length ({len(text)} digits); "
            "the capture may be truncated mid-byte"
        )
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise RecordParseError(f"invalid hex in record: {exc}") from exc


def _unwrap_handshake(record_hex: str, expected_handshake_type: int) -> _Reader:
    raw = _decode_hex(record_hex)
    reader = _Reader(raw)
    content_type = reader.uint8("record content type")
    if content_type != 22:
        raise RecordParseError(
            f"expected a handshake record (content type 22), got {content_type}"
        )
    reader.uint16("record legacy version")
    record_length = reader.uint16("record length")
    if reader.remaining() < record_length:
        raise TruncatedRecordError(
            "record payload", reader.pos, record_length, reader.remaining()
        )
    handshake_type = reader.uint8("handshake message type")
    if handshake_type != expected_handshake_type:
        raise RecordParseError(
            f"expected handshake type {expected_handshake_type}, "
            f"got {handshake_type}"
        )
    body_length = reader.uint24("handshake body length")
    if reader.remaining() < body_length:
        raise TruncatedRecordError(
            "handshake body", reader.pos, body_length, reader.remaining()
        )
    return reader


def _read_extensions(reader: _Reader) -> list[Extension]:
    extensions: list[Extension] = []
    if reader.remaining() == 0:
        return extensions
    total = reader.uint16("extensions length")
    blob = _Reader(reader.take(total, "extensions block"))
    while blob.remaining() > 0:
        ext_type = blob.uint16("extension type")
        ext_len = blob.uint16("extension length")
        data = blob.take(ext_len, f"extension {ext_type} data")
        extensions.append(Extension(ext_type=ext_type, data=data))
    return extensions


def _extension_uint16_list(extensions: list[Extension], ext_type: int) -> list[int]:
    for ext in extensions:
        if ext.ext_type != ext_type or not ext.data:
            continue
        blob = _Reader(ext.data)
        # supported_versions in ClientHello uses a 1-byte length prefix;
        # supported_groups / signature_algorithms use a 2-byte prefix.
        if ext_type == 43:
            count = blob.uint8("supported_versions length") // 2
        else:
            count = blob.uint16("vector length") // 2
        return [blob.uint16("vector entry") for _ in range(count)]
    return []


def parse_client_hello_hex(record_hex: str) -> ClientHello:
    """Parse a hex-encoded TLS record carrying a ClientHello."""
    reader = _unwrap_handshake(record_hex, expected_handshake_type=1)
    legacy_version = reader.uint16("client legacy_version")
    random = reader.take(32, "client random")
    session_id = reader.take(reader.uint8("session id length"), "session id")
    suites_len = reader.uint16("cipher suites length")
    suites_blob = _Reader(reader.take(suites_len, "cipher suites"))
    cipher_suites = []
    while suites_blob.remaining() >= 2:
        cipher_suites.append(suites_blob.uint16("cipher suite"))
    comp_len = reader.uint8("compression methods length")
    compression = list(reader.take(comp_len, "compression methods"))
    extensions = _read_extensions(reader)
    return ClientHello(
        legacy_version=legacy_version,
        cipher_suites=cipher_suites,
        extensions=extensions,
        supported_versions=_extension_uint16_list(extensions, 43),
        signature_algorithms=_extension_uint16_list(extensions, 13),
        supported_groups=_extension_uint16_list(extensions, 10),
        random=random,
        session_id=session_id,
        compression_methods=compression,
    )


def parse_server_hello_hex(record_hex: str) -> ServerHello:
    """Parse a hex-encoded TLS record carrying a ServerHello."""
    reader = _unwrap_handshake(record_hex, expected_handshake_type=2)
    version = reader.uint16("server version")
    random = reader.take(32, "server random")
    session_id_echo = reader.take(
        reader.uint8("session id echo length"), "session id echo"
    )
    cipher_suite = reader.uint16("server selected cipher suite")
    compression = reader.uint8("server compression method")
    extensions = _read_extensions(reader)
    for ext in extensions:
        # In a ServerHello, supported_versions carries one selected version.
        if ext.ext_type == 43 and len(ext.data) == 2:
            version = int.from_bytes(ext.data, "big")
    return ServerHello(
        version=version,
        cipher_suite=cipher_suite,
        extensions=extensions,
        random=random,
        session_id_echo=session_id_echo,
        compression_method=compression,
    )
