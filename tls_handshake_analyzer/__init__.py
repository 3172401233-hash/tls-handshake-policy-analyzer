"""Offline TLS handshake policy analyzer.

This library analyzes previously captured handshake records. It never
opens sockets and never participates in a live TLS connection.
"""

from .analyzer import (
    AnalysisReport,
    Finding,
    analyze_record,
)
from .config import PolicyConfig
from .models import (
    ClientHello,
    Extension,
    HandshakeEvent,
    HandshakeRecord,
    ServerHello,
    version_name,
)
from .parser import (
    RecordParseError,
    TruncatedRecordError,
    parse_client_hello_hex,
    parse_server_hello_hex,
)
from .suites import (
    KNOWN_CIPHER_SUITES,
    SIGNALING_SUITES,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    TLS_FALLBACK_SCSV,
    suite_name,
)

__all__ = [
    "AnalysisReport",
    "ClientHello",
    "Extension",
    "Finding",
    "HandshakeEvent",
    "HandshakeRecord",
    "KNOWN_CIPHER_SUITES",
    "PolicyConfig",
    "RecordParseError",
    "SIGNALING_SUITES",
    "ServerHello",
    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    "TLS_FALLBACK_SCSV",
    "TruncatedRecordError",
    "analyze_record",
    "parse_client_hello_hex",
    "parse_server_hello_hex",
    "suite_name",
    "version_name",
]

__version__ = "0.1.0"
