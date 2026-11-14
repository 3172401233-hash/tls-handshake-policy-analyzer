"""Offline analysis of captured TLS handshake records.

Every finding cites the exact message and field that triggered it, so an
operator can jump straight back to the captured evidence.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .config import PolicyConfig
from .models import (
    ClientHello,
    HandshakeRecord,
    ServerHello,
    version_name,
)
from .suites import (
    SIGNALING_SUITES,
    TLS_FALLBACK_SCSV,
    suite_name,
)

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"


@dataclass
class Finding:
    """One observation produced by a check.

    ``message_ref`` names the message that triggered the check
    (``client_hello``, ``server_hello`` or ``record``) and ``field`` the
    precise field inside it, so results always point at concrete evidence.
    """

    code: str
    severity: str
    message_ref: str
    field: str
    detail: str

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.code} "
            f"({self.message_ref}.{self.field}): {self.detail}"
        )


@dataclass
class AnalysisReport:
    """Aggregated result for one handshake record."""

    findings: list[Finding] = field(default_factory=list)
    negotiated_version: int | None = None
    negotiated_suite: int | None = None
    negotiated_suite_name: str | None = None

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_WARNING]

    def by_code(self, code: str) -> list[Finding]:
        return [f for f in self.findings if f.code == code]

    def has_errors(self) -> bool:
        return any(f.severity == SEVERITY_ERROR for f in self.findings)


def _check_duplicate_extensions(
    message_ref: str,
    hello: ClientHello | ServerHello,
    findings: list[Finding],
) -> None:
    counts = Counter(hello.extension_types())
    for ext_type, count in sorted(counts.items()):
        if count > 1:
            name = next(
                ext.name for ext in hello.extensions if ext.ext_type == ext_type
            )
            findings.append(
                Finding(
                    code="DUPLICATE_EXTENSION",
                    severity=SEVERITY_ERROR,
                    message_ref=message_ref,
                    field="extensions",
                    detail=(
                        f"extension {name} (type {ext_type}) appears "
                        f"{count} times; TLS forbids duplicate extensions"
                    ),
                )
            )


def _check_unknown_suites(
    record: HandshakeRecord,
    policy: PolicyConfig,
    findings: list[Finding],
) -> None:
    extra = policy.extra_known_suites
    for index, value in enumerate(record.client_hello.cipher_suites):
        if suite_name(value, extra) is None:
            findings.append(
                Finding(
                    code="UNKNOWN_CIPHER_SUITE",
                    severity=SEVERITY_WARNING,
                    message_ref="client_hello",
                    field=f"cipher_suites[{index}]",
                    detail=(
                        f"offered suite 0x{value:04x} is not in the known "
                        "suite registry or the configured extra registry"
                    ),
                )
            )
    server = record.server_hello
    if server is not None and suite_name(server.cipher_suite, extra) is None:
        findings.append(
            Finding(
                code="UNKNOWN_CIPHER_SUITE",
                severity=SEVERITY_WARNING,
                message_ref="server_hello",
                field="cipher_suite",
                detail=(
                    f"selected suite 0x{server.cipher_suite:04x} is not in "
                    "the known suite registry or the configured extra registry"
                ),
            )
        )


def _check_fallback_sentinel(
    record: HandshakeRecord, findings: list[Finding]
) -> None:
    suites = record.client_hello.cipher_suites
    if TLS_FALLBACK_SCSV not in suites:
        server = record.server_hello
        if server is not None and server.version < record.client_hello.max_version:
            findings.append(
                Finding(
                    code="UNGUARDED_DOWNGRADE",
                    severity=SEVERITY_INFO,
                    message_ref="client_hello",
                    field="cipher_suites",
                    detail=(
                        f"client advertised up to "
                        f"{version_name(record.client_hello.max_version)} but "
                        f"negotiated {version_name(server.version)} without "
                        "sending TLS_FALLBACK_SCSV; a deliberate client "
                        "fallback should carry the sentinel"
                    ),
                )
            )
        return
    positions = [i for i, v in enumerate(suites) if v == TLS_FALLBACK_SCSV]
    if len(positions) > 1:
        findings.append(
            Finding(
                code="DOWNGRADE_SENTINEL_MISPLACED",
                severity=SEVERITY_ERROR,
                message_ref="client_hello",
                field="cipher_suites",
                detail=(
                    f"TLS_FALLBACK_SCSV appears {len(positions)} times "
                    f"(indexes {positions}); it must appear at most once"
                ),
            )
        )
    elif positions[0] != len(suites) - 1:
        findings.append(
            Finding(
                code="DOWNGRADE_SENTINEL_MISPLACED",
                severity=SEVERITY_ERROR,
                message_ref="client_hello",
                field=f"cipher_suites[{positions[0]}]",
                detail=(
                    "TLS_FALLBACK_SCSV must be the last cipher suite "
                    f"(found at index {positions[0]} of {len(suites)}); "
                    "a mid-list sentinel suggests a rewritten ClientHello"
                ),
            )
        )
    server = record.server_hello
    if server is not None and server.version >= record.client_hello.max_version:
        findings.append(
            Finding(
                code="DOWNGRADE_SENTINEL_UNNEEDED",
                severity=SEVERITY_WARNING,
                message_ref="client_hello",
                field="cipher_suites",
                detail=(
                    "TLS_FALLBACK_SCSV present but the negotiated version "
                    f"{version_name(server.version)} is not below the "
                    "client's advertised maximum "
                    f"{version_name(record.client_hello.max_version)}"
                ),
            )
        )


def _check_negotiation(
    record: HandshakeRecord,
    policy: PolicyConfig,
    findings: list[Finding],
) -> None:
    server = record.server_hello
    if server is None:
        return
    client = record.client_hello

    if server.cipher_suite in SIGNALING_SUITES:
        findings.append(
            Finding(
                code="NO_COMMON_CIPHER_SUITE",
                severity=SEVERITY_ERROR,
                message_ref="server_hello",
                field="cipher_suite",
                detail=(
                    f"server selected signaling value "
                    f"{SIGNALING_SUITES[server.cipher_suite]}, which is not "
                    "a real cipher suite"
                ),
            )
        )
    elif server.cipher_suite not in client.cipher_suites:
        findings.append(
            Finding(
                code="NO_COMMON_CIPHER_SUITE",
                severity=SEVERITY_ERROR,
                message_ref="server_hello",
                field="cipher_suite",
                detail=(
                    f"server selected 0x{server.cipher_suite:04x}, which the "
                    "client never offered; the ServerHello may have been "
                    "rewritten in transit"
                ),
            )
        )

    client_max = client.max_version
    if server.version > client_max:
        findings.append(
            Finding(
                code="VERSION_ABOVE_ADVERTISED",
                severity=SEVERITY_ERROR,
                message_ref="server_hello",
                field="version",
                detail=(
                    f"negotiated {version_name(server.version)} exceeds the "
                    f"client's advertised maximum {version_name(client_max)}"
                ),
            )
        )
    server_max = record.server_declared_max()
    if server_max is not None and server.version > server_max:
        findings.append(
            Finding(
                code="VERSION_ABOVE_ADVERTISED",
                severity=SEVERITY_ERROR,
                message_ref="server_hello",
                field="version",
                detail=(
                    f"negotiated {version_name(server.version)} exceeds the "
                    f"server's declared maximum {version_name(server_max)}"
                ),
            )
        )
    if server.version < policy.minimum_version:
        findings.append(
            Finding(
                code="BELOW_MINIMUM_VERSION",
                severity=SEVERITY_WARNING,
                message_ref="server_hello",
                field="version",
                detail=(
                    f"negotiated {version_name(server.version)} is below the "
                    f"policy floor {version_name(policy.minimum_version)}"
                ),
            )
        )

    name = suite_name(server.cipher_suite, policy.extra_known_suites)
    if name is not None and server.cipher_suite not in SIGNALING_SUITES:
        categories = policy.categories_for(name)
        if categories:
            findings.append(
                Finding(
                    code="WEAK_CIPHER_SUITE",
                    severity=SEVERITY_WARNING,
                    message_ref="server_hello",
                    field="cipher_suite",
                    detail=(
                        f"negotiated suite {name} is classified weak by "
                        f"policy categories: {', '.join(categories)}"
                    ),
                )
            )


def analyze_record(
    record: HandshakeRecord, policy: PolicyConfig | None = None
) -> AnalysisReport:
    """Run all checks against one offline handshake record."""
    policy = policy or PolicyConfig.default()
    findings: list[Finding] = []

    _check_duplicate_extensions("client_hello", record.client_hello, findings)
    if record.server_hello is not None:
        _check_duplicate_extensions("server_hello", record.server_hello, findings)
    _check_unknown_suites(record, policy, findings)
    _check_fallback_sentinel(record, findings)
    _check_negotiation(record, policy, findings)

    report = AnalysisReport(findings=findings)
    if record.server_hello is not None:
        report.negotiated_version = record.server_hello.version
        report.negotiated_suite = record.server_hello.cipher_suite
        report.negotiated_suite_name = suite_name(
            record.server_hello.cipher_suite, policy.extra_known_suites
        )
    return report
