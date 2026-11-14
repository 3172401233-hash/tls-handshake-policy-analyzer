"""Synthetic-handshake tests for the offline analyzer."""

from __future__ import annotations

import unittest

from tls_handshake_analyzer import (
    ClientHello,
    Extension,
    HandshakeEvent,
    HandshakeRecord,
    PolicyConfig,
    RecordParseError,
    ServerHello,
    TLS_FALLBACK_SCSV,
    TruncatedRecordError,
    analyze_record,
    parse_client_hello_hex,
    parse_server_hello_hex,
)

TLS12 = 0x0303
TLS13 = 0x0304

AES_128_GCM = 0x009C  # TLS_RSA_WITH_AES_128_GCM_SHA256
ECDHE_RSA_GCM = 0xC02F  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS13_AES = 0x1301  # TLS_AES_128_GCM_SHA256
RC4_SHA = 0x0005  # TLS_RSA_WITH_RC4_128_SHA


def _ext(ext_type: int, data: bytes) -> tuple[int, bytes]:
    return (ext_type, data)


def build_client_hello_hex(
    legacy_version: int = TLS12,
    suites: list[int] | None = None,
    extensions: list[tuple[int, bytes]] | None = None,
) -> str:
    suites = suites if suites is not None else [TLS13_AES, ECDHE_RSA_GCM]
    extensions = extensions or []
    body = legacy_version.to_bytes(2, "big")
    body += b"\xab" * 32
    body += b"\x00"  # empty session id
    suite_blob = b"".join(s.to_bytes(2, "big") for s in suites)
    body += len(suite_blob).to_bytes(2, "big") + suite_blob
    body += b"\x01\x00"  # one compression method: null
    ext_blob = b"".join(
        t.to_bytes(2, "big") + len(d).to_bytes(2, "big") + d for t, d in extensions
    )
    body += len(ext_blob).to_bytes(2, "big") + ext_blob
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16" + b"\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record.hex()


def build_server_hello_hex(
    version: int = TLS12,
    cipher_suite: int = ECDHE_RSA_GCM,
    extensions: list[tuple[int, bytes]] | None = None,
) -> str:
    extensions = extensions or []
    body = version.to_bytes(2, "big")
    body += b"\xcd" * 32
    body += b"\x00"  # empty session id echo
    body += cipher_suite.to_bytes(2, "big")
    body += b"\x00"  # compression: null
    ext_blob = b"".join(
        t.to_bytes(2, "big") + len(d).to_bytes(2, "big") + d for t, d in extensions
    )
    body += len(ext_blob).to_bytes(2, "big") + ext_blob
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    record = b"\x16" + b"\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    return record.hex()


def supported_versions_ext(*versions: int) -> tuple[int, bytes]:
    blob = b"".join(v.to_bytes(2, "big") for v in versions)
    return _ext(43, bytes([len(blob)]) + blob)


def uint16_vector_ext(ext_type: int, values: list[int]) -> tuple[int, bytes]:
    blob = b"".join(v.to_bytes(2, "big") for v in values)
    return _ext(ext_type, len(blob).to_bytes(2, "big") + blob)


def make_record(
    client_suites: list[int],
    server_suite: int,
    client_versions: list[int] | None = None,
    server_version: int = TLS12,
    client_extensions: list[Extension] | None = None,
    server_extensions: list[Extension] | None = None,
    server_max_version: int | None = None,
) -> HandshakeRecord:
    client = ClientHello(
        legacy_version=TLS12,
        cipher_suites=client_suites,
        extensions=client_extensions or [],
        supported_versions=client_versions or [],
        signature_algorithms=[0x0403, 0x0804],
        supported_groups=[29, 23],
    )
    server = ServerHello(
        version=server_version,
        cipher_suite=server_suite,
        extensions=server_extensions or [],
    )
    return HandshakeRecord(
        client_hello=client,
        server_hello=server,
        events=[HandshakeEvent(kind="capture", detail={"source": "synthetic"})],
        server_max_version=server_max_version,
        label="synthetic",
    )


class NormalNegotiationTest(unittest.TestCase):
    def test_clean_tls13_handshake_has_no_findings(self):
        record = make_record(
            client_suites=[TLS13_AES, ECDHE_RSA_GCM],
            server_suite=TLS13_AES,
            client_versions=[TLS13, TLS12],
            server_version=TLS13,
        )
        report = analyze_record(record)
        self.assertEqual(report.findings, [])
        self.assertEqual(report.negotiated_version, TLS13)
        self.assertEqual(report.negotiated_suite_name, "TLS_AES_128_GCM_SHA256")

    def test_weak_suite_flagged_via_config_categories(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM, RC4_SHA],
            server_suite=RC4_SHA,
            client_versions=[TLS12],
            server_version=TLS12,
        )
        report = analyze_record(record)
        weak = report.by_code("WEAK_CIPHER_SUITE")
        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0].message_ref, "server_hello")
        self.assertEqual(weak[0].field, "cipher_suite")
        self.assertIn("rc4", weak[0].detail)

    def test_custom_policy_controls_weak_classification(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM, RC4_SHA],
            server_suite=RC4_SHA,
            server_version=TLS12,
        )
        policy = PolicyConfig.from_dict({"weak_categories": {}, "minimum_version": 0x0303})
        report = analyze_record(record, policy)
        self.assertEqual(report.by_code("WEAK_CIPHER_SUITE"), [])


class ClientDowngradeTest(unittest.TestCase):
    def test_deliberate_fallback_with_sentinel_last_is_accepted(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM, TLS_FALLBACK_SCSV],
            server_suite=ECDHE_RSA_GCM,
            client_versions=[TLS13, TLS12],
            server_version=TLS12,
        )
        report = analyze_record(record)
        self.assertEqual(report.by_code("DOWNGRADE_SENTINEL_MISPLACED"), [])
        self.assertEqual(report.by_code("UNGUARDED_DOWNGRADE"), [])

    def test_fallback_without_sentinel_is_noted(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM],
            server_suite=ECDHE_RSA_GCM,
            client_versions=[TLS13, TLS12],
            server_version=TLS12,
        )
        report = analyze_record(record)
        unguarded = report.by_code("UNGUARDED_DOWNGRADE")
        self.assertEqual(len(unguarded), 1)
        self.assertEqual(unguarded[0].message_ref, "client_hello")
        self.assertEqual(unguarded[0].field, "cipher_suites")

    def test_sentinel_mid_list_is_misplaced(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM, TLS_FALLBACK_SCSV, 0x009C],
            server_suite=ECDHE_RSA_GCM,
            client_versions=[TLS13, TLS12],
            server_version=TLS12,
        )
        report = analyze_record(record)
        misplaced = report.by_code("DOWNGRADE_SENTINEL_MISPLACED")
        self.assertEqual(len(misplaced), 1)
        self.assertEqual(misplaced[0].field, "cipher_suites[1]")

    def test_sentinel_present_but_no_downgrade_is_flagged(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM, TLS_FALLBACK_SCSV],
            server_suite=ECDHE_RSA_GCM,
            client_versions=[TLS12],
            server_version=TLS12,
        )
        report = analyze_record(record)
        self.assertEqual(len(report.by_code("DOWNGRADE_SENTINEL_UNNEEDED")), 1)


class TamperedServerHelloTest(unittest.TestCase):
    def test_unoffered_suite_and_inflated_version_detected(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM],
            server_suite=AES_128_GCM,
            client_versions=[TLS12],
            server_version=TLS13,
            server_max_version=TLS12,
        )
        report = analyze_record(record)
        no_common = report.by_code("NO_COMMON_CIPHER_SUITE")
        self.assertEqual(len(no_common), 1)
        self.assertEqual(no_common[0].message_ref, "server_hello")
        self.assertEqual(no_common[0].field, "cipher_suite")
        inflated = report.by_code("VERSION_ABOVE_ADVERTISED")
        self.assertEqual(len(inflated), 2)
        self.assertTrue(all(f.message_ref == "server_hello" for f in inflated))
        self.assertTrue(report.has_errors())


class DuplicateExtensionTest(unittest.TestCase):
    def test_duplicate_client_extension_detected(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM],
            server_suite=ECDHE_RSA_GCM,
            server_version=TLS12,
            client_extensions=[
                Extension(ext_type=10, data=b"\x00\x02\x00\x1d"),
                Extension(ext_type=10, data=b"\x00\x02\x00\x17"),
            ],
        )
        report = analyze_record(record)
        dup = report.by_code("DUPLICATE_EXTENSION")
        self.assertEqual(len(dup), 1)
        self.assertEqual(dup[0].message_ref, "client_hello")
        self.assertEqual(dup[0].field, "extensions")
        self.assertIn("supported_groups", dup[0].detail)


class UnknownSuiteTest(unittest.TestCase):
    def test_unknown_offered_and_selected_suites_flagged(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM, 0x00A9],
            server_suite=0x00A9,
            server_version=TLS12,
        )
        report = analyze_record(record)
        unknown = report.by_code("UNKNOWN_CIPHER_SUITE")
        self.assertEqual(len(unknown), 2)
        refs = {(f.message_ref, f.field) for f in unknown}
        self.assertIn(("client_hello", "cipher_suites[1]"), refs)
        self.assertIn(("server_hello", "cipher_suite"), refs)

    def test_configured_extra_registry_silences_unknown_warning(self):
        record = make_record(
            client_suites=[ECDHE_RSA_GCM, 0x00A9],
            server_suite=0x00A9,
            server_version=TLS12,
        )
        policy = PolicyConfig.from_dict(
            {"extra_known_suites": {"0x00a9": "TLS_PRIVATE_SUITE_X"}}
        )
        report = analyze_record(record, policy)
        self.assertEqual(report.by_code("UNKNOWN_CIPHER_SUITE"), [])
        self.assertEqual(report.negotiated_suite_name, "TLS_PRIVATE_SUITE_X")


class HexParsingTest(unittest.TestCase):
    def test_parse_client_hello_hex_extracts_lists(self):
        record_hex = build_client_hello_hex(
            suites=[TLS13_AES, ECDHE_RSA_GCM],
            extensions=[
                supported_versions_ext(TLS13, TLS12),
                uint16_vector_ext(13, [0x0403, 0x0804]),
                uint16_vector_ext(10, [29, 23]),
            ],
        )
        hello = parse_client_hello_hex(record_hex)
        self.assertEqual(hello.legacy_version, TLS12)
        self.assertEqual(hello.cipher_suites, [TLS13_AES, ECDHE_RSA_GCM])
        self.assertEqual(hello.supported_versions, [TLS13, TLS12])
        self.assertEqual(hello.signature_algorithms, [0x0403, 0x0804])
        self.assertEqual(hello.supported_groups, [29, 23])
        self.assertEqual(hello.max_version, TLS13)

    def test_parse_server_hello_hex_reads_supported_versions(self):
        record_hex = build_server_hello_hex(
            version=TLS12,
            cipher_suite=TLS13_AES,
            extensions=[_ext(43, TLS13.to_bytes(2, "big"))],
        )
        hello = parse_server_hello_hex(record_hex)
        self.assertEqual(hello.version, TLS13)
        self.assertEqual(hello.cipher_suite, TLS13_AES)

    def test_truncated_record_raises_with_offset(self):
        record_hex = build_client_hello_hex()
        truncated = record_hex[:40]  # cut inside the declared record payload
        with self.assertRaises(TruncatedRecordError) as ctx:
            parse_client_hello_hex(truncated)
        self.assertGreater(ctx.exception.needed, ctx.exception.available)

    def test_truncated_handshake_body_raises(self):
        record_hex = build_client_hello_hex()
        raw = bytes.fromhex(record_hex)
        cut = raw[: len(raw) - 10]
        with self.assertRaises(TruncatedRecordError):
            parse_client_hello_hex(cut.hex())

    def test_odd_length_hex_is_rejected(self):
        record_hex = build_client_hello_hex()
        with self.assertRaises(RecordParseError):
            parse_client_hello_hex(record_hex[:-1])

    def test_end_to_end_from_hex(self):
        ch = parse_client_hello_hex(
            build_client_hello_hex(
                suites=[TLS13_AES, ECDHE_RSA_GCM],
                extensions=[supported_versions_ext(TLS13, TLS12)],
            )
        )
        sh = parse_server_hello_hex(
            build_server_hello_hex(
                version=TLS12,
                cipher_suite=TLS13_AES,
                extensions=[_ext(43, TLS13.to_bytes(2, "big"))],
            )
        )
        report = analyze_record(HandshakeRecord(client_hello=ch, server_hello=sh))
        self.assertEqual(report.findings, [])
        self.assertEqual(report.negotiated_version, TLS13)


if __name__ == "__main__":
    unittest.main()
