"""Small built-in registry of well-known cipher suites.

The registry is intentionally a curated subset of the IANA TLS Cipher
Suite registry plus the two signaling cipher suite values (SCSVs).
Deployments can extend it through the policy configuration.
"""

from __future__ import annotations

# Signaling cipher suite values (RFC 7507 / RFC 5246) — not real suites.
TLS_FALLBACK_SCSV = 0x5600
TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF

SIGNALING_SUITES = {
    TLS_FALLBACK_SCSV: "TLS_FALLBACK_SCSV",
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}

KNOWN_CIPHER_SUITES = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}


def suite_name(value: int, extra: dict[int, str] | None = None) -> str | None:
    """Return the registered name for a suite, or ``None`` if unknown."""
    if value in SIGNALING_SUITES:
        return SIGNALING_SUITES[value]
    if extra and value in extra:
        return extra[value]
    return KNOWN_CIPHER_SUITES.get(value)
