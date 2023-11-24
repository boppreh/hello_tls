from multiprocessing.pool import ThreadPool
from typing import Sequence, Any, Callable, Optional, List, Tuple
from collections.abc import Iterator
from functools import total_ordering
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass
import dataclasses
import json
import logging
import socket
import struct
import re
import sys

logger = logging.getLogger(__name__)

# Default socket connection timeout, in seconds.
DEFAULT_TIMEOUT: float = 2
# Default number of workers/threads/concurrent connections to use.
DEFAULT_MAX_WORKERS: int = 6

@total_ordering
class Protocol(Enum):
    # Keep protocols in order of preference.
    TLS1_3 = b"\x03\x04"
    TLS1_2 = b"\x03\x03"
    TLS1_1 = b"\x03\x02"
    TLS1_0 = b"\x03\x01"
    SSLv3 = b"\x03\x00"

    def __repr__(self):
        return self.name
    def __lt__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self.value < other.value

class RecordType(Enum):
    INVALID = b'\x00' # Unused in this script.
    CHANGE_CIPHER_SPEC = b'\x14' # Unused in this script.
    ALERT = b'\x15'
    HANDSHAKE = b'\x16'
    APPLICATION_DATA = b'\x17' # Unused in this script.

class HandshakeType(Enum):
    client_hello = b'\x01'
    server_hello = b'\x02'
    new_session_ticket = b'\x04'
    end_of_early_data = b'\x05'
    encrypted_extensions = b'\x08'
    certificate = b'\x0B'
    server_key_exchange = b'\x0C'
    certificate_request = b'\x0D'
    server_hello_done = b'\x0E'
    certificate_verify = b'\x0F'
    finished = b'\x14'
    certificate_status = b'\x16'
    key_update = b'\x18'
    message_hash = b'\x19'

class Group(Enum):
    def __new__(cls, value, *rest, **kwds):
        obj = object.__new__(cls)
        obj._value_ = value
        return obj
    # Annotate each group with whether it's a PQ group.
    def __init__(self, _: bytes, is_pq: bool = False):
        self.is_pq = is_pq
    def __repr__(self):
        return self.name
    
    sect163k1 = b'\x00\x01'
    sect163r1 = b'\x00\x02'
    sect163r2 = b'\x00\x03'
    sect193r1 = b'\x00\x04'
    sect193r2 = b'\x00\x05'
    sect233k1 = b'\x00\x06'
    sect233r1 = b'\x00\x07'
    sect239k1 = b'\x00\x08'
    sect283k1 = b'\x00\x09'
    sect283r1 = b'\x00\x0a'
    sect409k1 = b'\x00\x0b'
    sect409r1 = b'\x00\x0c'
    sect571k1 = b'\x00\x0d'
    sect571r1 = b'\x00\x0e'
    secp160k1 = b'\x00\x0f'
    secp160r1 = b'\x00\x10'
    secp160r2 = b'\x00\x11'
    secp192k1 = b'\x00\x12'
    secp192r1 = b'\x00\x13'
    secp224k1 = b'\x00\x14'
    secp224r1 = b'\x00\x15'
    secp256k1 = b'\x00\x16'
    secp256r1 = b'\x00\x17'
    secp384r1 = b'\x00\x18'
    secp521r1 = b'\x00\x19'
    brainpoolP256r1 = b'\x00\x1a'
    brainpoolP384r1 = b'\x00\x1b'
    brainpoolP512r1 = b'\x00\x1c'
    x25519 = b'\x00\x1d'
    x448 = b'\x00\x1e'
    brainpoolP256r1tls13 = b'\x00\x1f'
    brainpoolP384r1tls13 = b'\x00\x20'
    brainpoolP512r1tls13 = b'\x00\x21'
    GC256A = b'\x00\x22'
    GC256B = b'\x00\x23'
    GC256C = b'\x00\x24'
    GC256D = b'\x00\x25'
    GC512A = b'\x00\x26'
    GC512B = b'\x00\x27'
    GC512C = b'\x00\x28'
    curveSM2 = b'\x00\x29'
    ffdhe2048 = b'\x01\x00'
    ffdhe3072 = b'\x01\x01'
    ffdhe4096 = b'\x01\x02'
    ffdhe6144 = b'\x01\x03'
    ffdhe8192 = b'\x01\x04'
    arbitrary_explicit_prime_curves = b'\xff\x01'
    arbitrary_explicit_char2_curves = b'\xff\x02'

    # Somewhat common post-quantum groups, not yet standardized:
    X25519Kyber768Draft00 = b'\x63\x99', True
    X25519Kyber768Draft00_obsolete = b'\xfe\x31', True
    X25519Kyber512Draft00 = b'\xfe\x30', True
    SecP256r1Kyber768Draft00 = b'\x63\x9a', True

    # Long list of unusual post-quantum groups from liboqs:
    # https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md?plain=1#L13
    frodo640aes = b'\x02\x00', True
    p256_frodo640aes = b'\x2F\x00', True
    x25519_frodo640aes = b'\x2F\x80', True
    frodo640shake = b'\x02\x01', True
    p256_frodo640shake = b'\x2F\x01', True
    x25519_frodo640shake = b'\x2F\x81', True
    frodo976aes = b'\x02\x02', True
    p384_frodo976aes = b'\x2F\x02', True
    x448_frodo976aes = b'\x2F\x82', True
    frodo976shake = b'\x02\x03', True
    p384_frodo976shake = b'\x2F\x03', True
    x448_frodo976shake = b'\x2F\x83', True
    frodo1344aes = b'\x02\x04', True
    p521_frodo1344aes = b'\x2F\x04', True
    frodo1344shake = b'\x02\x05', True
    p521_frodo1344shake = b'\x2F\x05', True
    kyber512 = b'\x02\x3A', True
    p256_kyber512 = b'\x2F\x3A', True
    x25519_kyber512 = b'\x2F\x39', True
    kyber768 = b'\x02\x3C', True
    p384_kyber768 = b'\x2F\x3C', True
    x448_kyber768 = b'\x2F\x90', True
    kyber1024 = b'\x02\x3D', True
    p521_kyber1024 = b'\x2F\x3D', True
    bikel1 = b'\x02\x41', True
    p256_bikel1 = b'\x2F\x41', True
    x25519_bikel1 = b'\x2F\xAE', True
    bikel3 = b'\x02\x42', True
    p384_bikel3 = b'\x2F\x42', True
    x448_bikel3 = b'\x2F\xAF', True
    bikel5 = b'\x02\x43', True
    p521_bikel5 = b'\x2F\x43', True
    hqc128 = b'\x02\x2C', True
    p256_hqc128 = b'\x2F\x2C', True
    x25519_hqc128 = b'\x2F\xAC', True
    hqc192 = b'\x02\x2D', True
    p384_hqc192 = b'\x2F\x2D', True
    x448_hqc192 = b'\x2F\xAD', True
    hqc256 = b'\x02\x2E', True
    p521_hqc256 = b'\x2F\x2E', True
    dilithium2 = b'\xfe\xa0', True
    p256_dilithium2 = b'\xfe\xa1', True
    rsa3072_dilithium2 = b'\xfe\xa2', True
    dilithium3 = b'\xfe\xa3', True
    p384_dilithium3 = b'\xfe\xa4', True
    dilithium5 = b'\xfe\xa5', True
    p521_dilithium5 = b'\xfe\xa6', True
    falcon512 = b'\xfe\xae', True
    p256_falcon512 = b'\xfe\xaf', True
    rsa3072_falcon512 = b'\xfe\xb0', True
    falcon1024 = b'\xfe\xb1', True
    p521_falcon1024 = b'\xfe\xb2', True
    sphincssha2128fsimple = b'\xfe\xb3', True
    p256_sphincssha2128fsimple = b'\xfe\xb4', True
    rsa3072_sphincssha2128fsimple = b'\xfe\xb5', True
    sphincssha2128ssimple = b'\xfe\xb6', True
    p256_sphincssha2128ssimple = b'\xfe\xb7', True
    rsa3072_sphincssha2128ssimple = b'\xfe\xb8', True
    sphincssha2192fsimple = b'\xfe\xb9', True
    p384_sphincssha2192fsimple = b'\xfe\xba', True
    sphincssha2192ssimple = b'\xfe\xbb', True
    p384_sphincssha2192ssimple = b'\xfe\xbc', True
    sphincssha2256fsimple = b'\xfe\xbd', True
    p521_sphincssha2256fsimple = b'\xfe\xbe', True
    sphincssha2256ssimple = b'\xfe\xc0', True
    p521_sphincssha2256ssimple = b'\xfe\xc1', True
    sphincsshake128fsimple = b'\xfe\xc2', True
    p256_sphincsshake128fsimple = b'\xfe\xc3', True
    rsa3072_sphincsshake128fsimple = b'\xfe\xc4', True
    sphincsshake128ssimple = b'\xfe\xc5', True
    p256_sphincsshake128ssimple = b'\xfe\xc6', True
    rsa3072_sphincsshake128ssimple = b'\xfe\xc7', True
    sphincsshake192fsimple = b'\xfe\xc8', True
    p384_sphincsshake192fsimple = b'\xfe\xc9', True
    sphincsshake192ssimple = b'\xfe\xca', True
    p384_sphincsshake192ssimple = b'\xfe\xcb', True
    sphincsshake256fsimple = b'\xfe\xcc', True
    p521_sphincsshake256fsimple = b'\xfe\xcd', True
    sphincsshake256ssimple = b'\xfe\xce', True
    p521_sphincsshake256ssimple = b'\xfe\xcf', True

class CipherSuite(Enum):
    def __repr__(self):
        return self.name
    def __new__(cls, value, *rest, **kwds):
        obj = object.__new__(cls)
        obj._value_ = value
        return obj
    # Annotate each cipher suite with the protocols it's supported at.
    # Default to all but TLS 1.3, because that's the most common.
    def __init__(self, _: bytes, protocols: Sequence[Protocol] = (Protocol.SSLv3, Protocol.TLS1_0, Protocol.TLS1_1, Protocol.TLS1_2)):
        self.protocols = protocols

    # Pseudo cipher suite, not actually picked.
    #TLS_EMPTY_RENEGOTIATION_INFO_SCSV = b"\x00\xff"

    # TLS 1.3 cipher suites.
    TLS_AES_128_GCM_SHA256 = b"\x13\x01", (Protocol.TLS1_3,)
    TLS_AES_256_GCM_SHA384 = b"\x13\x02", (Protocol.TLS1_3,)
    TLS_CHACHA20_POLY1305_SHA256 = b"\x13\x03", (Protocol.TLS1_3,)
    TLS_AES_128_CCM_SHA256 = b"\x13\x04", (Protocol.TLS1_3,)
    TLS_AES_128_CCM_8_SHA256 = b"\x13\x05", (Protocol.TLS1_3,)

    # Cipher suite that had its number reassigned.
    OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256  = b'\xcc\x13'
    
    # Cipher suites adapted from IANA assignments:
    # https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
    TLS_AEGIS_128L_SHA256 = b'\x13\x07' # [draft-irtf-cfrg-aegis-aead-00]
    TLS_AEGIS_256_SHA384 = b'\x13\x06' # [draft-irtf-cfrg-aegis-aead-00]
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x19' # [RFC4346]
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = b'\x00\x17' # [RFC4346][RFC6347]
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = b'\x00\x1B' # [RFC5246]
    TLS_DH_anon_WITH_AES_128_CBC_SHA = b'\x00\x34' # [RFC5246]
    TLS_DH_anon_WITH_AES_128_CBC_SHA256 = b'\x00\x6C' # [RFC5246]
    TLS_DH_anon_WITH_AES_128_GCM_SHA256 = b'\x00\xA6' # [RFC5288]
    TLS_DH_anon_WITH_AES_256_CBC_SHA = b'\x00\x3A' # [RFC5246]
    TLS_DH_anon_WITH_AES_256_CBC_SHA256 = b'\x00\x6D' # [RFC5246]
    TLS_DH_anon_WITH_AES_256_GCM_SHA384 = b'\x00\xA7' # [RFC5288]
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x46' # [RFC6209]
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x5A' # [RFC6209]
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x47' # [RFC6209]
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x5B' # [RFC6209]
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = b'\x00\x46' # [RFC5932]
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = b'\x00\xBF' # [RFC5932]
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x84' # [RFC6367]
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = b'\x00\x89' # [RFC5932]
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = b'\x00\xC5' # [RFC5932]
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x85' # [RFC6367]
    TLS_DH_anon_WITH_DES_CBC_SHA = b'\x00\x1A' # [RFC8996]
    TLS_DH_anon_WITH_RC4_128_MD5 = b'\x00\x18' # [RFC5246][RFC6347]
    TLS_DH_anon_WITH_SEED_CBC_SHA = b'\x00\x9B' # [RFC4162]
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x0B' # [RFC4346]
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = b'\x00\x0D' # [RFC5246]
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = b'\x00\x30' # [RFC5246]
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = b'\x00\x3E' # [RFC5246]
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = b'\x00\xA4' # [RFC5288]
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = b'\x00\x36' # [RFC5246]
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = b'\x00\x68' # [RFC5246]
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = b'\x00\xA5' # [RFC5288]
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x3E' # [RFC6209]
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x58' # [RFC6209]
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x3F' # [RFC6209]
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x59' # [RFC6209]
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = b'\x00\x42' # [RFC5932]
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = b'\x00\xBB' # [RFC5932]
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x82' # [RFC6367]
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = b'\x00\x85' # [RFC5932]
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = b'\x00\xC1' # [RFC5932]
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x83' # [RFC6367]
    TLS_DH_DSS_WITH_DES_CBC_SHA = b'\x00\x0C' # [RFC8996]
    TLS_DH_DSS_WITH_SEED_CBC_SHA = b'\x00\x97' # [RFC4162]
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x0E' # [RFC4346]
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = b'\x00\x10' # [RFC5246]
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = b'\x00\x31' # [RFC5246]
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = b'\x00\x3F' # [RFC5246]
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = b'\x00\xA0' # [RFC5288]
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = b'\x00\x37' # [RFC5246]
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = b'\x00\x69' # [RFC5246]
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = b'\x00\xA1' # [RFC5288]
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x40' # [RFC6209]
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x54' # [RFC6209]
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x41' # [RFC6209]
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x55' # [RFC6209]
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = b'\x00\x43' # [RFC5932]
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = b'\x00\xBC' # [RFC5932]
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x7E' # [RFC6367]
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = b'\x00\x86' # [RFC5932]
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = b'\x00\xC2' # [RFC5932]
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x7F' # [RFC6367]
    TLS_DH_RSA_WITH_DES_CBC_SHA = b'\x00\x0F' # [RFC8996]
    TLS_DH_RSA_WITH_SEED_CBC_SHA = b'\x00\x98' # [RFC4162]
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x11' # [RFC4346]
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = b'\x00\x13' # [RFC5246]
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = b'\x00\x32' # [RFC5246]
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = b'\x00\x40' # [RFC5246]
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = b'\x00\xA2' # [RFC5288]
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = b'\x00\x38' # [RFC5246]
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = b'\x00\x6A' # [RFC5246]
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = b'\x00\xA3' # [RFC5288]
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x42' # [RFC6209]
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x56' # [RFC6209]
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x43' # [RFC6209]
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x57' # [RFC6209]
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = b'\x00\x44' # [RFC5932]
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = b'\x00\xBD' # [RFC5932]
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x80' # [RFC6367]
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = b'\x00\x87' # [RFC5932]
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = b'\x00\xC3' # [RFC5932]
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x81' # [RFC6367]
    TLS_DHE_DSS_WITH_DES_CBC_SHA = b'\x00\x12' # [RFC8996]
    TLS_DHE_DSS_WITH_SEED_CBC_SHA = b'\x00\x99' # [RFC4162]
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = b'\x00\x8F' # [RFC4279]
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA = b'\x00\x90' # [RFC4279]
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = b'\x00\xB2' # [RFC5487]
    TLS_DHE_PSK_WITH_AES_128_CCM = b'\xC0\xA6' # [RFC6655]
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = b'\x00\xAA' # [RFC5487]
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA = b'\x00\x91' # [RFC4279]
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = b'\x00\xB3' # [RFC5487]
    TLS_DHE_PSK_WITH_AES_256_CCM = b'\xC0\xA7' # [RFC6655]
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = b'\x00\xAB' # [RFC5487]
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x66' # [RFC6209]
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x6C' # [RFC6209]
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x67' # [RFC6209]
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x6D' # [RFC6209]
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = b'\xC0\x96' # [RFC6367]
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x90' # [RFC6367]
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = b'\xC0\x97' # [RFC6367]
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x91' # [RFC6367]
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = b'\xCC\xAD' # [RFC7905]
    TLS_DHE_PSK_WITH_NULL_SHA = b'\x00\x2D' # [RFC4785]
    TLS_DHE_PSK_WITH_NULL_SHA256 = b'\x00\xB4' # [RFC5487]
    TLS_DHE_PSK_WITH_NULL_SHA384 = b'\x00\xB5' # [RFC5487]
    TLS_DHE_PSK_WITH_RC4_128_SHA = b'\x00\x8E' # [RFC4279][RFC6347]
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x14' # [RFC4346]
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = b'\x00\x16' # [RFC5246]
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = b'\x00\x33' # [RFC5246]
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = b'\x00\x67' # [RFC5246]
    TLS_DHE_RSA_WITH_AES_128_CCM = b'\xC0\x9E' # [RFC6655]
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = b'\xC0\xA2' # [RFC6655]
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = b'\x00\x9E' # [RFC5288]
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = b'\x00\x39' # [RFC5246]
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = b'\x00\x6B' # [RFC5246]
    TLS_DHE_RSA_WITH_AES_256_CCM = b'\xC0\x9F' # [RFC6655]
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = b'\xC0\xA3' # [RFC6655]
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = b'\x00\x9F' # [RFC5288]
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x44' # [RFC6209]
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x52' # [RFC6209]
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x45' # [RFC6209]
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x53' # [RFC6209]
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = b'\x00\x45' # [RFC5932]
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = b'\x00\xBE' # [RFC5932]
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x7C' # [RFC6367]
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = b'\x00\x88' # [RFC5932]
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = b'\x00\xC4' # [RFC5932]
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x7D' # [RFC6367]
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = b'\xCC\xAA' # [RFC7905]
    TLS_DHE_RSA_WITH_DES_CBC_SHA = b'\x00\x15' # [RFC8996]
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = b'\x00\x9A' # [RFC4162]
    TLS_ECCPWD_WITH_AES_128_CCM_SHA256 = b'\xC0\xB2' # [RFC8492]
    TLS_ECCPWD_WITH_AES_128_GCM_SHA256 = b'\xC0\xB0' # [RFC8492]
    TLS_ECCPWD_WITH_AES_256_CCM_SHA384 = b'\xC0\xB3' # [RFC8492]
    TLS_ECCPWD_WITH_AES_256_GCM_SHA384 = b'\xC0\xB1' # [RFC8492]
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = b'\xC0\x17' # [RFC8422]
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA = b'\xC0\x18' # [RFC8422]
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA = b'\xC0\x19' # [RFC8422]
    TLS_ECDH_anon_WITH_NULL_SHA = b'\xC0\x15' # [RFC8422]
    TLS_ECDH_anon_WITH_RC4_128_SHA = b'\xC0\x16' # [RFC8422][RFC6347]
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = b'\xC0\x03' # [RFC8422]
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = b'\xC0\x04' # [RFC8422]
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = b'\xC0\x25' # [RFC5289]
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = b'\xC0\x2D' # [RFC5289]
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = b'\xC0\x05' # [RFC8422]
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = b'\xC0\x26' # [RFC5289]
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = b'\xC0\x2E' # [RFC5289]
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x4A' # [RFC6209]
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x5E' # [RFC6209]
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x4B' # [RFC6209]
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x5F' # [RFC6209]
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = b'\xC0\x74' # [RFC6367]
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x88' # [RFC6367]
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = b'\xC0\x75' # [RFC6367]
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x89' # [RFC6367]
    TLS_ECDH_ECDSA_WITH_NULL_SHA = b'\xC0\x01' # [RFC8422]
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = b'\xC0\x02' # [RFC8422][RFC6347]
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = b'\xC0\x0D' # [RFC8422]
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = b'\xC0\x0E' # [RFC8422]
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = b'\xC0\x29' # [RFC5289]
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = b'\xC0\x31' # [RFC5289]
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = b'\xC0\x0F' # [RFC8422]
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = b'\xC0\x2A' # [RFC5289]
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = b'\xC0\x32' # [RFC5289]
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x4E' # [RFC6209]
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x62' # [RFC6209]
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x4F' # [RFC6209]
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x63' # [RFC6209]
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = b'\xC0\x78' # [RFC6367]
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x8C' # [RFC6367]
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = b'\xC0\x79' # [RFC6367]
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x8D' # [RFC6367]
    TLS_ECDH_RSA_WITH_NULL_SHA = b'\xC0\x0B' # [RFC8422]
    TLS_ECDH_RSA_WITH_RC4_128_SHA = b'\xC0\x0C' # [RFC8422][RFC6347]
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = b'\xC0\x08' # [RFC8422]
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = b'\xC0\x09' # [RFC8422]
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = b'\xC0\x23' # [RFC5289]
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = b'\xC0\xAC' # [RFC7251]
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = b'\xC0\xAE' # [RFC7251]
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = b'\xC0\x2B' # [RFC5289]
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = b'\xC0\x0A' # [RFC8422]
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = b'\xC0\x24' # [RFC5289]
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = b'\xC0\xAD' # [RFC7251]
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = b'\xC0\xAF' # [RFC7251]
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = b'\xC0\x2C' # [RFC5289]
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x48' # [RFC6209]
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x5C' # [RFC6209]
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x49' # [RFC6209]
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x5D' # [RFC6209]
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = b'\xC0\x72' # [RFC6367]
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x86' # [RFC6367]
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = b'\xC0\x73' # [RFC6367]
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x87' # [RFC6367]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = b'\xCC\xA9' # [RFC7905]
    TLS_ECDHE_ECDSA_WITH_NULL_SHA = b'\xC0\x06' # [RFC8422]
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = b'\xC0\x07' # [RFC8422][RFC6347]
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = b'\xC0\x34' # [RFC5489]
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = b'\xC0\x35' # [RFC5489]
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = b'\xC0\x37' # [RFC5489]
    TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 = b'\xD0\x03' # [RFC8442]
    TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = b'\xD0\x05' # [RFC8442]
    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = b'\xD0\x01' # [RFC8442]
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = b'\xC0\x36' # [RFC5489]
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = b'\xC0\x38' # [RFC5489]
    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = b'\xD0\x02' # [RFC8442]
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x70' # [RFC6209]
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x71' # [RFC6209]
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = b'\xC0\x9A' # [RFC6367]
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = b'\xC0\x9B' # [RFC6367]
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = b'\xCC\xAC' # [RFC7905]
    TLS_ECDHE_PSK_WITH_NULL_SHA = b'\xC0\x39' # [RFC5489]
    TLS_ECDHE_PSK_WITH_NULL_SHA256 = b'\xC0\x3A' # [RFC5489]
    TLS_ECDHE_PSK_WITH_NULL_SHA384 = b'\xC0\x3B' # [RFC5489]
    TLS_ECDHE_PSK_WITH_RC4_128_SHA = b'\xC0\x33' # [RFC5489][RFC6347]
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = b'\xC0\x12' # [RFC8422]
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = b'\xC0\x13' # [RFC8422]
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = b'\xC0\x27' # [RFC5289]
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = b'\xC0\x2F' # [RFC5289]
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = b'\xC0\x14' # [RFC8422]
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = b'\xC0\x28' # [RFC5289]
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = b'\xC0\x30' # [RFC5289]
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x4C' # [RFC6209]
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x60' # [RFC6209]
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x4D' # [RFC6209]
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x61' # [RFC6209]
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = b'\xC0\x76' # [RFC6367]
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x8A' # [RFC6367]
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = b'\xC0\x77' # [RFC6367]
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x8B' # [RFC6367]
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = b'\xCC\xA8' # [RFC7905]
    TLS_ECDHE_RSA_WITH_NULL_SHA = b'\xC0\x10' # [RFC8422]
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = b'\xC0\x11' # [RFC8422][RFC6347]
    TLS_GOSTR341112_256_WITH_28147_CNT_IMIT = b'\xC1\x02' # [RFC9189]
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC = b'\xC1\x00' # [RFC9189]
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L = b'\xC1\x03' # [RFC9367]
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S = b'\xC1\x05' # [RFC9367]
    TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC = b'\xC1\x01' # [RFC9189]
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_L = b'\xC1\x04' # [RFC9367]
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_S = b'\xC1\x06' # [RFC9367]
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = b'\x00\x29' # [RFC2712]
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = b'\x00\x26' # [RFC2712]
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = b'\x00\x2A' # [RFC2712]
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = b'\x00\x27' # [RFC2712]
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = b'\x00\x2B' # [RFC2712][RFC6347]
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA = b'\x00\x28' # [RFC2712][RFC6347]
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = b'\x00\x23' # [RFC2712]
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA = b'\x00\x1F' # [RFC2712]
    TLS_KRB5_WITH_DES_CBC_MD5 = b'\x00\x22' # [RFC2712]
    TLS_KRB5_WITH_DES_CBC_SHA = b'\x00\x1E' # [RFC2712]
    TLS_KRB5_WITH_IDEA_CBC_MD5 = b'\x00\x25' # [RFC2712]
    TLS_KRB5_WITH_IDEA_CBC_SHA = b'\x00\x21' # [RFC2712]
    TLS_KRB5_WITH_RC4_128_MD5 = b'\x00\x24' # [RFC2712][RFC6347]
    TLS_KRB5_WITH_RC4_128_SHA = b'\x00\x20' # [RFC2712][RFC6347]
    TLS_NULL_WITH_NULL_NULL = b'\x00\x00' # [RFC5246]
    TLS_PSK_DHE_WITH_AES_128_CCM_8 = b'\xC0\xAA' # [RFC6655]
    TLS_PSK_DHE_WITH_AES_256_CCM_8 = b'\xC0\xAB' # [RFC6655]
    TLS_PSK_WITH_3DES_EDE_CBC_SHA = b'\x00\x8B' # [RFC4279]
    TLS_PSK_WITH_AES_128_CBC_SHA = b'\x00\x8C' # [RFC4279]
    TLS_PSK_WITH_AES_128_CBC_SHA256 = b'\x00\xAE' # [RFC5487]
    TLS_PSK_WITH_AES_128_CCM = b'\xC0\xA4' # [RFC6655]
    TLS_PSK_WITH_AES_128_CCM_8 = b'\xC0\xA8' # [RFC6655]
    TLS_PSK_WITH_AES_128_GCM_SHA256 = b'\x00\xA8' # [RFC5487]
    TLS_PSK_WITH_AES_256_CBC_SHA = b'\x00\x8D' # [RFC4279]
    TLS_PSK_WITH_AES_256_CBC_SHA384 = b'\x00\xAF' # [RFC5487]
    TLS_PSK_WITH_AES_256_CCM = b'\xC0\xA5' # [RFC6655]
    TLS_PSK_WITH_AES_256_CCM_8 = b'\xC0\xA9' # [RFC6655]
    TLS_PSK_WITH_AES_256_GCM_SHA384 = b'\x00\xA9' # [RFC5487]
    TLS_PSK_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x64' # [RFC6209]
    TLS_PSK_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x6A' # [RFC6209]
    TLS_PSK_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x65' # [RFC6209]
    TLS_PSK_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x6B' # [RFC6209]
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = b'\xC0\x94' # [RFC6367]
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x8E' # [RFC6367]
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = b'\xC0\x95' # [RFC6367]
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x8F' # [RFC6367]
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = b'\xCC\xAB' # [RFC7905]
    TLS_PSK_WITH_NULL_SHA = b'\x00\x2C' # [RFC4785]
    TLS_PSK_WITH_NULL_SHA256 = b'\x00\xB0' # [RFC5487]
    TLS_PSK_WITH_NULL_SHA384 = b'\x00\xB1' # [RFC5487]
    TLS_PSK_WITH_RC4_128_SHA = b'\x00\x8A' # [RFC4279][RFC6347]
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x08' # [RFC4346]
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = b'\x00\x06' # [RFC4346]
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = b'\x00\x03' # [RFC4346][RFC6347]
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = b'\x00\x93' # [RFC4279]
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA = b'\x00\x94' # [RFC4279]
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = b'\x00\xB6' # [RFC5487]
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = b'\x00\xAC' # [RFC5487]
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA = b'\x00\x95' # [RFC4279]
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = b'\x00\xB7' # [RFC5487]
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = b'\x00\xAD' # [RFC5487]
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x68' # [RFC6209]
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x6E' # [RFC6209]
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x69' # [RFC6209]
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x6F' # [RFC6209]
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = b'\xC0\x98' # [RFC6367]
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x92' # [RFC6367]
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = b'\xC0\x99' # [RFC6367]
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x93' # [RFC6367]
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = b'\xCC\xAE' # [RFC7905]
    TLS_RSA_PSK_WITH_NULL_SHA = b'\x00\x2E' # [RFC4785]
    TLS_RSA_PSK_WITH_NULL_SHA256 = b'\x00\xB8' # [RFC5487]
    TLS_RSA_PSK_WITH_NULL_SHA384 = b'\x00\xB9' # [RFC5487]
    TLS_RSA_PSK_WITH_RC4_128_SHA = b'\x00\x92' # [RFC4279][RFC6347]
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = b'\x00\x0A' # [RFC5246]
    TLS_RSA_WITH_AES_128_CBC_SHA = b'\x00\x2F' # [RFC5246]
    TLS_RSA_WITH_AES_128_CBC_SHA256 = b'\x00\x3C' # [RFC5246]
    TLS_RSA_WITH_AES_128_CCM = b'\xC0\x9C' # [RFC6655]
    TLS_RSA_WITH_AES_128_CCM_8 = b'\xC0\xA0' # [RFC6655]
    TLS_RSA_WITH_AES_128_GCM_SHA256 = b'\x00\x9C' # [RFC5288]
    TLS_RSA_WITH_AES_256_CBC_SHA = b'\x00\x35' # [RFC5246]
    TLS_RSA_WITH_AES_256_CBC_SHA256 = b'\x00\x3D' # [RFC5246]
    TLS_RSA_WITH_AES_256_CCM = b'\xC0\x9D' # [RFC6655]
    TLS_RSA_WITH_AES_256_CCM_8 = b'\xC0\xA1' # [RFC6655]
    TLS_RSA_WITH_AES_256_GCM_SHA384 = b'\x00\x9D' # [RFC5288]
    TLS_RSA_WITH_ARIA_128_CBC_SHA256 = b'\xC0\x3C' # [RFC6209]
    TLS_RSA_WITH_ARIA_128_GCM_SHA256 = b'\xC0\x50' # [RFC6209]
    TLS_RSA_WITH_ARIA_256_CBC_SHA384 = b'\xC0\x3D' # [RFC6209]
    TLS_RSA_WITH_ARIA_256_GCM_SHA384 = b'\xC0\x51' # [RFC6209]
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = b'\x00\x41' # [RFC5932]
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = b'\x00\xBA' # [RFC5932]
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = b'\xC0\x7A' # [RFC6367]
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = b'\x00\x84' # [RFC5932]
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = b'\x00\xC0' # [RFC5932]
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = b'\xC0\x7B' # [RFC6367]
    TLS_RSA_WITH_DES_CBC_SHA = b'\x00\x09' # [RFC8996]
    TLS_RSA_WITH_IDEA_CBC_SHA = b'\x00\x07' # [RFC8996]
    TLS_RSA_WITH_NULL_MD5 = b'\x00\x01' # [RFC5246]
    TLS_RSA_WITH_NULL_SHA = b'\x00\x02' # [RFC5246]
    TLS_RSA_WITH_NULL_SHA256 = b'\x00\x3B' # [RFC5246]
    TLS_RSA_WITH_RC4_128_MD5 = b'\x00\x04' # [RFC5246][RFC6347]
    TLS_RSA_WITH_RC4_128_SHA = b'\x00\x05' # [RFC5246][RFC6347]
    TLS_RSA_WITH_SEED_CBC_SHA = b'\x00\x96' # [RFC4162]
    TLS_SHA256_SHA256 = b'\xC0\xB4' # [RFC9150]
    TLS_SHA384_SHA384 = b'\xC0\xB5' # [RFC9150]
    TLS_SM4_CCM_SM3 = b'\x00\xC7' # [RFC8998]
    TLS_SM4_GCM_SM3 = b'\x00\xC6' # [RFC8998]
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = b'\xC0\x1C' # [RFC5054]
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = b'\xC0\x1F' # [RFC5054]
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = b'\xC0\x22' # [RFC5054]
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = b'\xC0\x1B' # [RFC5054]
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = b'\xC0\x1E' # [RFC5054]
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = b'\xC0\x21' # [RFC5054]
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = b'\xC0\x1A' # [RFC5054]
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA = b'\xC0\x1D' # [RFC5054]
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA = b'\xC0\x20' # [RFC5054]

class AlertLevel(Enum):
    """ Different alert levels that can be sent by the server. """
    WARNING = b'\x01'
    FATAL = b'\x02'

class AlertDescription(Enum):
    """ Different alert messages that can be sent by the server. """
    close_notify = b'\x00'
    unexpected_message = b'\x0a'
    bad_record_mac = b'\x14'
    record_overflow = b'\x16'
    handshake_failure = b'\x28'
    bad_certificate = b'\x2a'
    unsupported_certificate = b'\x2b'
    certificate_revoked = b'\x2c'
    certificate_expired = b'\x2d'
    certificate_unknown = b'\x2e'
    illegal_parameter = b'\x2f'
    unknown_ca = b'\x30'
    access_denied = b'\x31'
    decode_error = b'\x32'
    decrypt_error = b'\x33'
    protocol_version = b'\x46'
    insufficient_security = b'\x47'
    internal_error = b'\x50'
    inappropriate_fallback = b'\x56'
    user_canceled = b'\x5a'
    missing_extension = b'\x6d'
    unsupported_extension = b'\x6e'
    unrecognized_name = b'\x70'
    bad_certificate_status_response = b'\x71'
    unknown_psk_identity = b'\x73'
    certificate_required = b'\x74'
    no_application_protocol = b'\x78'

class ExtensionType(Enum):
    server_name = b'\x00\x00'
    max_fragment_length = b'\x00\x01'
    client_certificate_url = b'\x00\x02'
    trusted_ca_keys = b'\x00\x03'
    truncated_hmac = b'\x00\x04'
    status_request = b'\x00\x05'
    user_mapping = b'\x00\x06'
    client_authz = b'\x00\x07'
    server_authz = b'\x00\x08'
    cert_type = b'\x00\x09'
    supported_groups = b'\x00\x0a'
    ec_point_formats = b'\x00\x0b'
    srp = b'\x00\x0c'
    signature_algorithms = b'\x00\x0d'
    use_srtp = b'\x00\x0e'
    heartbeat = b'\x00\x0f'
    application_layer_protocol_negotiation = b'\x00\x10'
    status_request_v2 = b'\x00\x11'
    signed_certificate_timestamp = b'\x00\x12'
    client_certificate_type = b'\x00\x13'
    server_certificate_type = b'\x00\x14'
    padding = b'\x00\x15'
    encrypt_then_mac = b'\x00\x16'
    extended_master_secret = b'\x00\x17'
    token_binding = b'\x00\x18'
    cached_info = b'\x00\x19'
    tls_lts = b'\x00\x1a'
    compress_certificate = b'\x00\x1b'
    record_size_limit = b'\x00\x1c'
    pwd_protect = b'\x00\x1d'
    pwd_clear = b'\x00\x1e'
    password_salt = b'\x00\x1f'
    ticket_pinning = b'\x00\x20'
    tls_cert_with_extern_psk = b'\x00\x21'
    delegated_credential = b'\x00\x22'
    session_ticket = b'\x00\x23'
    TLMSP = b'\x00\x24'
    TLMSP_proxying = b'\x00\x25'
    TLMSP_delegate = b'\x00\x26'
    supported_ekt_ciphers = b'\x00\x27'
    pre_shared_key = b'\x00\x29'
    early_data = b'\x00\x2a'
    supported_versions = b'\x00\x2b'
    cookie = b'\x00\x2c'
    psk_key_exchange_modes = b'\x00\x2d'
    certificate_authorities = b'\x00\x2f'
    oid_filters = b'\x00\x30'
    post_handshake_auth = b'\x00\x31'
    signature_algorithms_cert = b'\x00\x32'
    key_share = b'\x00\x33'
    transparency_info = b'\x00\x34'
    connection_id_deprecated = b'\x00\x35'
    connection_id = b'\x00\x36'
    external_id_hash = b'\x00\x37'
    external_session_id = b'\x00\x38'
    quic_transport_parameters = b'\x00\x39'
    ticket_request = b'\x00\x3a'
    dnssec_chain = b'\x00\x3b'
    sequence_number_encryption_algorithms = b'\x00\x3c'

class ScanError(Exception):
    """ Base error class for errors that occur during scanning. """
    pass

class ServerAlertError(ScanError):
    def __init__(self, level: AlertLevel, description: AlertDescription):
        super().__init__(self, f'Server error: {level}: {description}')
        self.level = level
        self.description = description

class DowngradeError(ScanError):
    """ Error for servers that attempt to downgrade beyond supported versions. """
    pass

class BadServerResponse(ScanError):
    """ Error for server responses that can't be parsed. """
    pass

class ConnectionError(ScanError):
    """ Class for error in resolving or connecting to a server. """
    pass

class ProxyError(ConnectionError):
    """ Class for errors in connecting through a proxy. """
    pass

@dataclass
class ServerHello:
    version: Protocol
    has_compression: bool
    cipher_suite: CipherSuite
    group: Optional[Group]

def try_parse_server_error(packet: bytes) -> Optional[ServerAlertError]:
    """
    Parses a server alert packet, or None if the packet is not an alert.
    """
    # Alert record
    if packet[0:1] != RecordType.ALERT.value:
        return None
    record_type_int, legacy_record_version, length = struct.unpack('!c2sH', packet[:5])
    alert_level_id, alert_description_id = struct.unpack('!cc', packet[5:7])
    return ServerAlertError(AlertLevel(alert_level_id), AlertDescription(alert_description_id))

def parse_server_hello(packet: bytes, parse_extra_records: bool = False) -> ServerHello:
    """
    Parses a Server Hello packet and returns the cipher suite accepted by the server.
    """
    if not packet:
        raise BadServerResponse('Empty response')
    
    if error := try_parse_server_error(packet):
        raise error
    
    start = 0
    def parse_next(length: int) -> bytes:
        nonlocal start
        value = packet[start:start+length]
        start += length
        return value
    def bytes_to_int(b: bytes) -> int:
        return int.from_bytes(b, byteorder='big')
    
    record_type = RecordType(parse_next(1))
    assert record_type == RecordType.HANDSHAKE, record_type
    legacy_record_version = parse_next(2)
    handshake_length = parse_next(2)
    handshake_type = HandshakeType(parse_next(1))
    assert handshake_type == HandshakeType.server_hello, handshake_type
    server_hello_length = bytes_to_int(parse_next(3))
    start_next_handshake = start + server_hello_length
    # At most TLS 1.2. Handshakes for TLS 1.3 use the supported_versions extension.
    version = Protocol(parse_next(2))
    server_random = parse_next(32)
    session_id_length = parse_next(1)
    session_id = parse_next(bytes_to_int(session_id_length))
    cipher_suite_bytes = parse_next(2)
    compression_method = parse_next(1)
    extensions_length = parse_next(2)
    extensions_end = start + bytes_to_int(extensions_length)

    group = None

    while start < extensions_end:
        extension_type = ExtensionType(parse_next(2))
        extension_data_length = parse_next(2)
        extension_data = parse_next(bytes_to_int(extension_data_length))
        if extension_type == ExtensionType.supported_versions:
            version = Protocol(extension_data)
        elif extension_type == ExtensionType.key_share:
            try:
                group = Group(extension_data[:2])
            except ValueError:
                logger.warning(f'Unknown group: {extension_data[:2]!r}')
                pass

    start = start_next_handshake
    # If enabled, parse extra records after server_hello.
    # # Especially useful for TLS 1.2 and lower, as they contain ECC group, certificate, etc.
    while parse_extra_records and start < len(packet):
        record_type_value = parse_next(1)
        legacy_record_version = parse_next(2)
        record_length = bytes_to_int(parse_next(2))
        logger.debug('Parsed additional record type: %s', record_type)
        if record_type_value != RecordType.HANDSHAKE.value:
            start += record_length
        else:
            handshake_type_value = parse_next(1)
            logger.debug('Parsed additional handshake type: %s', handshake_type)
            handshake_length = bytes_to_int(parse_next(3))
            if handshake_type_value == HandshakeType.server_key_exchange.value:
                assert parse_next(1) == b'\x03', 'Expected curve type: named_curve'
                group = Group(parse_next(2))
                pubkey_length = bytes_to_int(parse_next(1))
                start += pubkey_length
                signature_algorithm = parse_next(2)
                signature_length = bytes_to_int(parse_next(2))
                start += signature_length
            else:
                start += handshake_length
    
    cipher_suite = CipherSuite(cipher_suite_bytes)
    return ServerHello(version, compression_method != b'\x00', cipher_suite, group)

class CompressionMethod(Enum):
    NULL = b'\x00'
    DEFLATE = b'\x01'

@dataclass
class TlsHelloSettings:
    """
    Settings necessary to send a TLS Client Hello to a server.
    By default, all protocols and cipher suites are (claimed to be) supported.
    """
    host: str
    port: int = 443
    proxy: Optional[str] = None
    timeout_in_seconds: Optional[float] = DEFAULT_TIMEOUT

    server_name_indication: Optional[str] = None # Defaults to host if not provided.
    protocols: Sequence[Protocol] = tuple(Protocol)
    cipher_suites: Sequence[CipherSuite] = tuple(CipherSuite)
    groups: Sequence[Group] = tuple(Group)
    compression_methods: Sequence[CompressionMethod] = tuple(CompressionMethod)

def make_client_hello(hello_prefs: TlsHelloSettings) -> bytes:
    """
    Creates a TLS Record byte string with Client Hello handshake based on client preferences.
    """
    def _prefix_length(b: bytes, width_bytes: int = 2) -> bytes:
        """ Returns `b` prefixed with its length, encoded as a big-endian integer of `width_bytes` bytes. """
        return len(b).to_bytes(width_bytes, byteorder="big") + b
    
    protocol_values = [protocol for protocol in hello_prefs.protocols]
    max_protocol = max(protocol_values)
    # Record and Hanshake versions have a maximum value due to ossification.
    legacy_handshake_version = min(Protocol.TLS1_2, max_protocol)
    legacy_record_version = min(Protocol.TLS1_0, max_protocol)
    # Only NULL compression is allowed in TLS 1.3.
    legacy_compression_methods = [CompressionMethod.NULL] if Protocol.TLS1_3 in hello_prefs.protocols else hello_prefs.compression_methods

    return bytes((
        0x16, # Record type: handshake.
        *legacy_record_version.value, # Legacy record version: max TLS 1.0.
        *_prefix_length(bytes([ # Handshake record.
            0x01,  # Handshake type: Client Hello.
            *_prefix_length(width_bytes=3, b=bytes([ # Client hello handshake.
                *legacy_handshake_version.value,  # Legacy client version: max TLS 1.2.
                *32*[0x07],  # Random. Any value will do.
                32,  # Legacy session ID length.
                *32*[0x07],  # Legacy session ID. Any value will do.
                *_prefix_length( # Cipher suites.
                    b"".join(cipher_suite.value for cipher_suite in hello_prefs.cipher_suites)
                ),

                *_prefix_length( # Compression methods.
                    b"".join(compression_method.value for compression_method in legacy_compression_methods),
                    width_bytes=1
                ),
                
                *_prefix_length(bytes([ # Extensions.
                    0x00, 0x00,  # Extension type: server_name.
                    *_prefix_length( # Extension data.
                        _prefix_length( # server_name list
                            b'\x00' + # Name type: host_name.
                            _prefix_length((
                                hello_prefs.server_name_indication or hello_prefs.host
                            ).encode('ascii'))
                        )
                    ),

                    0x00, 0x05, # Extension type: status_request. Allow server to send OCSP information.
                    0x00, 0x05, # Length of extension data.
                    0x01, # Certificate status type: OCSP.
                    0x00, 0x00, # Responder ID list length.
                    0x00, 0x00, # Request extension information length.

                    0x00, 0x0b,  # Extension type: EC point formats.
                    0x00, 0x04,  # Length of extension data.
                    0x03,  # Length of EC point formats list.
                    0x00,  # EC point format: uncompressed.
                    0x01,  # EC point format: ansiX962_compressed_prime.
                    0x02,  # EC point format: ansiX962_compressed_char2.

                    0x00, 0x0a,  # Extension type: supported groups (mostly EC curves).
                    *_prefix_length( # Extension data.
                        _prefix_length(
                            b''.join(group.value for group in hello_prefs.groups)
                        )
                    ),

                    0x00, 0x23,  # Extension type: session ticket.
                    0x00, 0x00,  # No session ticket data follows.

                    0x00, 0x16,  # Extension type: encrypt-then-MAC.
                    0x00, 0x00,  # Length of extension data.

                    0x00, 0x17,  # Extension type: extended master secret.
                    0x00, 0x00,  # No extension data follows.

                    0x00, 0x0d,  # Extension type: signature algorithms.
                    *_prefix_length( # Extension data.
                        _prefix_length(bytes([ # Signature algorithm list.
                            0x04, 0x03, # ECDSA-SECP256r1-SHA256
                            0x05, 0x03, # ECDSA-SECP384r1-SHA384
                            0x06, 0x03, # ECDSA-SECP521r1-SHA512
                            0x08, 0x07, # ED25519
                            0x08, 0x08, # ED448
                            0x08, 0x09, # RSA-PSS-PSS-SHA256
                            0x08, 0x0a, # RSA-PSS-PSS-SHA384
                            0x08, 0x0b, # RSA-PSS-PSS-SHA512
                            0x08, 0x04, # RSA-PSS-RSAE-SHA256
                            0x08, 0x05, # RSA-PSS-RSAE-SHA384
                            0x08, 0x06, # RSA-PSS-RSAE-SHA512
                            0x04, 0x01, # RSA-PKCS1-SHA256
                            0x05, 0x01, # RSA-PKCS1-SHA384
                            0x06, 0x01, # RSA-PKCS1-SHA512
                            0x02, 0x01, # RSA-PKCS1-SHA1
                            0x02, 0x03, # ECDSA-SHA1
                        ]))
                    ),

                    0x00, 0x12, # Extension type: SCT. Allow server to return signed certificate timestamp.
                    0x00, 0x00, # Length of extension data.

                    *((Protocol.TLS1_3 in hello_prefs.protocols) * [ # This extension is only available in TLS 1.3.
                        0x00, 0x2b,  # Extension type: supported version.
                        *_prefix_length(
                            _prefix_length(
                                b"".join(protocol.value for protocol in hello_prefs.protocols),
                                width_bytes=1
                            )
                        )
                    ]),

                    # TODO: PSK key exchange modes extension.
                    0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
                    
                    # TODO: key share extension.
                    0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54,
                ]))
            ]))
        ]))
    ))

def make_socket(hello_prefs: TlsHelloSettings) -> socket.socket:
    """
    Creates and connects a socket to the target server, through the chosen proxy if any.
    """
    socket_host, socket_port = None, None # To appease the type checker.
    try:
        if not hello_prefs.proxy:
            socket_host, socket_port = hello_prefs.host, hello_prefs.port
            return socket.create_connection((socket_host, socket_port), timeout=hello_prefs.timeout_in_seconds)

        if not hello_prefs.proxy.startswith('http://'):
            raise ProxyError("Only HTTP proxies are supported at the moment.", hello_prefs.proxy)
        
        socket_host, socket_port = parse_target(hello_prefs.proxy, 80)

        sock = socket.create_connection((socket_host, socket_port), timeout=hello_prefs.timeout_in_seconds)
        sock.send(f"CONNECT {hello_prefs.host}:{hello_prefs.port} HTTP/1.1\r\nhost:{socket_host}\r\n\r\n".encode('utf-8'))
        sock_file = sock.makefile('r', newline='\r\n')
        line = sock_file.readline()
        if not re.fullmatch(r'HTTP/1\.[01] 200 Connection [Ee]stablished\r\n', line):
            sock_file.close()
            sock.close()
            raise ProxyError("Proxy refused the connection: ", line)
        while True:
            if sock_file.readline() == '\r\n':
                break
        return sock
    except TimeoutError as e:
        raise ConnectionError(f"Connection to {socket_host}:{socket_port} timed out after {hello_prefs.timeout_in_seconds} seconds") from e
    except socket.gaierror as e:
        raise ConnectionError(f"Could not resolve host {socket_host}") from e
    except socket.error as e:
        raise ConnectionError(f"Could not connect to {socket_host}:{socket_port}") from e

def send_hello(hello_prefs: TlsHelloSettings, wait_additional_records: bool = False) -> Iterator[bytes]:
    """
    Sends a Client Hello packet to the server based on hello_prefs, and returns the first few bytes of the server response.
    """
    logger.debug(f"Sending Client Hello to {hello_prefs.host}:{hello_prefs.port}")
    with make_socket(hello_prefs) as sock:
        sock.send(make_client_hello(hello_prefs))
        # Hopefully the ServerHello response.
        yield sock.recv(4096)
        # Short timeout to receive buffered packets containing further records.
        sock.settimeout(0.01)
        try:
            while wait_additional_records and (data := sock.recv(4096)):
                yield data
        except TimeoutError:
            pass
    
def get_server_hello(hello_prefs: TlsHelloSettings, parse_additional_records: bool = False) -> ServerHello:
    """
    Sends a Client Hello to the server, and returns the parsed ServerHello.
    Raises exceptions for the different alert messages the server can send.
    """
    response = b''.join(send_hello(hello_prefs, parse_additional_records))
    if error := try_parse_server_error(response):
        raise error

    server_hello = parse_server_hello(response, parse_additional_records)
    
    if server_hello.version not in hello_prefs.protocols:
        # Server picked a protocol we didn't ask for.
        logger.info(f"Server attempted to downgrade protocol to unsupported version {server_hello.version}")
        raise DowngradeError(f"Server attempted to downgrade from {hello_prefs.protocols} to {server_hello.version}")
    
    return server_hello

def _iterate_server_option(hello_prefs: TlsHelloSettings, request_option: str, response_option: str, on_response: Callable[[ServerHello], None] = lambda s: None, parse_additional_records: bool = False) -> Iterator[Any]:
    """
    Continually sends Client Hello packets to the server, removing the `response_option` from the list of options each time,
    until the server rejects the handshake.
    """
    # We'll be mutating the list of options, so make a copy.
    options_to_test = list(getattr(hello_prefs, request_option))
    # TODO: figure out how to have mypy accept this line.
    hello_prefs = dataclasses.replace(hello_prefs, **{request_option: options_to_test}) # type: ignore

    logger.info(f"Enumerating server {response_option} with {len(options_to_test)} options and protocols {hello_prefs.protocols}")

    while options_to_test:
        try:
            logger.debug(f"Offering {len(options_to_test)} {response_option} over {hello_prefs.protocols}: {options_to_test}")
            server_hello = get_server_hello(hello_prefs, parse_additional_records=parse_additional_records)
            on_response(server_hello)
        except DowngradeError:
            break
        except ServerAlertError as error:
            if error.description in [AlertDescription.protocol_version, AlertDescription.handshake_failure]:
                break
            raise

        accepted_option = getattr(server_hello, response_option)
        if accepted_option is None or accepted_option not in options_to_test:
            # When enumerating groups, the server can refuse all groups and still accept the handshake (group=None),
            # or accept a group that we didn't offer (e.g. Caddy 2.7.5 with group x25519).
            break
        options_to_test.remove(accepted_option)
        yield accepted_option

def enumerate_server_cipher_suites(hello_prefs: TlsHelloSettings, on_response: Callable[[ServerHello], None] = lambda s: None) -> Sequence[CipherSuite]:
    """
    Given a list of cipher suites to test, sends a sequence of Client Hello packets to the server,
    removing the accepted cipher suite from the list each time.
    Returns a list of all cipher suites the server accepted.
    """
    return list(_iterate_server_option(hello_prefs, 'cipher_suites', 'cipher_suite', on_response, parse_additional_records=False))

def enumerate_server_groups(hello_prefs: TlsHelloSettings, on_response: Callable[[ServerHello], None] = lambda s: None) -> Sequence[Group]:
    """
    Given a list of groups to test, sends a sequence of Client Hello packets to the server,
    removing the accepted group from the list each time.
    Returns a list of all groups the server accepted.
    """
    return list(_iterate_server_option(hello_prefs, 'groups', 'group', on_response, parse_additional_records=True))

@dataclass
class Certificate:
    """
    Represents an X509 certificate in a chain sent by the server.
    """
    serial_number: str
    fingerprint_sha256: str
    subject: dict[str, str]
    issuer: dict[str, str]
    subject_alternative_names: list[str]
    key_type: str
    key_length_in_bits: int
    all_key_usage: list[str] = dataclasses.field(init=False)
    not_before: datetime
    not_after: datetime
    is_expired: bool = dataclasses.field(init=False)
    days_until_expiration: int = dataclasses.field(init=False)
    signature_algorithm: str
    extensions: dict[str, str]

    def __post_init__(self):
        now = datetime.now(tz=timezone.utc)
        self.is_expired = self.not_after < now
        self.days_until_expiration = (self.not_after - now).days

        all_key_usage_str = self.extensions.get('keyUsage', '') + ', ' + self.extensions.get('extendedKeyUsage', '')
        self.all_key_usage = [ku for ku in all_key_usage_str.split(', ') if ku]
    
def get_server_certificate_chain(hello_prefs: TlsHelloSettings) -> Sequence[Certificate]:
    """
    Use socket and pyOpenSSL to get the server certificate chain.
    """
    from OpenSSL import SSL, crypto
    import ssl, select

    def _x509_name_to_dict(x509_name: crypto.X509Name) -> dict[str, str]:
        return {name.decode('utf-8'): value.decode('utf-8') for name, value in x509_name.get_components()}

    def _x509_time_to_datetime(x509_time: Optional[bytes]) -> datetime:
        if x509_time is None:
            raise BadServerResponse('Timestamp cannot be None')
        return datetime.strptime(x509_time.decode('ascii'), '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
    
    no_flag_by_protocol = {
        Protocol.SSLv3: SSL.OP_NO_SSLv3,
        Protocol.TLS1_0: SSL.OP_NO_TLSv1,
        Protocol.TLS1_1: SSL.OP_NO_TLSv1_1,
        Protocol.TLS1_2: SSL.OP_NO_TLSv1_2,
        Protocol.TLS1_3: SSL.OP_NO_TLSv1_3,
    }
    logger.info("Fetching certificate chain with pyOpenSSL")
    with make_socket(hello_prefs) as sock:
        # This order of operations is necessary to work around a pyOpenSSL bug:
        # https://github.com/pyca/pyopenssl/issues/168#issuecomment-289194607
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        forbidden_versions = sum(no_flag_by_protocol[protocol] for protocol in Protocol if protocol not in hello_prefs.protocols)
        context.set_options(forbidden_versions)
        connection = SSL.Connection(context, sock)
        connection.set_connect_state()        
        # Necessary for servers that expect SNI. Otherwise expect "tlsv1 alert internal error".
        connection.set_tlsext_host_name((hello_prefs.server_name_indication or hello_prefs.host).encode('utf-8'))
        while True:
            try:
                connection.do_handshake()
                break
            except SSL.WantReadError as e:
                rd, _, _ = select.select([sock], [], [], sock.gettimeout())
                if not rd:
                    raise ConnectionError('Timed out during handshake for certificate chain') from e
                continue
            except SSL.Error as e:
                raise ConnectionError(f'OpenSSL exception during handshake for certificate chain: {e}') from e
        connection.shutdown()

    raw_certs = connection.get_peer_cert_chain()

    if raw_certs is None:
        raise BadServerResponse('Server did not give any certificate chain')
    
    logger.info(f"Received {len(raw_certs)} certificates")
    
    public_key_type_by_id = {crypto.TYPE_DH: 'DH', crypto.TYPE_DSA: 'DSA', crypto.TYPE_EC: 'EC', crypto.TYPE_RSA: 'RSA'}
    nice_certs: list[Certificate] = []
    for raw_cert in raw_certs:
        extensions: dict[str, str] = {}
        for i in range(raw_cert.get_extension_count()):
            extension = raw_cert.get_extension(i)
            extensions[extension.get_short_name().decode('utf-8')] = str(extension)

        san = re.findall(r'DNS:(.+?)(?:, |$)', extensions.get('subjectAltName', ''))

        nice_certs.append(Certificate(
            serial_number=str(raw_cert.get_serial_number()),
            subject=_x509_name_to_dict(raw_cert.get_subject()),
            issuer=_x509_name_to_dict(raw_cert.get_issuer()),
            subject_alternative_names=san,
            not_before=_x509_time_to_datetime(raw_cert.get_notBefore()),
            not_after=_x509_time_to_datetime(raw_cert.get_notAfter()),
            signature_algorithm=raw_cert.get_signature_algorithm().decode('utf-8'),
            extensions=extensions,
            key_length_in_bits=raw_cert.get_pubkey().bits(),
            key_type=public_key_type_by_id.get(raw_cert.get_pubkey().type(), 'UNKNOWN'),
            fingerprint_sha256=raw_cert.digest('sha256').decode('utf-8'),
        ))
    return nice_certs

@dataclass
class ProtocolResult:
    has_compression: bool
    has_cipher_suite_order: bool
    has_post_quantum: bool
    groups: List[Group]
    cipher_suites: List[CipherSuite]

    def __post_init__(self):
        # Internal fields to store every ServerHello seen during cipher suite and group enumeration.
        # Used by the scan to detect compression and cipher suite order without additional handshakes.
        self._cipher_suite_hellos: List[ServerHello] = []
        self._group_hellos: List[ServerHello] = []

@dataclass
class ServerScanResult:
    host: str
    port: int
    proxy: Optional[str]
    protocols: dict[Protocol, Optional[ProtocolResult]]
    certificate_chain: Optional[list[Certificate]]

def scan_server(
    host: str,
    port: int = 443,
    protocols: Sequence[Protocol] = tuple(Protocol),
    enumerate_options: bool = True,
    fetch_cert_chain: bool = True,
    server_name_indication: Optional[str] = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    timeout_in_seconds: Optional[float] = DEFAULT_TIMEOUT,
    proxy:Optional[str] = None,
    progress: Callable[[int, int], None] = lambda current, total: None,
    ) -> ServerScanResult:
    """
    Scans a SSL/TLS server for supported protocols, cipher suites, and certificate chain.

    `fetch_cert_chain` can be used to load the certificate chain, at the cost of using pyOpenSSL.

    Runs scans in parallel to speed up the process, with up to `max_workers` threads connecting at the same time.
    """
    logger.info(f"Scanning {host}:{port}")
    hello_prefs = TlsHelloSettings(host, port, proxy, timeout_in_seconds, server_name_indication=server_name_indication, protocols=protocols)

    tmp_certificate_chain: List[Certificate] = []
    tmp_protocol_results = {p: ProtocolResult(False, False, False, [], []) for p in Protocol}

    with ThreadPool(max_workers) as pool:
        logger.debug("Initializing workers")

        tasks: List[Callable[[], None]] = []

        if enumerate_options:
            def scan_protocol(protocol):
                protocol_result = tmp_protocol_results[protocol]
                suites_to_test = [cs for cs in CipherSuite if protocol in cs.protocols]

                cipher_suite_prefs = dataclasses.replace(hello_prefs, protocols=[protocol], cipher_suites=suites_to_test)
                # Save the cipher suites to protocol results, and store each Server Hello for post-processing of other options.
                tasks.append(lambda: protocol_result.cipher_suites.extend(enumerate_server_cipher_suites(cipher_suite_prefs, protocol_result._cipher_suite_hellos.append)))

                # Submit reversed list of cipher suites when checking for groups, to detect servers that respect user cipher suite order.
                group_prefs = dataclasses.replace(hello_prefs, protocols=[protocol], cipher_suites=list(reversed(suites_to_test)))
                tasks.append(lambda: protocol_result.groups.extend(enumerate_server_groups(group_prefs, protocol_result._group_hellos.append)))

            for protocol in protocols:
                # Must be extracted to a function to avoid late binding in task lambdas.
                scan_protocol(protocol)

        if fetch_cert_chain:
            tasks.append(lambda: tmp_certificate_chain.extend(get_server_certificate_chain(hello_prefs)))

        if max_workers > len(tasks):
            logging.warning(f'Max workers is {max_workers}, but only {len(tasks)} tasks were ever created')

        # Process tasks out of order, wait for all of them to finish, and stop on first exception.
        for i, _ in enumerate(pool.imap_unordered(lambda t: t(), tasks)):
            progress(i+1, len(tasks))

    result = ServerScanResult(
        host=host,
        port=port,
        proxy=proxy,
        protocols={},
        certificate_chain=tmp_certificate_chain if tmp_certificate_chain is not None else None,
    )

    # Finish processing the Server Hellos to detect compression and cipher suite order.
    for protocol, protocol_result in tmp_protocol_results.items():
        if protocol_result.cipher_suites:
            protocol_result.has_compression = protocol_result._cipher_suite_hellos[0].has_compression
            # The cipher suites in cipher_suite_hellos and group_hellos were sent in reversed order.
            # If the server accepted different cipher suites, then we know it respects the client order.
            protocol_result.has_cipher_suite_order = bool(protocol_result._cipher_suite_hellos) and protocol_result._cipher_suite_hellos[0].cipher_suite == protocol_result._group_hellos[0].cipher_suite
            protocol_result.has_post_quantum = any(group.is_pq for group in protocol_result.groups)
            result.protocols[protocol] = protocol_result
        else:
            result.protocols[protocol] = None

    return result

def parse_target(target:str, default_port:int = 443) -> tuple[str, int]:
    """
    Parses the target string into a host and port, stripping protocol and path.
    """
    import re
    from urllib.parse import urlparse
    if not re.match(r'\w+://', target):
        # Without a scheme, urlparse will treat the target as a path.
        # Prefix // to make it a netloc.
        url = urlparse('//' + target)
    else:
        url = urlparse(target, scheme='https')
    host = url.hostname or 'localhost'
    port = url.port if url.port else default_port
    return host, port

def to_json_obj(o: Any) -> Any:
    """
    Converts an object to a JSON-serializable structure, replacing dataclasses, enums, sets, datetimes, etc.
    """
    if isinstance(o, dict):
        return {to_json_obj(key): to_json_obj(value) for key, value in o.items()}
    elif dataclasses.is_dataclass(o):
        return to_json_obj(dataclasses.asdict(o))
    elif isinstance(o, set):
        return sorted(to_json_obj(item) for item in o)
    elif isinstance(o, (tuple, list)):
        return [to_json_obj(item) for item in o]
    elif isinstance(o, Enum):
        return o.name
    elif isinstance(o, datetime):
        return o.isoformat(' ')
    return o

def main():
    import os
    import argparse
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("target", help="server to scan, in the form of 'example.com', 'example.com:443', or even a full URL")
    parser.add_argument("--timeout", "-t", dest="timeout", type=float, default=DEFAULT_TIMEOUT, help=f"socket connection timeout in seconds")
    parser.add_argument("--max-workers", "-w", type=int, default=DEFAULT_MAX_WORKERS, help=f"maximum number of threads/concurrent connections to use for scanning")
    parser.add_argument("--server-name-indication", "-s", default='', help=f"value to be used in the SNI extension, defaults to the target host")
    parser.add_argument("--certs", "-c", default=True, action=argparse.BooleanOptionalAction, help="fetch the certificate chain using pyOpenSSL")
    parser.add_argument("--enumerate", "-e", dest='enumerate', default=True, action=argparse.BooleanOptionalAction, help="enumerate supported protocols, cipher suites, groups, compression, etc")
    parser.add_argument("--protocols", "-p", dest='protocols_str', default=','.join(p.name for p in Protocol), help="comma separated list of TLS/SSL protocols to test")
    parser.add_argument("--proxy", default=None, help="HTTP proxy to use for the connection, defaults to the env variable 'http_proxy' else no proxy")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="increase output verbosity")
    parser.add_argument("--progress", default=False, action=argparse.BooleanOptionalAction, help="write lines with progress percentages to stderr")
    args = parser.parse_args()

    logging.basicConfig(
        datefmt='%Y-%m-%d %H:%M:%S',
        format='{asctime}.{msecs:0<3.0f} {module} {threadName} {levelname}: {message}',
        style='{',
        level=[logging.WARNING, logging.INFO, logging.DEBUG][min(2, args.verbose)]
    )
    
    if not args.protocols_str:
        parser.error("no protocols to test")
    try:
        protocols = [Protocol[p] for p in args.protocols_str.split(',')]
    except KeyError as e:
        parser.error(f'invalid protocol name "{e.args[0]}", must be one of {", ".join(p.name for p in Protocol)}')

    host, port = parse_target(args.target)

    if args.certs and protocols == [Protocol.SSLv3]:
        parser.error("SSLv3 is not supported by pyOpenSSL, so `--protocols SSLv3` must be used with `--no-certs`")

    proxy = os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY') if args.proxy is None else args.proxy

    if args.progress:
        progress = lambda current, total: print(f'{current/total:.0%}', flush=True, file=sys.stderr)
        print('0%', flush=True, file=sys.stderr)
    else:
        progress = lambda current, total: None

    results = scan_server(
        host,
        port=port,
        protocols=protocols,
        enumerate_options=args.enumerate,
        fetch_cert_chain=args.certs,
        server_name_indication=args.server_name_indication,
        max_workers=args.max_workers,
        timeout_in_seconds=args.timeout,
        proxy=proxy,
        progress=progress,
    )

    json.dump(to_json_obj(results), sys.stdout, indent=2)

if __name__ == '__main__':
    main()