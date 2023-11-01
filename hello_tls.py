from multiprocessing.pool import ThreadPool, AsyncResult
from typing import Sequence, Any
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
# Default number of workers/threads/concurrent connectiosn to use.
DEFAULT_MAX_WORKERS: int = 6
# Maximum number of cipher suite groups to divide when enumerating.
MAX_WORKERS_PER_PROTOCOL: int = 3

@total_ordering
class Protocol(Enum):
    # Keep protocols in order of preference.
    TLS1_3 = b"\x03\x04"
    TLS1_2 = b"\x03\x03"
    TLS1_1 = b"\x03\x02"
    TLS1_0 = b"\x03\x01"
    SSLv3 = b"\x03\x00"

    def __str__(self):
        return self.name
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
    certificate_request = b'\x0D'
    certificate_verify = b'\x0F'
    finished = b'\x14'
    key_update = b'\x18'
    message_hash = b'\x19'

class Group(Enum):
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
    X25519Kyber768Draft00 = b'\x63\x99'
    SecP256r1Kyber768Draft00 = b'\x63\x9a'
    arbitrary_explicit_prime_curves = b'\xff\x01'
    arbitrary_explicit_char2_curves = b'\xff\x02'

@total_ordering
class CipherSuite(Enum):
    # Pseudo cipher suite, not actually picked.
    #TLS_EMPTY_RENEGOTIATION_INFO_SCSV = b"\x00\xff"

    # TLS 1.3 cipher suites.
    TLS_AES_128_GCM_SHA256 = b"\x13\x01"
    TLS_AES_256_GCM_SHA384 = b"\x13\x02"
    TLS_CHACHA20_POLY1305_SHA256 = b"\x13\x03"
    TLS_AES_128_CCM_SHA256 = b"\x13\x04"
    TLS_AES_128_CCM_8_SHA256 = b"\x13\x05"

    # TLS 1.2 and lower cipher suites.
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = b"\x00\x0a"
    TLS_RSA_WITH_AES_128_CBC_SHA = b"\x00\x2f"
    TLS_RSA_WITH_AES_256_CBC_SHA = b"\x00\x35"
    TLS_RSA_WITH_AES_128_GCM_SHA256 = b"\x00\x9c"
    TLS_RSA_WITH_AES_256_GCM_SHA384 = b"\x00\x9d"
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = b"\xc0\x09"
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = b"\xc0\x0a"
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = b"\xc0\x12"
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = b"\xc0\x13"
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = b"\xc0\x14"
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = b"\xc0\x2b"
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = b"\xc0\x2c"
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = b"\xc0\x2f"
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = b"\xc0\x30"
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = b"\xcc\xa8"
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = b"\xcc\xa9"

    # Old, old cipher suites.
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x19'
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = b'\x00\x17'
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = b'\x00\x1B'
    TLS_DH_anon_WITH_AES_128_CBC_SHA = b'\x00\x34'
    TLS_DH_anon_WITH_AES_128_CBC_SHA256 = b'\x00\x6C'
    TLS_DH_anon_WITH_AES_256_CBC_SHA = b'\x00\x3A'
    TLS_DH_anon_WITH_AES_256_CBC_SHA256 = b'\x00\x6D'
    TLS_DH_anon_WITH_DES_CBC_SHA = b'\x00\x1A'
    TLS_DH_anon_WITH_RC4_128_MD5 = b'\x00\x18'
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x0B'
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = b'\x00\x0D'
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = b'\x00\x30'
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = b'\x00\x3E'
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = b'\x00\x36'
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = b'\x00\x68'
    TLS_DH_DSS_WITH_DES_CBC_SHA = b'\x00\x0C'
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x0E'
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = b'\x00\x10'
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = b'\x00\x31'
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = b'\x00\x3F'
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = b'\x00\x37'
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = b'\x00\x69'
    TLS_DH_RSA_WITH_DES_CBC_SHA = b'\x00\x0F'
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x11'
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = b'\x00\x13'
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = b'\x00\x32'
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = b'\x00\x40'
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = b'\x00\x38'
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = b'\x00\x6A'
    TLS_DHE_DSS_WITH_DES_CBC_SHA = b'\x00\x12'
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x14'
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = b'\x00\x16'
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = b'\x00\x33'
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = b'\x00\x67'
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = b'\x00\x39'
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = b'\x00\x6B'
    TLS_DHE_RSA_WITH_DES_CBC_SHA = b'\x00\x15'
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = b'\x00\x29'
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = b'\x00\x26'
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = b'\x00\x2A'
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = b'\x00\x27'
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = b'\x00\x2B'
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA = b'\x00\x28'
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = b'\x00\x23'
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA = b'\x00\x1F'
    TLS_KRB5_WITH_DES_CBC_MD5 = b'\x00\x22'
    TLS_KRB5_WITH_DES_CBC_SHA = b'\x00\x1E'
    TLS_KRB5_WITH_IDEA_CBC_MD5 = b'\x00\x25'
    TLS_KRB5_WITH_IDEA_CBC_SHA = b'\x00\x21'
    TLS_KRB5_WITH_RC4_128_MD5 = b'\x00\x24'
    TLS_KRB5_WITH_RC4_128_SHA = b'\x00\x20'
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = b'\x00\x08'
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = b'\x00\x06'
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = b'\x00\x03'
    TLS_RSA_WITH_AES_128_CBC_SHA256 = b'\x00\x3C'
    TLS_RSA_WITH_AES_256_CBC_SHA256 = b'\x00\x3D'
    TLS_RSA_WITH_DES_CBC_SHA = b'\x00\x09'
    TLS_RSA_WITH_IDEA_CBC_SHA = b'\x00\x07'
    TLS_RSA_WITH_NULL_MD5 = b'\x00\x01'
    TLS_RSA_WITH_NULL_SHA = b'\x00\x02'
    TLS_RSA_WITH_NULL_SHA256 = b'\x00\x3B'
    TLS_RSA_WITH_RC4_128_MD5 = b'\x00\x04'
    TLS_RSA_WITH_RC4_128_SHA = b'\x00\x05'

    def __lt__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self.value < other.value
    def __str__(self):
        return self.name
    def __repr__(self):
        return self.name

TLS1_3_CIPHER_SUITES = [
    CipherSuite.TLS_AES_128_GCM_SHA256,
    CipherSuite.TLS_AES_256_GCM_SHA384,
    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_AES_128_CCM_SHA256,
    CipherSuite.TLS_AES_128_CCM_8_SHA256,
]
TLS1_2_AND_LOWER_CIPHER_SUITES = [suite for suite in CipherSuite if suite not in TLS1_3_CIPHER_SUITES]

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
    pass

class ServerAlertError(ScanError):
    def __init__(self, level: AlertLevel, description: AlertDescription):
        super().__init__(self, f'Server error: {level}: {description}')
        self.level = level
        self.description = description

class BadServerResponse(ScanError):
    """ Error for server responses that can't be parsed. """
    pass

class ConnectionError(ScanError):
    """ Class for error in resolving or connecting to a server. """
    pass

@dataclass
class ServerHello:
    version: Protocol
    has_compression: bool
    cipher_suite: CipherSuite
    group: Group | None

def try_parse_server_error(packet: bytes) -> ServerAlertError | None:
    """
    Parses a server alert packet, or None if the packet is not an alert.
    """
    # Alert record
    if packet[0:1] != RecordType.ALERT.value:
        return None
    record_type_int, legacy_record_version, length = struct.unpack('!c2sH', packet[:5])
    alert_level_id, alert_description_id = struct.unpack('!cc', packet[5:7])
    return ServerAlertError(AlertLevel(alert_level_id), AlertDescription(alert_description_id))

def parse_server_hello(packet: bytes) -> ServerHello:
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
    
    record_type = parse_next(1)
    assert record_type == RecordType.HANDSHAKE.value, record_type
    legacy_record_version = parse_next(2)
    handshake_length = parse_next(2)
    handshake_type = parse_next(1)
    assert handshake_type == HandshakeType.server_hello.value, handshake_type
    server_hello_length = parse_next(3)
    server_version = parse_next(2)
    server_random = parse_next(32)
    session_id_length = parse_next(1)
    session_id = parse_next(bytes_to_int(session_id_length))
    cipher_suite_bytes = parse_next(2)
    compression_method = parse_next(1)
    extensions_length = parse_next(2)
    extensions_end = start + bytes_to_int(extensions_length)

    # At most TLS 1.2. Handshakes for TLS 1.3 use the supported_versions extension.
    version = Protocol(server_version)
    group = None

    while start < extensions_end:
        extension_type = parse_next(2)
        extension_data_length = parse_next(2)
        extension_data = parse_next(bytes_to_int(extension_data_length))
        if extension_type == ExtensionType.supported_versions.value:
            version = Protocol(extension_data)
        elif extension_type == ExtensionType.key_share.value:
            try:
                group = Group(extension_data[:2])
            except ValueError:
                logger.warning(f'Unknown group: {extension_data[:2]!r}')
                pass
    
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
    server_host: str
    server_port: int = 443
    proxy: str | None = None
    timeout_in_seconds: float | None = DEFAULT_TIMEOUT

    server_name_indication: str | None = None # Defaults to server_host if not provided.
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
                                hello_prefs.server_name_indication or hello_prefs.server_host
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
            socket_host, socket_port = hello_prefs.server_host, hello_prefs.server_port
            return socket.create_connection((socket_host, socket_port), timeout=hello_prefs.timeout_in_seconds)

        if not hello_prefs.proxy.startswith('http://'):
            raise ConnectionError("Only HTTP proxies are supported at the moment.", hello_prefs.proxy)
        
        socket_host, socket_port = parse_target(hello_prefs.proxy, 80)

        sock = socket.create_connection((socket_host, socket_port), timeout=hello_prefs.timeout_in_seconds)
        sock.send(f"CONNECT {hello_prefs.server_host}:{hello_prefs.server_port} HTTP/1.1\r\nhost:{socket_host}\r\n\r\n".encode('utf-8'))
        sock_file = sock.makefile('r', newline='\r\n')
        line = sock_file.readline()
        if not re.fullmatch(r'HTTP/1\.[01] 200 Connection [Ee]stablished\r\n', line):
            sock_file.close()
            sock.close()
            raise ConnectionError("Proxy refused the connection: ", line)
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

def send_hello(hello_prefs: TlsHelloSettings) -> bytes:
    """
    Sends a Client Hello packet to the server based on hello_prefs, and returns the first few bytes of the server response.
    """
    logger.debug(f"Sending Client Hello to {hello_prefs.server_host}:{hello_prefs.server_port}")
    with make_socket(hello_prefs) as sock:
        sock.send(make_client_hello(hello_prefs))
        return sock.recv(1024)
    
def get_server_hello(hello_prefs: TlsHelloSettings) -> ServerHello:
    """
    Sends a Client Hello to the server, and returns the parsed ServerHello.
    Raises exceptions for the different alert messages the server can send.
    """
    response = send_hello(hello_prefs)
    if error := try_parse_server_error(response):
        logger.info(f"Server rejected Client Hello: {error.description.name}")
        raise error

    server_hello = parse_server_hello(response)
    
    if server_hello.version not in hello_prefs.protocols:
        # Server picked a protocol we didn't ask for.
        logger.info(f"Server attempted to downgrade protocol to unsupported version {server_hello.version}")
        raise BadServerResponse(f"Server attempted to downgrade from {hello_prefs.protocols} to {server_hello.version}")
    
    return server_hello

def enumerate_server_cipher_suites(hello_prefs: TlsHelloSettings) -> Sequence[CipherSuite]:
    """
    Given a list of cipher suites to test, sends a sequence of Client Hello packets to the server,
    removing the accepted cipher suite from the list each time.
    Returns a list of all cipher suites the server accepted.
    """
    logger.info(f"Testing support of {len(hello_prefs.cipher_suites)} cipher suites with protocols {hello_prefs.protocols}")
    cipher_suites_to_test = list(hello_prefs.cipher_suites)
    accepted_cipher_suites = []
    while cipher_suites_to_test:
        hello_prefs = dataclasses.replace(hello_prefs, cipher_suites=cipher_suites_to_test)
        try:
            cipher_suite_picked = get_server_hello(hello_prefs).cipher_suite
        except ServerAlertError as error:
            if error.description in [AlertDescription.protocol_version, AlertDescription.handshake_failure]:
                break
            raise
        accepted_cipher_suites.append(cipher_suite_picked)
        cipher_suites_to_test.remove(cipher_suite_picked)
    logger.info(f"Server accepted {len(accepted_cipher_suites)} cipher suites with protocols {hello_prefs.protocols}")
    return accepted_cipher_suites

def enumerate_server_groups(hello_prefs: TlsHelloSettings) -> Sequence[Group]:
    """
    Given a list of groups to test, sends a sequence of Client Hello packets to the server,
    removing the accepted group from the list each time.
    Returns a list of all groups the server accepted.
    """
    logger.info(f"Testing support of {len(hello_prefs.cipher_suites)} groups with protocols {hello_prefs.protocols}")
    groups_to_test = list(hello_prefs.groups)
    accepted_groups = []
    while groups_to_test:
        hello_prefs = dataclasses.replace(hello_prefs, groups=groups_to_test)
        try:
            group_picked = get_server_hello(hello_prefs).group
        except ServerAlertError as error:
            if error.description in [AlertDescription.protocol_version, AlertDescription.handshake_failure]:
                break
            raise
        if not group_picked or group_picked not in groups_to_test:
            break
        accepted_groups.append(group_picked)
        groups_to_test.remove(group_picked)
    logger.info(f"Server accepted {len(accepted_groups)} cipher suites with protocols {hello_prefs.protocols}")
    return accepted_groups

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
    all_key_usage: list[str] | None = dataclasses.field(init=False)
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

        self.all_key_usage = self.extensions.get('keyUsage', '').split(', ') + self.extensions.get('extendedKeyUsage', '').split(', ')
    
def get_server_certificate_chain(hello_prefs: TlsHelloSettings) -> Sequence[Certificate]:
    """
    Use socket and pyOpenSSL to get the server certificate chain.
    """
    from OpenSSL import SSL, crypto
    import ssl, select

    def _x509_name_to_dict(x509_name: crypto.X509Name) -> dict[str, str]:
        return {name.decode('utf-8'): value.decode('utf-8') for name, value in x509_name.get_components()}

    def _x509_time_to_datetime(x509_time: bytes | None) -> datetime:
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
        connection.set_tlsext_host_name((hello_prefs.server_name_indication or hello_prefs.server_host).encode('utf-8'))
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
    groups: Sequence[Group] | None
    cipher_suites: Sequence[CipherSuite]

@dataclass
class ServerScanResult:
    host: str
    port: int
    proxy: str | None
    protocols: dict[Protocol, ProtocolResult | None]
    certificate_chain: list[Certificate] | None

def scan_server(
    host: str,
    port: int = 443,
    protocols: Sequence[Protocol] = tuple(Protocol),
    enumerate_options: bool = True,
    fetch_cert_chain: bool = True,
    server_name_indication: str | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    timeout_in_seconds: float | None = DEFAULT_TIMEOUT,
    proxy:str | None = None,
    progress: bool = False,
    ) -> ServerScanResult:
    """
    Scans a SSL/TLS server for supported protocols, cipher suites, and certificate chain.

    `fetch_certificate_chain` can be used to load the certificate chain, at the cost of using pyOpenSSL.

    Runs scans in parallel to speed up the process, with up to `max_workers` threads connecting at the same time.
    """
    logger.info(f"Scanning {host}:{port}")
    hello_prefs = TlsHelloSettings(host, port, proxy, timeout_in_seconds, server_name_indication=server_name_indication, protocols=protocols)

    result = ServerScanResult(
        host=host,
        port=port,
        proxy=proxy,
        protocols={p: None for p in Protocol},
        certificate_chain=None,
    )

    tasks: list[AsyncResult] = []
    errors = []
    with ThreadPool(max_workers) as pool:
        logger.debug("Initializing workers")

        def report_progress(e):
            if progress:
                finished_tasks = (1 + sum(1 for task in tasks if task.ready()))
                print(f'{finished_tasks / len(tasks):.0%}', flush=True, file=sys.stderr)

        def add_task(f, args=(), ignore_errors=False):
            task = pool.apply_async(
                f, args,
                callback=report_progress,
                error_callback=lambda e: None if ignore_errors else errors.append(e)
            )
            tasks.append(task)
            return task

        if fetch_cert_chain:
            add_task(lambda: result.__setattr__(
                'certificate_chain',
                get_server_certificate_chain(hello_prefs)
            ))

        if enumerate_options:
            def save_protocol_results(server_hello_result, groups_result, cipher_suites_result, protocol):
                try:
                    server_hello = server_hello_result.get()
                    groups = groups_result.get()
                    cipher_suites = cipher_suites_result.get()
                except ServerAlertError:
                    return

                result.protocols[protocol] = ProtocolResult(
                    has_compression=server_hello.has_compression,
                    has_cipher_suite_order=bool(cipher_suites) and server_hello.cipher_suite == cipher_suites[0],
                    groups=groups,
                    cipher_suites=cipher_suites,
                )

            for protocol in protocols:
                suites_to_test = TLS1_3_CIPHER_SUITES if protocol == Protocol.TLS1_3 else TLS1_2_AND_LOWER_CIPHER_SUITES
                protocol_prefs = dataclasses.replace(hello_prefs, protocols=[protocol], cipher_suites=suites_to_test)
                reversed_prefs = dataclasses.replace(protocol_prefs, cipher_suites=list(reversed(suites_to_test)))
                
                # Create async tasks for each category of test.
                server_hello_result = add_task(get_server_hello, (protocol_prefs,), ignore_errors=True)
                groups_result = add_task(enumerate_server_groups, (protocol_prefs,), ignore_errors=True)
                # Reverse cipher suite order to check if the server respect the client preferences.
                cipher_suites_result = add_task(enumerate_server_cipher_suites, (reversed_prefs,), ignore_errors=True)

                # And schedule an async task to wait for the results and save them.
                add_task(save_protocol_results, (server_hello_result, groups_result, cipher_suites_result, protocol))

        pool.close()
        pool.join()

    if max_workers > len(tasks):
        logging.warning(f'Max workers is {max_workers}, but only {len(tasks)} tasks were ever created')

    if errors:
        # There'll be either a single error, or two identical errors. So we can raise just the first one.
        raise errors[0]

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
        progress=args.progress,
    )

    import sys
    json.dump(to_json_obj(results), sys.stdout, indent=2)

if __name__ == '__main__':
    main()