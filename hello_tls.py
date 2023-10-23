from multiprocessing.pool import ThreadPool
from functools import total_ordering
from datetime import datetime
from typing import Sequence
from enum import Enum
import dataclasses
import logging
import socket
import struct

logger = logging.getLogger(__name__)

# Default socket connection timeout, in seconds.
DEFAULT_TIMEOUT: float = 2
# Default number of workers/threads/concurrent connectiosn to use.
DEFAULT_MAX_WORKERS: int = 6
# Maximum number of cipher suite groups to divide when enumerating.
MAX_WORKERS_PER_PROTOCOL: int = 3

@total_ordering
class Protocol(Enum):
    def __lt__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self.value < other.value

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

class RecordType(Enum):
    INVALID = 0 # Unused in this script.
    CHANGE_CIPHER_SPEC = 20 # Unused in this script.
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23 # Unused in this script.

class HandshakeType(Enum):
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    encrypted_extensions = 8
    certificate = 11
    certificate_request = 13
    certificate_verify = 15
    finished = 20
    key_update = 24
    message_hash = 25

@total_ordering
class CipherSuite(Enum):
    def __lt__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self.value < other.value
    
    # For compability.
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = b"\x00\xff"

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

TLS1_3_CIPHER_SUITES = [
    CipherSuite.TLS_AES_128_GCM_SHA256,
    CipherSuite.TLS_AES_256_GCM_SHA384,
    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_AES_128_CCM_SHA256,
    CipherSuite.TLS_AES_128_CCM_8_SHA256,
    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
]
TLS1_2_AND_LOWER_CIPHER_SUITES = [
    *(suite for suite in CipherSuite if suite not in TLS1_3_CIPHER_SUITES),
    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
]

class AlertLevel(Enum):
    """ Different alert levels that can be sent by the server. """
    WARNING = 1
    FATAL = 2

class AlertDescription(Enum):
    """ Different alert messages that can be sent by the server. """
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    record_overflow = 22
    handshake_failure = 40
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    missing_extension = 109
    unsupported_extension = 110
    unrecognized_name = 112
    bad_certificate_status_response = 113
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120

class ServerAlertError(Exception):
    def __init__(self, level: AlertLevel, description: AlertDescription):
        super().__init__(self, f'Server error: {level}: {description}')
        self.level = level
        self.description = description

@dataclasses.dataclass
class ServerHello:
    # TODO: parse more accurate protocol version by reading the TLS 1.3 extension.
    legacy_record_protocol: Protocol
    legacy_server_protocol: Protocol
    cipher_suite: CipherSuite

def try_parse_server_error(packet: bytes) -> ServerAlertError | None:
    """
    Parses a server alert packet, or None if the packet is not an alert.
    """
    # Alert record
    if packet[0] != RecordType.ALERT.value:
        return None
    record_type_int, legacy_record_version, length = struct.unpack('!B2sH', packet[:5])
    alert_level_id, alert_description_id = struct.unpack('!BB', packet[5:7])
    return ServerAlertError(AlertLevel(alert_level_id), AlertDescription(alert_description_id))

def parse_server_hello(packet: bytes) -> ServerHello:
    """
    Parses a Server Hello packet and returns the cipher suite accepted by the server.
    """
    record_type = RecordType(packet[0])

    if not packet:
        raise ValueError('Empty response')
    
    if error := try_parse_server_error(packet):
        raise error
    
    assert record_type == RecordType.HANDSHAKE
    
    begin_format = "!B2sHB3s2s32sB"
    begin_length = struct.calcsize(begin_format)
    begin_packet = packet[:begin_length]
    (
        record_type,
        legacy_record_version,
        handshake_length,
        handshake_type_int,
        server_hello_length,
        server_version,
        server_random,
        session_id_length,
    ) = struct.unpack(begin_format, begin_packet)

    assert HandshakeType(handshake_type_int) == HandshakeType.server_hello

    cipher_suite_start = begin_length+session_id_length
    cipher_suite_id = bytes(packet[cipher_suite_start:cipher_suite_start+2])
    return ServerHello(Protocol(legacy_record_version), Protocol(server_version), CipherSuite(cipher_suite_id))

@dataclasses.dataclass
class TlsHelloSettings:
    """
    Settings necessary to send a TLS Client Hello to a server.
    By default, all protocols and cipher suites are (claimed to be) supported.
    """
    server_host: str
    server_port: int = 443
    timeout_in_seconds: float | None = DEFAULT_TIMEOUT

    server_name_indication: str | None = None # Defaults to server_host if not provided.
    protocols: Sequence[Protocol] = tuple(Protocol)
    cipher_suites: Sequence[CipherSuite] = tuple(CipherSuite)

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
                0x01,  # Legacy compression methods length.
                0x00,  # Legacy compression method: null.
                
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
                        _prefix_length(bytes([ # Supported groups list.
                            0x00, 0x1d, # Curve "x25519".
                            0x00, 0x17, # Curve "secp256r1".
                            0x00, 0x1e, # Curve "x448".
                            0x00, 0x18, # Curve "secp384r1".
                            0x00, 0x19, # Curve "secp521r1".
                            0x01, 0x00, # Curve "ffdhe2048".
                            0x01, 0x01, # Curve "ffdhe3072".
                            0x01, 0x02, # Curve "ffdhe4096".
                            0x01, 0x03, # Curve "ffdhe6144".
                            0x01, 0x04, # Curve "ffdhe8192".
                        ]))
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

                    0xff, 0x01, # Extension type: renegotiation_info (TLS 1.2 or lower).
                    0x00, 0x01, # Length of extension data.
                    0x00, # Renegotiation info length.

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

def send_hello(hello_prefs: TlsHelloSettings) -> bytes:
    """
    Sends a Client Hello packet to the server based on hello_prefs, and returns the first few bytes of the server response.
    """
    logger.debug(f"Sending Client Hello to {hello_prefs.server_host}:{hello_prefs.server_port}")
    with socket.create_connection((hello_prefs.server_host, hello_prefs.server_port), timeout=hello_prefs.timeout_in_seconds) as sock:
        sock.send(make_client_hello(hello_prefs))
        return sock.recv(512)

def get_server_preferred_cipher_suite(hello_prefs: TlsHelloSettings) -> CipherSuite | None:
    """
    Attempts to connect to the server and returns the cipher suite picked by the server, if any.
    Protocol and cipher suite errors are swallowed, returning None, but other errors are raised.
    """
    response = send_hello(hello_prefs)
    if error := try_parse_server_error(response):
        logger.info(f"Server rejected Client Hello: {error.description.name}")
        if error.description in [AlertDescription.protocol_version, AlertDescription.handshake_failure]:
            return None
        else:
            raise error
    
    server_hello = parse_server_hello(response)
    is_protocol_expected = (
        server_hello.legacy_server_protocol in hello_prefs.protocols
        # Server version is always <=TLS 1.2 for compatibility reasons, it might actually be TLS 1.3.
        or server_hello.cipher_suite in TLS1_3_CIPHER_SUITES and Protocol.TLS1_3 in hello_prefs.protocols
    )
    if not is_protocol_expected:
        # Server picked a protocol we didn't ask for.
        logger.info(f"Server attempted to downgrade protocol to unsupported version {server_hello.legacy_server_protocol}")
        return None
    
    return server_hello.cipher_suite

def enumerate_server_cipher_suites(hello_prefs: TlsHelloSettings) -> set[CipherSuite]:
    """
    Given a list of cipher suites to test, sends a sequence of Client Hello packets to the server,
    removing the accepted cipher suite from the list each time.
    Returns a list of all cipher suites the server accepted.
    """
    logger.info(f"Testing support of {len(hello_prefs.cipher_suites)} cipher suites with protocols {hello_prefs.protocols}")
    cipher_suites_to_test = list(hello_prefs.cipher_suites)
    accepted_cipher_suites = set()
    while cipher_suites_to_test:
        hello_prefs = dataclasses.replace(hello_prefs, cipher_suites=cipher_suites_to_test)
        cipher_suite_picked = get_server_preferred_cipher_suite(hello_prefs)
        if cipher_suite_picked:
            accepted_cipher_suites.add(cipher_suite_picked)
            cipher_suites_to_test.remove(cipher_suite_picked)
        else:
            break
    logger.info(f"Server accepted {len(accepted_cipher_suites)} cipher suites with protocols {hello_prefs.protocols}")
    return accepted_cipher_suites

@dataclasses.dataclass
class Certificate:
    """
    Represents an X509 certificate in a chain sent by the server.
    """
    serial_number: int
    subject: dict[str, str]
    issuer: dict[str, str]
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    extensions: dict[str, str]

    @property
    def is_valid(self):
        return self.not_before < datetime.now() < self.not_after

    @property
    def days_until_expiration(self):
        return (self.not_after - datetime.now()).days
    
    @property
    def key_usage(self):
        return self.extensions.get('keyUsage', '').split(', ') + self.extensions.get('extendedKeyUsage', '').split(', ')
    
def get_server_certificate_chain(hello_prefs: TlsHelloSettings) -> Sequence[Certificate]:
    """
    Use socket and pyOpenSSL to get the server certificate chain.
    """
    from OpenSSL import SSL, crypto

    def _x509_name_to_dict(x509_name: crypto.X509Name) -> dict[str, str]:
        return {name.decode('utf-8'): value.decode('utf-8') for name, value in x509_name.get_components()}

    def _x509_time_to_datetime(x509_time: bytes | None) -> datetime:
        if x509_time is None:
            raise ValueError('Timestamp cannot be None')
        return datetime.strptime(x509_time.decode('ascii'), '%Y%m%d%H%M%SZ')
    
    no_flag_by_protocol = {
        Protocol.SSLv3: SSL.OP_NO_SSLv3,
        Protocol.TLS1_0: SSL.OP_NO_TLSv1,
        Protocol.TLS1_1: SSL.OP_NO_TLSv1_1,
        Protocol.TLS1_2: SSL.OP_NO_TLSv1_2,
        Protocol.TLS1_3: SSL.OP_NO_TLSv1_3,
    }
    logger.info("Fetching certificate chain with pyOpenSSL")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # This order of operations is necessary to work around a pyOpenSSL bug:
        # https://github.com/pyca/pyopenssl/issues/168#issuecomment-289194607
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        forbidden_versions = sum(no_flag_by_protocol[protocol] for protocol in Protocol if protocol not in hello_prefs.protocols)
        context.set_options(forbidden_versions)
        connection = SSL.Connection(context, sock)
        connection.settimeout(hello_prefs.timeout_in_seconds)
        connection.connect((hello_prefs.server_host, hello_prefs.server_port))
        connection.setblocking(True)
        
        # Necessary for servers that expect SNI. Otherwise expect "tlsv1 alert internal error".
        connection.set_tlsext_host_name((hello_prefs.server_name_indication or hello_prefs.server_host).encode('utf-8'))
        connection.do_handshake()
        connection.shutdown()

    raw_certs = connection.get_peer_cert_chain()

    if raw_certs is None:
        raise ValueError('Server did not give any certificate chain')
    
    logger.info(f"Received {len(raw_certs)} certificates")
    
    nice_certs: list[Certificate] = []
    for raw_cert in raw_certs:
        extensions: dict[str, str] = {}
        for i in range(raw_cert.get_extension_count()):
            extension = raw_cert.get_extension(i)
            extensions[extension.get_short_name().decode('utf-8')] = str(extension)
        
        nice_certs.append(Certificate(
            serial_number=raw_cert.get_serial_number(),
            subject=_x509_name_to_dict(raw_cert.get_subject()),
            issuer=_x509_name_to_dict(raw_cert.get_issuer()),
            not_before=_x509_time_to_datetime(raw_cert.get_notBefore()),
            not_after=_x509_time_to_datetime(raw_cert.get_notAfter()),
            signature_algorithm=raw_cert.get_signature_algorithm().decode('utf-8'),
            extensions=extensions,
        ))
    return nice_certs

@dataclasses.dataclass
class ServerScanResult:
    host: str
    port: int
    cipher_suites_per_protocol: dict[str, set[CipherSuite]]
    certificate_chain: list[Certificate] | None

def scan_server(
    host: str,
    port: int = 443,
    protocols: Sequence[Protocol] = tuple(Protocol),
    enumerate_cipher_suites: bool = True,
    fetch_cert_chain: bool = True,
    server_name_indication: str | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    timeout_in_seconds: float | None = DEFAULT_TIMEOUT
    ) -> ServerScanResult:
    """
    Scans a SSL/TLS server for supported protocols, cipher suites, and certificate chain.

    `fetch_certificate_chain` can be used to load the certificate chain, at the cost of using pyOpenSSL.

    Runs scans in parallel to speed up the process, with up to `max_workers` threads connecting at the same time.
    """
    logger.info(f"Scanning {host}:{port}")
    hello_prefs = TlsHelloSettings(host, port, timeout_in_seconds, server_name_indication=server_name_indication, protocols=protocols)

    result = ServerScanResult(
        host=host,
        port=port,
        cipher_suites_per_protocol={},
        certificate_chain=None,
    )

    tasks = []
    with ThreadPool(max_workers) as pool:
        logger.debug("Initializing workers")
        add_task = lambda f, args=(): tasks.append(pool.apply_async(f, args))

        if fetch_cert_chain:
            add_task(lambda: result.__setattr__(
                'certificate_chain',
                get_server_certificate_chain(hello_prefs)
            ))

        if enumerate_cipher_suites:
            # Add an intermediary name to appease the type checker.
            result.cipher_suites_per_protocol = {p.name: set() for p in protocols}

            def start_enumeration(protocol: Protocol):
                """ Checks if the server supports this protocol, and if so, start enumerating cipher suites. """
                suites_to_test = TLS1_3_CIPHER_SUITES if protocol == Protocol.TLS1_3 else TLS1_2_AND_LOWER_CIPHER_SUITES
                logger.debug(f"Testing server support for {protocol}")
                first_cipher_suite = get_server_preferred_cipher_suite(dataclasses.replace(hello_prefs, protocols=[protocol], cipher_suites=suites_to_test))
                if not first_cipher_suite:
                    # The server doesn't support this protocol at all.
                    logger.info(f"Server does not support {protocol}")
                    return
                # Register the cipher suite we found.
                accepted_cipher_suites = {first_cipher_suite}
                result.cipher_suites_per_protocol[protocol.name] = accepted_cipher_suites
                # Divide remaining cipher suites in groups and enumerate them in parallel.
                # Use % to distribute "desirable" cipher suites evenly.
                n_groups = min(max_workers, MAX_WORKERS_PER_PROTOCOL)
                groups = [[suite for i, suite in enumerate(suites_to_test) if i % n_groups == j and suite != first_cipher_suite] for j in range(n_groups)]
                logger.debug(f"Starting enumeration of cipher suites for {protocol}")
                for cipher_suite_group in groups:
                    prefs = dataclasses.replace(hello_prefs, protocols=[protocol], cipher_suites=cipher_suite_group)
                    add_task(lambda prefs=prefs: accepted_cipher_suites.update(enumerate_server_cipher_suites(prefs)))

            for protocol in protocols:
                add_task(start_enumeration, (protocol,))

        # Join all tasks, waiting for them to finish in any order.
        # pool.close() + pool.join() perform a similar job, but discard task errors.
        for task in tasks:
            task.get()

    return result

def main():
    import argparse
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("target", help="server to scan, in the form of 'example.com', 'example.com:443', or even a full URL")
    parser.add_argument("--timeout", "-t", dest="timeout", type=float, default=DEFAULT_TIMEOUT, help=f"socket connection timeout in seconds")
    parser.add_argument("--max-workers", "-w", type=int, default=DEFAULT_MAX_WORKERS, help=f"maximum number of threads/concurrent connections to use for scanning")
    parser.add_argument("--server-name-indication", "-s", default='', help=f"value to be used in the SNI extension, defaults to the target host")
    parser.add_argument("--certs", "-c", default=True, action=argparse.BooleanOptionalAction, help="fetch the certificate chain using pyOpenSSL")
    parser.add_argument("--enumerate-cipher-suites", "-e", dest='enumerate_cipher_suites', default=True, action=argparse.BooleanOptionalAction, help="enumerate supported cipher suites for each protocol")
    parser.add_argument("--protocols", "-p", dest='protocols_str', default=','.join(p.name for p in Protocol), help="comma separated list of TLS/SSL protocols to test")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="increase output verbosity")
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

    total_workers = int(args.certs) + int(args.enumerate_cipher_suites) * len(protocols) * MAX_WORKERS_PER_PROTOCOL
    if args.max_workers > total_workers:
        logging.warning(f'--max-workers is {args.max_workers}, but only {total_workers} workers will ever be used at once')

    from urllib.parse import urlparse
    if not '//' in args.target:
        # Without a scheme, urlparse will treat the target as a path.
        # Prefix // to make it a netloc.
        url = urlparse('//' + args.target)
    else:
        url = urlparse(args.target, scheme='https')
    host = url.hostname or 'localhost'
    port = url.port if url.port and url.scheme != 'http' else 443

    if args.certs and protocols == [Protocol.SSLv3]:
        parser.error("SSLv3 is not supported by pyOpenSSL, so `--protocols SSLv3` must be used with `--no-certs`")

    results = scan_server(
        host,
        port=port,
        protocols=protocols,
        enumerate_cipher_suites=args.enumerate_cipher_suites,
        fetch_cert_chain=args.certs,
        server_name_indication=args.server_name_indication,
        max_workers=args.max_workers,
        timeout_in_seconds=args.timeout,
    )

    import sys, json, dataclasses
    class EnhancedJSONEncoder(json.JSONEncoder):
        """ Converts non-primitive objects to JSON """
        def default(self, o):
            if dataclasses.is_dataclass(o):
                return dataclasses.asdict(o)
            if isinstance(o, set):
                return sorted(o)
            elif isinstance(o, Enum):
                return o.name
            elif isinstance(o, datetime):
                return o.isoformat()
            return super().default(o)
    json.dump(results, sys.stdout, indent=2, cls=EnhancedJSONEncoder)

if __name__ == '__main__':
    main()