from multiprocessing.pool import ThreadPool
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from typing import Sequence
import socket
import struct

# Default socket timeout, in seconds.
DEFAULT_TIMEOUT: float = 2

class Protocol(Enum):
    SSLv3 = b"\x03\x00"
    TLS_1_0 = b"\x03\x01"
    TLS_1_1 = b"\x03\x02"
    TLS_1_2 = b"\x03\x03"
    TLS_1_3 = b"\x03\x04"

class CipherSuite(Enum):
    # TLS 1.3 cipher suites.
    TLS_AES_128_GCM_SHA256 = b"\x13\x01"
    TLS_AES_256_GCM_SHA384 = b"\x13\x02"
    TLS_CHACHA20_POLY1305_SHA256 = b"\x13\x03"
    TLS_AES_128_CCM_SHA256 = b"\x13\x04"
    TLS_AES_128_CCM_8_SHA256 = b"\x13\x05"
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = b"\x00\xff"

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

class ServerError(Exception):
    def __init__(self, protocol: Protocol, level: AlertLevel, alert: AlertDescription):
        super().__init__(self, f'Server error ({protocol}): {level}: {alert}')
        self.protocol = protocol
        self.level = level
        self.alert = alert

@dataclass
class ServerHello:
    protocol: Protocol
    cipher_suite: CipherSuite

    @staticmethod
    def from_packet(packet: bytes):
        """
        Parses a Server Hello packet and returns the cipher suite accepted by the server.
        """
        if not packet:
            raise ValueError('Empty response')
        if packet[0] == 0x15:
            # Alert record
            record_type, legacy_record_version, length = struct.unpack('!B2sH', packet[:5])
            assert record_type == 0x15
            alert_level_id, alert_description_id = struct.unpack('!BB', packet[5:7])
            raise ServerError(Protocol(legacy_record_version), AlertLevel(alert_level_id), AlertDescription(alert_description_id))
        
        assert packet[0] == 0x16
        
        begin_format = "!BHHB3s2s32sB"
        begin_length = struct.calcsize(begin_format)
        begin_packet = packet[:begin_length]
        (
            record_type,
            legacy_record_version,
            handshake_length,
            handshake_type,
            server_hello_length,
            server_version,
            server_random,
            session_id_length,
        ) = struct.unpack(begin_format, begin_packet)

        assert record_type == 0x16
        assert legacy_record_version in [0x0301, 0x0302, 0x0303]
        assert handshake_type == 0x02
        assert session_id_length in [0, 0x20]

        cipher_suite_start = begin_length+session_id_length
        cipher_suite_id = packet[cipher_suite_start:cipher_suite_start+2]
        # TODO: protocol is wrong for TLS 1.3 because it appears as an extension.
        return ServerHello(Protocol(server_version), CipherSuite(cipher_suite_id))

def _prefix_length(b: bytes, width_bytes: int = 2) -> bytes:
    """
    Returns `b` prefixed with its length, encoded as a big-endian integer of `width_bytes` bytes.
    """
    return len(b).to_bytes(width_bytes, byteorder="big") + b
def _get_client_hello_version(allowed_protocols: Sequence[Protocol]) -> bytes:
    versions = [protocol.value for protocol in allowed_protocols]
    return min(Protocol.TLS_1_2.value, max(versions))
def _get_record_version(allowed_protocols: Sequence[Protocol]) -> bytes:
    # Record version cannot be higher than TLS 1.0 due to ossification.
    return max(Protocol.TLS_1_0.value, _get_client_hello_version(allowed_protocols))

@dataclass
class ClientHello:
    server_name: str
    allowed_protocols: Sequence[Protocol] = tuple(Protocol)
    allowed_cipher_suites: Sequence[CipherSuite] = tuple(CipherSuite)

    def make_packet(self) -> bytes:
        """
        Generates a Client Hello packet for the given server name and settings.
        """
        return bytes((
            0x16, # Record type: handshake.
            *_get_record_version(self.allowed_protocols), # Legacy record version: max TLS 1.0.
            *_prefix_length(bytes([ # Handshake record.
                0x01,  # Handshake type: Client Hello.
                *_prefix_length(width_bytes=3, b=bytes([ # Client hello handshake.
                    *_get_client_hello_version(self.allowed_protocols),  # Legacy client version: max TLS 1.2.
                    *32*[0x07],  # Random. Any value will do.
                    32,  # Legacy session ID length.
                    *32*[0x07],  # Legacy session ID. Any value will do.
                    *_prefix_length( # Cipher suites.
                        b"".join(cipher_suite.value for cipher_suite in self.allowed_cipher_suites)
                    ),
                    0x01,  # Legacy compression methods length.
                    0x00,  # Legacy compression method: null.
                    
                    *_prefix_length(bytes([ # Extensions.
                        0x00, 0x00,  # Extension type: server_name.
                        *_prefix_length( # Extension data.
                            _prefix_length( # server_name list
                                b'\x00' + # Name type: host_name.
                                _prefix_length(self.server_name.encode('ascii'))
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

                        *((Protocol.TLS_1_3 in self.allowed_protocols) * [ # This extension is only available in TLS 1.3.
                            0x00, 0x2b,  # Extension type: supported version.
                            *_prefix_length(
                                _prefix_length(
                                    b"".join(protocol.value for protocol in self.allowed_protocols),
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
    
    def send(self, port: int = 443, server_name: str | None = None, timeout_in_seconds: float | None = DEFAULT_TIMEOUT) -> ServerHello:
        """
        Sends a Client Hello packet to the server and returns the Server Hello packet.
        By default, sends the packet to the server specified in the constructor.
        """
        host = self.server_name if server_name is None else server_name
        with socket.create_connection((host, port), timeout=timeout_in_seconds) as s:
            s.send(self.make_packet())
            return ServerHello.from_packet(s.recv(4096))

def enumerate_server_cipher_suites(server_name: str, cipher_suites_to_test: Sequence[CipherSuite], protocol: Protocol = Protocol.TLS_1_3, port: int = 443, timeout_in_seconds: float | None = DEFAULT_TIMEOUT) -> Sequence[CipherSuite]:
    """
    Given a list of cipher suites to test, sends a sequence of Client Hello packets to the server,
    removing the accepted cipher suite from the list each time.
    Returns a list of all cipher suites the server accepted.
    """
    cipher_suites_to_test = list(cipher_suites_to_test)
    accepted_cipher_suites = []
    while cipher_suites_to_test:
        client_hello = ClientHello(server_name, allowed_protocols=[protocol], allowed_cipher_suites=cipher_suites_to_test)
        try:
            server_hello = client_hello.send(port=port, timeout_in_seconds=timeout_in_seconds)
        except ServerError as e:
            if e.alert == AlertDescription.handshake_failure:
                break
            else:
                raise e
        accepted_cipher_suites.append(server_hello.cipher_suite)
        cipher_suites_to_test.remove(server_hello.cipher_suite)
    return accepted_cipher_suites

@dataclass
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
    
def get_server_certificate_chain(server_name:str, port: int = 443, timeout_in_seconds: float | None = DEFAULT_TIMEOUT) -> Sequence[Certificate]:
    """
    Use socket and pyOpenSSL to get the server certificate chain.
    """
    from OpenSSL import SSL, crypto
    import socket

    def _x509_name_to_dict(x509_name: crypto.X509Name) -> dict[str, str]:
        return {name.decode('utf-8'): value.decode('utf-8') for name, value in x509_name.get_components()}

    def _x509_time_to_datetime(x509_time: bytes | None) -> datetime:
        if x509_time is None:
            raise ValueError('Timestamp cannot be None')
        return datetime.strptime(x509_time.decode('ascii'), '%Y%m%d%H%M%SZ')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        connection = SSL.Connection(SSL.Context(SSL.TLS_CLIENT_METHOD), sock)
        connection.connect((server_name, port))
        # Necessary for servers that expect SNI. Otherwise expect "tlsv1 alert internal error".
        connection.set_tlsext_host_name(server_name.encode('utf-8'))
        connection.do_handshake()

    raw_certs = connection.get_peer_cert_chain()

    if raw_certs is None:
        raise ValueError('Server did not give any certificate chain')
    
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

@dataclass
class ServerScanResult:
    protocol_support: dict[str, bool]
    cipher_suites_tls_1_2: list[CipherSuite]
    cipher_suites_tls_1_3: list[CipherSuite]
    certificate_chain: list[Certificate]

def scan_server(server_name: str, port: int = 443, fetch_certificate_chain: bool = True, max_workers: int = 5, timeout_in_seconds: float | None = DEFAULT_TIMEOUT) -> ServerScanResult:
    """
    Scans a SSL/TLS server for supported protocols, cipher suites, and certificate chain.

    `fetch_certificate_chain` can be used to load the certificate chain, at the cost of using pyOpenSSL.

    Runs scans in parallel to speed up the process, with up to `max_workers` threads connecting at the same time.
    """
    result = ServerScanResult(
        certificate_chain=[],
        protocol_support={p.name: False for p in Protocol},
        cipher_suites_tls_1_2=[],
        cipher_suites_tls_1_3=[]
    )

    def check_protocol_support(protocol: Protocol) -> None:
        try:
            ClientHello(server_name, allowed_protocols=[protocol]).send(port=port, timeout_in_seconds=timeout_in_seconds)
            result.protocol_support[protocol.name] = True
        except ServerError as e:
            result.protocol_support[protocol.name] = False

    with ThreadPool(max_workers) as pool:
        if fetch_certificate_chain:
            pool.apply_async(lambda: result.certificate_chain.extend(
                get_server_certificate_chain(server_name, port, timeout_in_seconds))
            )

        # How many workers to use for scanning cipher suites, per protocol.
        n_cipher_suite_scanners = max(1, max_workers//3)
        # Split list of cipher suites into `n_cipher_suite_scanners` chunks. Use % to distribute "more desirable" cipher suites evenly.
        cipher_suite_chunks = [[c for i, c in enumerate(CipherSuite) if i % n_cipher_suite_scanners == n] for n in range(n_cipher_suite_scanners)]
        for cipher_suites_to_test in cipher_suite_chunks:
            # Scan TLS 1.2 and TLS 1.3 separately because the cipher suites are different.
            pool.apply_async(
                enumerate_server_cipher_suites,
                (server_name, cipher_suites_to_test, Protocol.TLS_1_2, port, timeout_in_seconds),
                callback=result.cipher_suites_tls_1_2.extend
            )
            pool.apply_async(
                enumerate_server_cipher_suites,
                (server_name, cipher_suites_to_test, Protocol.TLS_1_3, port, timeout_in_seconds),
                callback=result.cipher_suites_tls_1_3.extend
            )

        for other_protocol in [Protocol.SSLv3, Protocol.TLS_1_0, Protocol.TLS_1_1]:
            pool.apply_async(
                check_protocol_support,
                (other_protocol,)
            )

        # Join all tasks to ensure they finish before returning.
        pool.close()
        pool.join()

    # Add higher protocol version support based on cipher suites found.
    result.protocol_support[Protocol.TLS_1_2.name] = len(result.cipher_suites_tls_1_2) > 0
    result.protocol_support[Protocol.TLS_1_3.name] = len(result.cipher_suites_tls_1_3) > 0

    return result

if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else 'boppreh.com'
    if ':' in target:
        server_name, port_str = target.split(':', 1)
        port = int(port_str)
    else:
        server_name = target
        port = 443

    import json, dataclasses
    class EnhancedJSONEncoder(json.JSONEncoder):
        """ Converts non-primitive objects to JSON """
        def default(self, o):
            if dataclasses.is_dataclass(o):
                return dataclasses.asdict(o)
            elif isinstance(o, Enum):
                return o.name
            elif isinstance(o, datetime):
                return o.isoformat()
            return super().default(o)
    print(json.dumps(scan_server(server_name, port=port, max_workers=6), indent=2, cls=EnhancedJSONEncoder))
