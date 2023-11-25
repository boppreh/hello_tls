from multiprocessing.pool import ThreadPool
from typing import Sequence, Any, Callable, Optional, List
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import dataclasses
import logging
import socket
import struct
import re

from .names_and_numbers import Protocol, RecordType, HandshakeType, CompressionMethod, CipherSuite, ExtensionType, Group, AlertLevel, AlertDescription

logger = logging.getLogger(__name__)

# Default socket connection timeout, in seconds.
DEFAULT_TIMEOUT: float = 2
# Default number of workers/threads/concurrent connections to use.
DEFAULT_MAX_WORKERS: int = 6

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
        if record_type_value != RecordType.HANDSHAKE.value:
            start += record_length
        else:
            handshake_type_value = parse_next(1)
            handshake_length = bytes_to_int(parse_next(3))
            if handshake_type_value == HandshakeType.server_key_exchange.value:
                assert parse_next(1) == b'\x03', 'Expected curve type: named_curve'
                group = Group(parse_next(2))
                pubkey_length = bytes_to_int(parse_next(1))
                start += pubkey_length
                signature_algorithm = parse_next(2)
                signature_length = bytes_to_int(parse_next(2))
                start += signature_length
            elif handshake_type_value == HandshakeType.certificate.value:
                certificates_length = bytes_to_int(parse_next(3))
                start += certificates_length
            else:
                start += handshake_length
    
    cipher_suite = CipherSuite(cipher_suite_bytes)
    return ServerHello(version, compression_method != b'\x00', cipher_suite, group)

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
