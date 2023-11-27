from multiprocessing.pool import ThreadPool
import socket
import re
from typing import Sequence, List, Optional, Iterator, Callable, Any
from urllib.parse import urlparse

import dataclasses
from datetime import datetime, timezone
from .protocol import ClientHello, ScanError, make_client_hello, parse_server_response, ServerAlertError, BadServerResponse, ServerHello, logger
from .names_and_numbers import AlertDescription, CipherSuite, Group, Protocol, CompressionMethod

# Default number of workers/threads/concurrent connections to use.
DEFAULT_MAX_WORKERS: int = 6

# Default socket connection timeout, in seconds.
DEFAULT_TIMEOUT: float = 2

class DowngradeError(ScanError):
    """ Error for servers that attempt to downgrade beyond supported versions. """
    pass

class ConnectionError(ScanError):
    """ Class for error in resolving or connecting to a server. """
    pass

class ProxyError(ConnectionError):
    """ Class for errors in connecting through a proxy. """
    pass

@dataclasses.dataclass
class ConnectionSettings:
    """
    Settings for a connection to a server, including the host, port, and proxy.
    """
    host: str
    port: int = 443
    proxy: Optional[str] = None
    timeout_in_seconds: Optional[float] = DEFAULT_TIMEOUT

def make_socket(settings: ConnectionSettings) -> socket.socket:
    """
    Creates and connects a socket to the target server, through the chosen proxy if any.
    """
    socket_host, socket_port = None, None # To appease the type checker.
    try:
        if not settings.proxy:
            socket_host, socket_port = settings.host, settings.port
            return socket.create_connection((socket_host, socket_port), timeout=settings.timeout_in_seconds)

        if not settings.proxy.startswith('http://'):
            raise ProxyError("Only HTTP proxies are supported at the moment.", settings.proxy)
        
        socket_host, socket_port = parse_target(settings.proxy, 80)

        sock = socket.create_connection((socket_host, socket_port), timeout=settings.timeout_in_seconds)
        sock.send(f"CONNECT {settings.host}:{settings.port} HTTP/1.1\r\nhost:{socket_host}\r\n\r\n".encode('utf-8'))
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
        raise ConnectionError(f"Connection to {socket_host}:{socket_port} timed out after {settings.timeout_in_seconds} seconds") from e
    except socket.gaierror as e:
        raise ConnectionError(f"Could not resolve host {socket_host}") from e
    except socket.error as e:
        raise ConnectionError(f"Could not connect to {socket_host}:{socket_port}") from e

def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello, parse_additional_records: bool = False) -> ServerHello:
    """
    Sends a Client Hello to the server, and returns the parsed ServerHello.
    Raises exceptions for the different alert messages the server can send.
    """
    sock = make_socket(connection_settings)
    sock.send(make_client_hello(client_hello))

    packet_stream = iter(lambda: sock.recv(4096), b'')
    server_hello = parse_server_response(packet_stream, parse_additional_records)
    
    if server_hello.version not in client_hello.protocols:
        # Server picked a protocol we didn't ask for.
        logger.info(f"Server attempted to downgrade protocol to unsupported version {server_hello.version}")
        raise DowngradeError(f"Server attempted to downgrade from {client_hello.protocols} to {server_hello.version}")
    
    return server_hello

def _iterate_server_option(connection_settings: ConnectionSettings, client_hello: ClientHello, request_option: str, response_option: str, on_response: Callable[[ServerHello], None] = lambda s: None, parse_additional_records: bool = False) -> Iterator[Any]:
    """
    Continually sends Client Hello packets to the server, removing the `response_option` from the list of options each time,
    until the server rejects the handshake.
    """
    # We'll be mutating the list of options, so make a copy.
    options_to_test = list(getattr(client_hello, request_option))
    # TODO: figure out how to have mypy accept this line.
    client_hello = dataclasses.replace(client_hello, **{request_option: options_to_test}) # type: ignore

    logger.info(f"Enumerating server {response_option} with {len(options_to_test)} options and protocols {client_hello.protocols}")

    while options_to_test:
        try:
            logger.debug(f"Offering {len(options_to_test)} {response_option} over {client_hello.protocols}: {options_to_test}")
            server_hello = send_hello(connection_settings, client_hello, parse_additional_records=parse_additional_records)
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

def enumerate_server_cipher_suites(connection_settings: ConnectionSettings, client_hello: ClientHello, on_response: Callable[[ServerHello], None] = lambda s: None) -> Sequence[CipherSuite]:
    """
    Given a list of cipher suites to test, sends a sequence of Client Hello packets to the server,
    removing the accepted cipher suite from the list each time.
    Returns a list of all cipher suites the server accepted.
    """
    return list(_iterate_server_option(connection_settings, client_hello, 'cipher_suites', 'cipher_suite', on_response, parse_additional_records=False))

def enumerate_server_groups(connection_settings: ConnectionSettings, client_hello: ClientHello, on_response: Callable[[ServerHello], None] = lambda s: None) -> Sequence[Group]:
    """
    Given a list of groups to test, sends a sequence of Client Hello packets to the server,
    removing the accepted group from the list each time.
    Returns a list of all groups the server accepted.
    """
    return list(_iterate_server_option(connection_settings, client_hello, 'groups', 'group', on_response, parse_additional_records=True))

@dataclasses.dataclass
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
    
def get_server_certificate_chain(connection_settings: ConnectionSettings, client_hello: ClientHello) -> Sequence[Certificate]:
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
    with make_socket(connection_settings) as sock:
        # This order of operations is necessary to work around a pyOpenSSL bug:
        # https://github.com/pyca/pyopenssl/issues/168#issuecomment-289194607
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        forbidden_versions = sum(no_flag_by_protocol[protocol] for protocol in Protocol if protocol not in client_hello.protocols)
        context.set_options(forbidden_versions)
        connection = SSL.Connection(context, sock)
        connection.set_connect_state()        
        # Necessary for servers that expect SNI. Otherwise expect "tlsv1 alert internal error".
        connection.set_tlsext_host_name((client_hello.server_name or connection_settings.host).encode('utf-8'))
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

@dataclasses.dataclass
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

@dataclasses.dataclass
class ServerScanResult:
    connection: ConnectionSettings
    protocols: dict[Protocol, Optional[ProtocolResult]]
    certificate_chain: list[Certificate]

def scan_server(
    connection_settings: ConnectionSettings,
    client_hello: Optional[ClientHello] = None,
    do_enumerate_cipher_suites: bool = True,
    do_enumerate_groups: bool = True,
    fetch_cert_chain: bool = True,
    max_workers: int = DEFAULT_MAX_WORKERS,
    progress: Callable[[int, int], None] = lambda current, total: None,
    ) -> ServerScanResult:
    """
    Scans a SSL/TLS server for supported protocols, cipher suites, and certificate chain.

    `fetch_cert_chain` can be used to load the certificate chain, at the cost of using pyOpenSSL.

    Runs scans in parallel to speed up the process, with up to `max_workers` threads connecting at the same time.
    """
    logger.info(f"Scanning {connection_settings.host}:{connection_settings.port}")

    if not client_hello:
        client_hello = ClientHello(server_name=connection_settings.host)            

    tmp_certificate_chain: List[Certificate] = []
    tmp_protocol_results = {p: ProtocolResult(False, False, False, [], []) for p in Protocol}

    with ThreadPool(max_workers) as pool:
        logger.debug("Initializing workers")

        tasks: List[Callable[[], None]] = []

        def scan_protocol(protocol):
            protocol_result = tmp_protocol_results[protocol]
            suites_to_test = [cs for cs in CipherSuite if protocol in cs.protocols]

            if do_enumerate_cipher_suites:
                cipher_suite_hello = dataclasses.replace(client_hello, protocols=[protocol], cipher_suites=suites_to_test)
                # Save the cipher suites to protocol results, and store each Server Hello for post-processing of other options.
                tasks.append(lambda: protocol_result.cipher_suites.extend(enumerate_server_cipher_suites(connection_settings, cipher_suite_hello, protocol_result._cipher_suite_hellos.append)))

            if do_enumerate_groups:
                # Submit reversed list of cipher suites when checking for groups, to detect servers that respect user cipher suite order.
                group_hello = dataclasses.replace(client_hello, protocols=[protocol], cipher_suites=list(reversed(suites_to_test)))
                tasks.append(lambda: protocol_result.groups.extend(enumerate_server_groups(connection_settings, group_hello, protocol_result._group_hellos.append)))

        for protocol in client_hello.protocols:
            # Must be extracted to a function to avoid late binding in task lambdas.
            scan_protocol(protocol)

        if fetch_cert_chain:
            tasks.append(lambda: tmp_certificate_chain.extend(get_server_certificate_chain(connection_settings, client_hello)))

        if max_workers > len(tasks):
            logger.warning(f'Max workers is {max_workers}, but only {len(tasks)} tasks were ever created')

        # Process tasks out of order, wait for all of them to finish, and stop on first exception.
        for i, _ in enumerate(pool.imap_unordered(lambda t: t(), tasks)):
            progress(i+1, len(tasks))

    result = ServerScanResult(
        connection=connection_settings,
        protocols={},
        certificate_chain=tmp_certificate_chain,
    )

    # Finish processing the Server Hellos to detect compression and cipher suite order.
    for protocol, protocol_result in tmp_protocol_results.items():
        if protocol_result.cipher_suites or protocol_result.groups:
            protocol_result.has_compression = (protocol_result._cipher_suite_hellos or protocol_result._group_hellos)[0].compression != CompressionMethod.NULL
            # The cipher suites in cipher_suite_hellos and group_hellos were sent in reversed order.
            # If the server accepted different cipher suites, then we know it respects the client order.
            protocol_result.has_cipher_suite_order = bool(protocol_result._cipher_suite_hellos and protocol_result._group_hellos) and protocol_result._cipher_suite_hellos[0].cipher_suite == protocol_result._group_hellos[0].cipher_suite
            protocol_result.has_post_quantum = any(group.is_pq for group in protocol_result.groups)
            result.protocols[protocol] = protocol_result
        else:
            result.protocols[protocol] = None

    return result

def parse_target(target:str, default_port:int = 443) -> tuple[str, int]:
    """
    Parses the target string into a host and port, stripping protocol and path.
    """
    if not re.match(r'\w+://', target):
        # Without a scheme, urlparse will treat the target as a path.
        # Prefix // to make it a netloc.
        url = urlparse('//' + target)
    else:
        url = urlparse(target, scheme='https')
    host = url.hostname or 'localhost'
    port = url.port if url.port else default_port
    return host, port
