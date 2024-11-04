from typing import Iterator, List, Sequence, Optional, Iterable, Callable, Tuple
from contextlib import contextmanager
from dataclasses import dataclass
import logging

from .names_and_numbers import Protocol, RecordType, HandshakeType, CompressionMethod, CipherSuite, ExtensionType, Group, AlertLevel, AlertDescription, PskKeyExchangeMode

logger = logging.getLogger(__name__)

class ScanError(Exception):
    """ Base error class for errors that occur during scanning. """
    pass

class ServerAlertError(ScanError):
    def __init__(self, level: AlertLevel, description: AlertDescription):
        super().__init__(self, f'Server error: {level}: {description}')
        self.level = level
        self.description = description

class BadServerResponse(ScanError):
    """ Error for server responses that can't be parsed. """
    pass

@dataclass
class ServerHello:
    version: Protocol
    is_retry_request: bool
    compression: CompressionMethod
    cipher_suite: CipherSuite
    group: Optional[Group]

def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def parse_server_hello(packets: Iterable[bytes]) -> ServerHello:
    """
    Parses a Server Hello packet and returns the cipher suite accepted by the server.
    """
    start = 0
    packets_iter = iter(packets)
    data = next(packets_iter) # Buffer first packet.
    def read_next(length: int) -> bytes:
        """ Returns the next `length` unparsed bytes. """
        nonlocal start, data
        while start + length > len(data):
            try:
                # This is quadratic, but there are few packets to loop over.
                data += next(packets_iter)
            except StopIteration:
                raise BadServerResponse('Server response ended unexpectedly')
        value = data[start:start+length]
        start += length
        return value
    
    if data.startswith(b'HTTP/'):
        raise BadServerResponse('Server responded with plaintext HTTP, not TLS', data)

    record_type = RecordType(read_next(1))
    legacy_record_version = read_next(2)
    record_length = _bytes_to_int(read_next(2))
    record_end = start + record_length
    if record_type == RecordType.ALERT:
        # Server responded with an error.
        alert_level = AlertLevel(read_next(1))
        alert_description = AlertDescription(read_next(1))
        raise ServerAlertError(alert_level, alert_description)
    
    if record_type != RecordType.HANDSHAKE:
        raise BadServerResponse(f'Server responded with unexpected Record Type, expected {RecordType.HANDSHAKE} but got {record_type}')
    
    handshake_type = HandshakeType(read_next(1))
    assert handshake_type == HandshakeType.server_hello, handshake_type
    server_hello_length = _bytes_to_int(read_next(3))
    # At most TLS 1.2. Handshakes for TLS 1.3 use the supported_versions extension.
    version = Protocol(read_next(2))
    server_random = read_next(32)

    # Magic value meaning Hello Retry Request (see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4 ).
    # It's an error, but represented in server_random to maintain backwards compatibility.
    is_retry_request = server_random == b'\xCF\x21\xAD\x74\xE5\x9A\x61\x11\xBE\x1D\x8C\x02\x1E\x65\xB8\x91\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E\x07\x9E\x09\xE2\xC8\xA8\x33\x9C'

    session_id_length = read_next(1)
    session_id = read_next(_bytes_to_int(session_id_length))
    cipher_suite = CipherSuite(read_next(2))
    compression_method = CompressionMethod(read_next(1))
    if start + 2 <= record_end:
        extensions_length = _bytes_to_int(read_next(2))
    else: # extensions may not be present in TLS 1.2 and lower
        extensions_length = 0
    extensions_end = start + extensions_length

    group = None

    while start < extensions_end:
        try:
            extension_type = ExtensionType(read_next(2))
        except ValueError:
            # Ignore unknown extensions.
            continue
        extension_data_length = read_next(2)
        extension_data = read_next(_bytes_to_int(extension_data_length))
        if extension_type == ExtensionType.supported_versions:
            version = Protocol(extension_data)
        elif extension_type == ExtensionType.key_share:
            try:
                group = Group(extension_data[:2])
            except ValueError:
                logger.warning(f'Unknown group: {extension_data[:2]!r}')
                pass
    
    return ServerHello(version, is_retry_request, compression_method, cipher_suite, group)

@dataclass
class ClientHello:
    server_name: Optional[str] # No default value because you probably want to set this.
    protocols: Sequence[Protocol] = tuple(Protocol)
    cipher_suites: Sequence[CipherSuite] = tuple(CipherSuite)
    groups: Sequence[Group] = tuple(Group)
    compression_methods: Sequence[CompressionMethod] = tuple(CompressionMethod)

def make_client_hello(client_hello: ClientHello) -> bytes:
    """
    Creates a TLS Record byte string with Client Hello handshake based on client preferences.
    """
    # Because Python's `bytes` are immutable, we must use a list of octets instead.
    octets: List[int] = []

    # TLS really likes its length-prefixed data structures. I strongly prefer writing
    # the bytes in the order they'll be sent, so I use this helper context manager to
    # insert a dummy length, and come back to update it when the context exits.
    @contextmanager
    def prefix_length(block_name: str, width_bytes: int = 2) -> Iterator[None]:
        """ Inserts `width_bytes` bytes of zeros, and on exit fills it with the observed length. """
        start_index = len(octets)
        octets.extend(width_bytes*[0])
        yield None
        length = len(octets) - start_index - width_bytes
        octets[start_index:start_index+width_bytes] = length.to_bytes(width_bytes, byteorder="big")
    
    octets.extend(RecordType.HANDSHAKE.value)
    octets.extend(min(Protocol.TLS1_0, max(client_hello.protocols)).value) # Legacy record version: max TLS 1.0.
    with prefix_length('record'):
        octets.extend(HandshakeType.client_hello.value)
        
        with prefix_length('Client Hello', width_bytes=3):
            octets.extend(min(Protocol.TLS1_2, max(client_hello.protocols)).value) # Legacy client version: max TLS 1.2.
            octets.extend(32*[0x07]) # Random. Any value will do.

            with prefix_length('session ID', width_bytes=1):
                octets.extend(32*[0x07]) # Legacy session ID. Any value will do.

            with prefix_length('cipher Suites'):
                for cipher_suite in client_hello.cipher_suites:
                    octets.extend(cipher_suite.value)

            with prefix_length('compression methods', width_bytes=1):
                if Protocol.TLS1_3 in client_hello.protocols:
                    # Only NULL compression is allowed in TLS 1.3.
                    octets.extend(CompressionMethod.NULL.value)
                else:
                    for compression_method in client_hello.compression_methods:
                        octets.extend(compression_method.value)

            with prefix_length('extensions'):

                if client_hello.server_name is not None:
                    octets.extend(ExtensionType.server_name.value)
                    with prefix_length('server_name extension'):
                        with prefix_length('server_name list'):
                            octets.append(0x00) # Name type: host_name
                            with prefix_length('server_name'):
                                octets.extend(client_hello.server_name.encode('ascii'))

                octets.extend(ExtensionType.status_request.value)
                with prefix_length('status_request extension'):
                    octets.append(0x01) # Certificate status type: OCSP.
                    with prefix_length('status_request responder ID list'):
                        pass
                    with prefix_length('status_request information'):
                        pass

                octets.extend(ExtensionType.ec_point_formats.value)
                with prefix_length('EC point formats extension'):
                    with prefix_length('EC point formats list', width_bytes=1):
                        octets.append(0x00) # EC point format: uncompressed.
                        octets.append(0x01) # EC point format: ansiX962_compressed_prime.
                        octets.append(0x02) # EC point format: ansiX962_compressed_char2.

                octets.extend(ExtensionType.supported_groups.value)
                with prefix_length('supported_groups extension'):
                    with prefix_length('supported_groups list'):
                        for group in client_hello.groups:
                            octets.extend(group.value)

                octets.extend(ExtensionType.session_ticket.value)
                with prefix_length('session ticket extension'):
                    pass

                octets.extend(ExtensionType.encrypt_then_mac.value)
                with prefix_length('encrypt-then-MAC extension'):
                    pass

                octets.extend(ExtensionType.extended_master_secret.value)
                with prefix_length('extended master secret extension'):
                    pass

                octets.extend(ExtensionType.signature_algorithms.value)
                with prefix_length('signature algorithms extension'):
                    with prefix_length('signature algorithm list'):
                        octets.extend([
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
                        ])

                octets.extend(ExtensionType.signed_certificate_timestamp.value)
                with prefix_length('SCT extension'):
                    pass

                if Protocol.TLS1_3 in client_hello.protocols:
                    # This extension is only available in TLS 1.3.
                    octets.extend(ExtensionType.supported_versions.value)
                    with prefix_length('supported_versions extension'):
                        with prefix_length('supported_versions list', width_bytes=1):
                            for protocol in client_hello.protocols:
                                octets.extend(protocol.value)

                octets.extend(ExtensionType.psk_key_exchange_modes.value)
                with prefix_length('pre_shared_key_modes extension'):
                    with prefix_length('pre_shared_key_modes list', width_bytes=1):
                        octets.extend(PskKeyExchangeMode.psk_dhe_ke.value)

                # Add empty key_share extension
                # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
                # "This vector MAY be empty if the client is requesting a HelloRetryRequest. ... Clients MUST
                # NOT offer any KeyShareEntry values for groups not listed in the client's "supported_groups"
                # extension. Servers MAY check for violations of these rules and abort the handshake with an
                # "illegal_parameter" alert if one is violated."
                octets.extend(ExtensionType.key_share.value)
                with prefix_length('key_share extension'):
                    with prefix_length('key share bytes'):
                        pass

    return bytes(octets)
