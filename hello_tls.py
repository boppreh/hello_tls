from enum import Enum
import socket
import struct

class Protocol(Enum):
    SSL_3_0 = b"\x03\x00"
    TLS_1_0 = b"\x03\x01"
    TLS_1_1 = b"\x03\x02"
    TLS_1_2 = b"\x03\x03"
    TLS_1_3 = b"\x03\x04"

class CipherSuite(Enum):
    TLS_AES_128_GCM_SHA256 = b"\x13\x01"
    TLS_AES_256_GCM_SHA384 = b"\x13\x02"
    TLS_CHACHA20_POLY1305_SHA256 = b"\x13\x03"
    TLS_AES_128_CCM_SHA256 = b"\x13\x04"
    TLS_AES_128_CCM_8_SHA256 = b"\x13\x05"
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = b"\x00\xff"

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

class Alert(Enum):
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

def to_uint24(n):
    return n.to_bytes(3, byteorder="big")
def to_uint8(n):
    return n.to_bytes(1, byteorder="big")
def to_uint16(n):
    return n.to_bytes(2, byteorder="big")
def from_uint8(b):
    return int.from_bytes(b, byteorder="big")
from_uint16 = from_uint8

def generate_client_hello(server_name: str, allowed_protocols: list[Protocol]=list(Protocol), allowed_cipher_suites: list[CipherSuite]=list(CipherSuite)) -> bytes:
    # TLS 1.3 Client Hello
    # https://tools.ietf.org/html/rfc8446#section-4.1.2
    # https://tls13.xargs.org/#client-hello/annotated
    cipher_suites = b"".join(cipher_suite.value for cipher_suite in allowed_cipher_suites)

    curves = b"".join([
        b"\x00\x1d",  # Curve "x25519".
        b"\x00\x17",  # Curve "secp256r1".
        b"\x00\x1e",  # Curve "x448".
        b"\x00\x18",  # Curve "secp384r1".
        b"\x00\x19",  # Curve "secp521r1".
        b"\x01\x00",  # Curve "ffdhe2048".
        b"\x01\x01",  # Curve "ffdhe3072".
        b"\x01\x02",  # Curve "ffdhe4096".
        b"\x01\x03",  # Curve "ffdhe6144".
        b"\x01\x04",  # Curve "ffdhe8192".
    ])

    signature_algorithms = b"".join([
        b"\x04\x03", # ECDSA-SECP256r1-SHA256
        b"\x05\x03", # ECDSA-SECP384r1-SHA384
        b"\x06\x03", # ECDSA-SECP521r1-SHA512
        b"\x08\x07", # ED25519
        b"\x08\x08", # ED448
        b"\x08\x09", # RSA-PSS-PSS-SHA256
        b"\x08\x0a", # RSA-PSS-PSS-SHA384
        b"\x08\x0b", # RSA-PSS-PSS-SHA512
        b"\x08\x04", # RSA-PSS-RSAE-SHA256
        b"\x08\x05", # RSA-PSS-RSAE-SHA384
        b"\x08\x06", # RSA-PSS-RSAE-SHA512
        b"\x04\x01", # RSA-PKCS1-SHA256
        b"\x05\x01", # RSA-PKCS1-SHA384
        b"\x06\x01", # RSA-PKCS1-SHA512
        b"\x02\x01", # RSA-PKCS1-SHA1
        b"\x02\x03", # ECDSA-SHA1
    ])

    supported_versions = b"".join([
        b"\x03\x04",  # Supported versions: TLS 1.3.
        b"\x03\x03" * (Protocol.TLS_1_2 in allowed_protocols),  # Supported versions: TLS 1.2.
    ])

    supported_version_extension = (Protocol.TLS_1_3 in allowed_protocols) * b"".join([
        b"\x00\x2b",  # Extension type: supported version.
        to_uint16(len(supported_versions)+1), # Length of extension data.
        to_uint8(len(supported_versions)), # Supported versions length.
        supported_versions
    ])

    extensions = b"".join([
        b"\x00\x00",  # Extension type: server_name.
        to_uint16(len(server_name) + 5),  # Length of extension data.
        to_uint16(len(server_name) + 3),  # Length of server_name list.
        b"\x00",  # Name type: host_name.
        to_uint16(len(server_name)),  # Length of host_name.
        server_name.encode("ascii"),

        b"\x00\x05", # Extension type: status_request. Allow server to send OCSP information.
        b"\x00\x05", # Length of extension data.
        b"\x01", # Certificate status type: OCSP.
        b"\x00\x00", # Responder ID list length.
        b"\x00\x00", # Request extension information length.

        b"\x00\x0b",  # Extension type: EC point formats.
        b"\x00\x04",  # Length of extension data.
        b"\x03",  # Length of EC point formats list.
        b"\x00",  # EC point format: uncompressed.
        b"\x01",  # EC point format: ansiX962_compressed_prime.
        b"\x02",  # EC point format: ansiX962_compressed_char2.

        b"\x00\x0a",  # Extension type: supported groups (mostly EC curves).
        to_uint16(len(curves) + 2),  # Length of extension data.
        to_uint16(len(curves)),  # Length of supported groups list.
        curves,

        b"\x00\x23",  # Extension type: session ticket.
        b"\x00\x00",  # No session ticket data follows.

        b"\x00\x16",  # Extension type: encrypt-then-MAC.
        b"\x00\x00",  # Length of extension data.

        b"\x00\x17",  # Extension type: extended master secret.
        b"\x00\x00",  # No extension data follows.

        b"\x00\x0d",  # Extension type: signature algorithms.
        to_uint16(len(signature_algorithms) + 2),  # Length of extension data.
        to_uint16(len(signature_algorithms)),  # Length of algorithm list.
        signature_algorithms,

        b"\xff\x01", # Extension type: renegotiation_info (TLS 1.2 or lower).
        b"\x00\x01", # Length of extension data.
        b"\x00", # Renegotiation info length.

        b"\x00\x12", # Extension type: SCT. Allow server to return signed certificate timestamp.
        b"\x00\x00", # Length of extension data.

        supported_version_extension,

        # TODO: PSK key exchange modes extension.
        b"\x00\x2d\x00\x02\x01\x01",
        
        # TODO: key share extension.
        b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x35\x80\x72\xd6\x36\x58\x80\xd1\xae\xea\x32\x9a\xdf\x91\x21\x38\x38\x51\xed\x21\xa2\x8e\x3b\x75\xe9\x65\xd0\xd2\xcd\x16\x62\x54",
    ])

    client_hello = b"".join([
        b"\x03\x03",  # Legacy client version: TLS 1.2 (because ossification).
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",  # "Random".
        b"\x20",  # Legacy session ID length.
        b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",  # Legacy session ID.
        to_uint16(len(cipher_suites)),
        cipher_suites,
        b"\x01",  # Legacy compression methods length.
        b"\x00",  # Legacy compression method: null.
        to_uint16(len(extensions)),
        extensions,
    ])

    # Don't use struct.pack because it doesn't support 24bit integers.
    handshake = b"".join([
        b"\x01",  # Handshake type: Client Hello.
        to_uint24(len(client_hello)),
        client_hello,
    ])

    record = b"".join([
        b"\x16",  # Record type: handshake.
        b"\x03\x01",  # Legacy record version: TLS 1.0 (because ossification).
        to_uint16(len(handshake)),
        handshake,
    ])

    return record

def parse_server_hello(packet: bytes) -> CipherSuite:
    if packet[0] == 0x15:
        # Alert record
        record_type, legacy_record_version, length = struct.unpack('!BHH', packet[:5])
        assert record_type == 0x15
        assert legacy_record_version == 0x0303
        alert_level, alert_description_id = struct.unpack('!BB', packet[5:7])
        alert_level_str = {1: 'warning', 2: 'fatal'}[alert_level]
        raise ValueError(f'Server error: {alert_level_str}: {Alert(alert_description_id)}')
    
    assert packet[0] == 0x16
    
    begin_format = "!BHHB3sH32sB"
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
    assert legacy_record_version == 0x0303
    assert handshake_type == 0x02
    assert server_version == 0x0303
    assert session_id_length in [0, 0x20]

    cipher_suite_start = begin_length+session_id_length
    cipher_suite_id = packet[cipher_suite_start:cipher_suite_start+2]
    return CipherSuite(cipher_suite_id)

def enumerate_ciphers_suites(server_name: str, protocol=Protocol.TLS_1_3) -> list[CipherSuite]:
    accepted_cipher_suites: list[CipherSuite] = []
    remainig_cipher_suites: list[CipherSuite] = list(CipherSuite)
    while True:
        client_hello = generate_client_hello(server_name, allowed_protocols=[protocol], allowed_cipher_suites=remainig_cipher_suites)
        try:
            server_hello = send_hello(server_name, client_hello)
        except ValueError:
            break
        accepted_cipher_suites.append(server_hello)
        remainig_cipher_suites.remove(server_hello)
    return accepted_cipher_suites

def send_hello(server_name, client_hello):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_name, 443))
    s.send(client_hello)
    response = s.recv(4096)
    return parse_server_hello(response)

if __name__ == '__main__':
    print(enumerate_ciphers_suites('boppreh.com', Protocol.TLS_1_2))