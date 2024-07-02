import pytest
from hello_tls import *

def test_implicit_connection_settings(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        assert connection_settings.host == 'example.com'
        assert client_hello.server_name == 'example.com'
        assert connection_settings.port == 443
        raise ServerHelloRetryRequestError()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False, do_enumerate_groups=False)

def test_parse_target(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        assert connection_settings.host == 'example.com'
        assert client_hello.server_name == 'example.com'
        assert connection_settings.port == 8443
        raise ServerHelloRetryRequestError()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    scan.scan_server('https://example.com:8443/sample/path?query#path', fetch_cert_chain=False, do_test_sni=False, do_enumerate_groups=False)

def test_parse_target_implicit_localhost(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        assert connection_settings.host == 'localhost'
        assert client_hello.server_name == 'localhost'
        assert connection_settings.port == 8443
        raise ServerHelloRetryRequestError()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    scan.scan_server(':8443', fetch_cert_chain=False, do_test_sni=False, do_enumerate_groups=False)

def test_explicit_args(monkeypatch):
    conn = ConnectionSettings(host='example.com')
    hello = ClientHello(None, [Protocol.TLS1_3])
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        assert connection_settings == conn
        assert client_hello.protocols == [Protocol.TLS1_3]
        assert client_hello.server_name is None
        raise ServerHelloRetryRequestError()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    scan.scan_server(conn, client_hello=hello, fetch_cert_chain=False, do_test_sni=False, do_enumerate_groups=False)

def test_bad_response_error(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        raise BadServerResponse()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    with pytest.raises(BadServerResponse):
        scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False, do_enumerate_groups=False)

def test_no_protocol(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        raise DowngradeError()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False, do_enumerate_groups=False)
    assert result.protocols == {protocol: None for protocol in Protocol}

def test_two_ciphersuites(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        for cipher_suite in [CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_GCM_SHA256]:
            if cipher_suite in client_hello.cipher_suites:
                return scan.ServerHello(cipher_suite=cipher_suite, compression=CompressionMethod.NULL, group=None, version=client_hello.protocols[0])
        raise DowngradeError()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False, do_enumerate_groups=False)
    assert set(result.protocols[Protocol.TLS1_3].cipher_suites) == set([CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_GCM_SHA256])

def test_two_groups(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        for group in [Group.X25519Kyber768Draft00, Group.p384_kyber768]:
            if group in client_hello.groups:
                return scan.ServerHello(group=group, compression=CompressionMethod.NULL, cipher_suite=CipherSuite.TLS_CHACHA20_POLY1305_SHA256, version=client_hello.protocols[0])
        raise DowngradeError()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False, do_enumerate_cipher_suites=False)
    assert set(result.protocols[Protocol.TLS1_3].groups) == set([Group.X25519Kyber768Draft00, Group.p384_kyber768])

def test_invalid_group_choice(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        return scan.ServerHello(cipher_suite=CipherSuite.TLS_AES_128_GCM_SHA256, compression=CompressionMethod.NULL, group=Group.X25519Kyber768Draft00, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False, do_enumerate_cipher_suites=False)
    assert result.protocols[Protocol.TLS1_3].groups == [Group.X25519Kyber768Draft00]

def test_has_ciphersuite_order(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        ciphersuites = sorted(client_hello.cipher_suites, key=lambda c: c.value)
        return scan.ServerHello(cipher_suite=ciphersuites[0], compression=CompressionMethod.NULL, group=Group.X25519Kyber768Draft00, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False)
    assert result.protocols[Protocol.TLS1_3].has_cipher_suite_order

def test_no_ciphersuite_order(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        return scan.ServerHello(cipher_suite=client_hello.cipher_suites[0], compression=CompressionMethod.NULL, group=Group.X25519Kyber768Draft00, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False)
    assert not result.protocols[Protocol.TLS1_3].has_cipher_suite_order

def test_test_sni_requires_correct(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        if client_hello.server_name != connection_settings.host:
            raise ServerHelloRetryRequestError()
        return scan.ServerHello(cipher_suite=client_hello.cipher_suites[0], compression=CompressionMethod.NULL, group=None, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=True, do_enumerate_cipher_suites=False, do_enumerate_groups=False)
    assert result.accepts_bad_sni == False
    assert result.requires_sni == True

def test_test_sni_requires_any(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        if client_hello.server_name is None:
            raise ServerHelloRetryRequestError()
        return scan.ServerHello(cipher_suite=client_hello.cipher_suites[0], compression=CompressionMethod.NULL, group=None, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=True, do_enumerate_cipher_suites=False, do_enumerate_groups=False)
    assert result.accepts_bad_sni == True
    assert result.requires_sni == True

def test_test_sni_optional_correct(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        if client_hello.server_name not in (None, connection_settings.host):
            raise ServerHelloRetryRequestError()
        return scan.ServerHello(cipher_suite=client_hello.cipher_suites[0], compression=CompressionMethod.NULL, group=None, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=True, do_enumerate_cipher_suites=False, do_enumerate_groups=False)
    assert result.accepts_bad_sni == False
    assert result.requires_sni == False

def test_test_sni_any(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        return scan.ServerHello(cipher_suite=client_hello.cipher_suites[0], compression=CompressionMethod.NULL, group=None, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=True, do_enumerate_cipher_suites=False, do_enumerate_groups=False)
    assert result.accepts_bad_sni == True
    assert result.requires_sni == False