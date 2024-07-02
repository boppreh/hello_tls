import pytest
from hello_tls import *

def test_implicit_connection_settings(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        assert connection_settings.host == 'example.com'
        assert client_hello.server_name == 'example.com'
        assert connection_settings.port == 443
        raise ServerHelloRetryRequestError()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False)

def test_bad_response_error(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        raise BadServerResponse()
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    with pytest.raises(BadServerResponse):
        scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=False)

def test_test_sni_requires_correct(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        if client_hello.server_name != connection_settings.host:
            raise ServerHelloRetryRequestError()
        return scan.ServerHello(cipher_suite=client_hello.cipher_suites[0], compression=CompressionMethod.NULL, group=None, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=True, do_enumerate_cipher_suites=False)
    assert result.accepts_bad_sni == False
    assert result.requires_sni == True

def test_test_sni_requires_any(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        if client_hello.server_name is None:
            raise ServerHelloRetryRequestError()
        return scan.ServerHello(cipher_suite=client_hello.cipher_suites[0], compression=CompressionMethod.NULL, group=None, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=True, do_enumerate_cipher_suites=False)
    assert result.accepts_bad_sni == True
    assert result.requires_sni == True

def test_test_sni_optional_correct(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        if client_hello.server_name not in (None, connection_settings.host):
            raise ServerHelloRetryRequestError()
        return scan.ServerHello(cipher_suite=client_hello.cipher_suites[0], compression=CompressionMethod.NULL, group=None, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=True, do_enumerate_cipher_suites=False)
    assert result.accepts_bad_sni == False
    assert result.requires_sni == False

def test_test_sni_any(monkeypatch):
    def send_hello(connection_settings: ConnectionSettings, client_hello: ClientHello) -> scan.ServerHello:
        return scan.ServerHello(cipher_suite=client_hello.cipher_suites[0], compression=CompressionMethod.NULL, group=None, version=client_hello.protocols[0])
    monkeypatch.setattr(scan, 'send_hello', send_hello)
    result = scan.scan_server('example.com', fetch_cert_chain=False, do_test_sni=True, do_enumerate_cipher_suites=False)
    assert result.accepts_bad_sni == True
    assert result.requires_sni == False