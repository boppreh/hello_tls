# Hello TLS!

This is a pure Python, single-file, dependency-less implementation of SSL/TLS Client Hello.

There's no actual cryptography, just sending a stream of bytes and seeing if the server reply vaguely looks ok or not. Supports TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, and *maybe* SSLv3 (untested).

Its purpose is to quickly discover what cipher suites are enabled on a server. Since the server doesn't advertise this list, instead picking from what is offered by the client, hello_tls.py sends a sequence of Client Hello with different cipher suite combinations. It usually needs less than 5 requests and 200 ms, but for servers with many cipher suites or high latency, bumping `max_workers` splits discovery over many threads.

```python
def enumerate_ciphers_suites(server_name: str, protocol:Protocol = Protocol.TLS_1_3, port:int = 443, max_workers:int = 1) -> Sequence[CipherSuite]:
    ...

enumerate_ciphers_suites('google.com')
# [<CipherSuite.TLS_AES_128_GCM_SHA256: b'\x13\x01'>, <CipherSuite.TLS_AES_256_GCM_SHA384: b'\x13\x02'>, <CipherSuite.TLS_CHACHA20_POLY1305_SHA256: b'\x13\x03'>]
```