# Hello TLS!

This is a pure Python, dependency-less\* implementation of SSL/TLS Client Hello and basic scaning.

Its purpose is to quickly discover what cipher suites and SSL/TLS protocols are enabled on a server. Since the server doesn't advertise this list, instead picking from what is offered by the client, hello_tls.py sends a sequence of Client Hello with different cipher suite and protocol combinations. It usually needs less than 8 requests and 300 ms, but for servers with many cipher suites or high latency, bumping `max_workers` splits discovery over many threads.

There's no actual cryptography, just sending a stream of bytes and seeing if the server reply vaguely looks ok or not. Supports TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, and SSLv3.

\* Optionally, the certificate chain can be fetched and parsed, at the cost of relying on pyOpenSSL.

## Installation

Install via pip:

```bash
pip install hello_tls
python -m hello_tls boppreh.com --no-certs
```

or clone this repo:

```bash
git clone https://github.com/boppreh/hello_tls.git
cd hello_tls/src
python -m hello_tls boppreh.com --no-certs
```

## As a library

Main function signature:

```python
def scan_server(
    connection_settings: Union[ConnectionSettings, str],
    client_hello: Optional[ClientHello] = None,
    do_enumerate_cipher_suites: bool = True,
    do_enumerate_groups: bool = True,
    fetch_cert_chain: bool = True,
    max_workers: int = DEFAULT_MAX_WORKERS,
    progress: Callable[[int, int], None] = lambda current, total: None,
    ) -> ServerScanResult:
    ...
```

Usage:

```python
from hello_tls import scan_server
result = scan_server('boppreh.com')
print(result)
```

Output:

```python
ServerScanResult(
    connection=ConnectionSettings(
        host="boppreh.com",
        port=443,
        proxy=None,
        timeout_in_seconds=2,
        date=datetime(2024, 1, 14, 23, 49, 33, tzinfo=datetime.timezone.utc),
    ),
    protocols={
        SSLv3: None,
        TLS1_0: None,
        TLS1_1: None,
        TLS1_2: ProtocolResult(
            has_compression=False,
            has_cipher_suite_order=None,
            has_post_quantum=None,
            groups=None,
            cipher_suites=[
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ],
        ),
        TLS1_3: ProtocolResult(
            has_compression=False,
            has_cipher_suite_order=False,
            has_post_quantum=False,
            groups=[x25519, secp256r1],
            cipher_suites=[
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
            ],
        ),
    },
    requires_sni=True,
    accepts_bad_sni=False,
    client_ca_names=[]
    certificate_chain=[
        Certificate(...),
        Certificate(...),
        Certificate(...),
    ],
)

```

## As a command line application

```bash
python -m hello_tls boppreh.com
```
```json
{
  "connection": {
    "host": "boppreh.com",
    "port": 443,
    "proxy": null,
    "timeout_in_seconds": 2,
    "date": "2024-07-02 17:17:36+00:00"
  },
  "protocols": {
    "TLS1_3": null,
    "TLS1_2": {
      "has_compression": false,
      "has_cipher_suite_order": null,
      "has_post_quantum": null,
      "groups": null,
      "cipher_suites": [
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
      ]
    },
    "TLS1_1": null,
    "TLS1_0": null,
    "SSLv3": null
  },
  "requires_sni": true,
  "accepts_bad_sni": false,
  "client_ca_names": [],
  "certificate_chain": [
    {
      "serial_number": "295893172444948417823726078506384416865360",
      "fingerprint_sha256": "5F:32:F6:D8:AE:F6:66:18:8D:93:14:21:43:67:AF:CC:8F:23:C2:8C:CC:BB:CC:90:B0:71:84:8F:FE:7A:81:0E",
      "subject": {
        "CN": "boppreh.com"
      },
      "issuer": {
        "C": "US",
        "O": "Let's Encrypt",
        "CN": "R3"
      },
      "subject_alternative_names": [
        "boppreh.com"
      ],
      "key_type": "EC",
      "key_length_in_bits": 256,
      "all_key_usage": [
        "Digital Signature",
        "TLS Web Server Authentication",
        "TLS Web Client Authentication"
      ],
      "not_before": "2024-05-15 07:04:08+00:00",
      "not_after": "2024-08-13 07:04:07+00:00",
      "is_expired": false,
      "days_until_expiration": 41,
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "keyUsage": "Digital Signature",
        "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
        "basicConstraints": "CA:FALSE",
        "subjectKeyIdentifier": "4A:9A:3C:75:B0:74:58:A9:C1:A0:6F:83:3E:2A:A0:24:6B:19:26:34",
        "authorityKeyIdentifier": "14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6",
        "authorityInfoAccess": "OCSP - URI:http://r3.o.lencr.org\nCA Issuers - URI:http://r3.i.lencr.org/",
        "subjectAltName": "DNS:boppreh.com",
        "certificatePolicies": "Policy: 2.23.140.1.2.1",
        "ct_precert_scts": "Signed Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 48:B0:E3:6B:DA:A6:47:34:0F:E5:6A:02:FA:9D:30:EB:\n                1C:52:01:CB:56:DD:2C:81:D9:BB:BF:AB:39:D8:84:73\n    Timestamp : May 15 08:04:08.781 2024 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n
       30:45:02:20:2E:B3:9A:98:2F:87:09:0B:2A:FE:1B:44:\n                8C:CD:A0:3B:03:61:4C:CF:6F:61:7C:27:89:4D:B3:5A:\n                97:1A:20:CE:02:21:00:F3:2D:8F:9A:F1:72:E3:50:CF:\n                DF:7B:14:D0:07:D9:47:3C:DA:3C:2C:52:83:73:02:0D:\n                23:95:FD:09:62:B6:2E\nSigned Certificate Timestamp:\n    
Version   : v1 (0x0)\n    Log ID    : DF:E1:56:EB:AA:05:AF:B5:9C:0F:86:71:8D:A8:C0:32:\n                4E:AE:56:D9:6E:A7:F5:A5:6A:01:D1:C1:3B:BE:52:5C\n    Timestamp : May 15 08:04:09.015 2024 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:44:02:20:26:A7:E6:DA:8B:9A:6F:D2:92:E3:F6:B2:\n      
          5D:6C:B3:34:7A:47:F5:5D:86:F4:CB:DD:E7:F7:D4:02:\n                27:87:DE:14:02:20:3E:25:03:7E:52:4B:3B:4C:08:AD:\n                5C:AB:81:1F:27:0B:2D:06:DD:C4:E2:D4:69:8E:51:8D:\n                EB:70:DD:51:59:74"
      },
      "pem": "-----BEGIN CERTIFICATE-----\nMIIEFzCCAv+gAwIBAgISA2WNSB16OSm7PhT3t6zOvHxQMA0GCSqGSIb3DQEBCwUA\nMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\nEwJSMzAeFw0yNDA1MTUwNzA0MDhaFw0yNDA4MTMwNzA0MDdaMBYxFDASBgNVBAMT\nC2JvcHByZWguY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEorAmsmsRficI\nyYDurgDeqSzX1WfuscgVS/e2wkYSIuyoDT4K/kNonCwC+qe6MSgybvSZH9UIAxzI\nsDJ4O9Yhf6OCAgwwggIIMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEF\nBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUSpo8dbB0WKnB\noG+DPiqgJGsZJjQwHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYI\nKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMuby5sZW5jci5vcmcw\nIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8wFgYDVR0RBA8wDYIL\nYm9wcHJlaC5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwggEDBgorBgEEAdZ5AgQC\nBIH0BIHxAO8AdgBIsONr2qZHNA/lagL6nTDrHFIBy1bdLIHZu7+rOdiEcwAAAY97\nR7fNAAAEAwBHMEUCIC6zmpgvhwkLKv4bRIzNoDsDYUzPb2F8J4lNs1qXGiDOAiEA\n8y2PmvFy41DP33sU0AfZRzzaPCxSg3MCDSOV/Qliti4AdQDf4VbrqgWvtZwPhnGN\nqMAyTq5W2W6n9aVqAdHBO75SXAAAAY97R7i3AAAEAwBGMEQCICan5tqLmm/SkuP2\nsl1sszR6R/VdhvTL3ef31AInh94UAiA+JQN+Uks7TAitXKuBHycLLQbdxOLUaY5R\njetw3VFZdDANBgkqhkiG9w0BAQsFAAOCAQEAm7klMy/QfRKXw09ongrJz4HuOC99\n+r2I0UmhPE5aFVRV1tWSUUs8XEp2WOkZ/is1xKRauDdbncxbHOSM4+Oki/GHCw1O\nBuzfhB5kV2+IIJCMhaXIyejFttZso3FFTBELMrXeEqLgyc2H6Xsr46OBa0kH74nH\n/axER6z99vt1nFslhPj0I/2Q9jFijA+bAErcV0sFhFQch80ynLOmaeTX573nAEmT\nuHItoIfwgNsNWkTKhHHslMfDX6XTe7//5SUcoRbygNH3bVfH/Atvz5M7+Thf9pup\nj+u32K2uEE+KLUSQUBPM3rb//E7VoGb3aJNV3EAslZ4Ml+qoAtg7HeF3PA==\n-----END CERTIFICATE-----\n"
    },
    {
      "serial_number": "192961496339968674994309121183282847578",
      "fingerprint_sha256": "67:AD:D1:16:6B:02:0A:E6:1B:8F:5F:C9:68:13:C0:4C:2A:A5:89:96:07:96:86:55:72:A3:C7:E7:37:61:3D:FD",
      "subject": {
        "C": "US",
        "O": "Let's Encrypt",
        "CN": "R3"
      },
      "issuer": {
        "C": "US",
        "O": "Internet Security Research Group",
        "CN": "ISRG Root X1"
      },
      "subject_alternative_names": [],
      "key_type": "RSA",
      "key_length_in_bits": 2048,
      "all_key_usage": [
        "Digital Signature",
        "Certificate Sign",
        "CRL Sign",
        "TLS Web Client Authentication",
        "TLS Web Server Authentication"
      ],
      "not_before": "2020-09-04 00:00:00+00:00",
      "not_after": "2025-09-15 16:00:00+00:00",
      "is_expired": false,
      "days_until_expiration": 439,
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "keyUsage": "Digital Signature, Certificate Sign, CRL Sign",
        "extendedKeyUsage": "TLS Web Client Authentication, TLS Web Server Authentication",
        "basicConstraints": "CA:TRUE, pathlen:0",
        "subjectKeyIdentifier": "14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6",
        "authorityKeyIdentifier": "79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E",
        "authorityInfoAccess": "CA Issuers - URI:http://x1.i.lencr.org/",
        "crlDistributionPoints": "Full Name:\n  URI:http://x1.c.lencr.org/",
        "certificatePolicies": "Policy: 2.23.140.1.2.1\nPolicy: 1.3.6.1.4.1.44947.1.1.1"
      },
      "pem": "-----BEGIN CERTIFICATE-----\nMIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\nWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\nRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\nR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\nsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\nNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\nZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\nFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\nAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\nOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\ngt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\nPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\nikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\nCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\nlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\navAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\nyJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\nyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\nhCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\nHlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\nMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\nnLRbwHOoq7hHwg==\n-----END CERTIFICATE-----\n"
    }
  ]
}
```
