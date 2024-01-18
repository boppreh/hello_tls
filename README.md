# Hello TLS!

This is a pure Python, dependency-less\* implementation of SSL/TLS Client Hello and basic scaning.

Its purpose is to quickly discover what cipher suites and SSL/TLS protocols are enabled on a server. Since the server doesn't advertise this list, instead picking from what is offered by the client, hello_tls.py sends a sequence of Client Hello with different cipher suite and protocol combinations. It usually needs less than 8 requests and 300 ms, but for servers with many cipher suites or high latency, bumping `max_workers` splits discovery over many threads.

There's no actual cryptography, just sending a stream of bytes and seeing if the server reply vaguely looks ok or not. Supports TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, and SSLv3.

\* Optionally, the certificate chain can be fetched and parsed, at the cost of relying on pyOpenSSL.

## Installation

Install via pip:

```bash
pip install hello_tls
python -m hello_tls boppreh.com
```

or clone this repo:

```bash
git clone https://github.com/boppreh/hello_tls.git
cd hello_tls
python hello_tls.py boppreh.com
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
    "date": "2024-01-18 15:14:53+00:00"
  },
  "protocols": {
    "TLS1_3": {
      "has_compression": false,
      "has_cipher_suite_order": false,
      "has_post_quantum": false,
      "groups": [
        "x25519",
        "secp256r1"
      ],
      "cipher_suites": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
      ]
    },
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
  "certificate_chain": [
    {
      "serial_number": "382679495808622627988755972496471047742486",
      "fingerprint_sha256": "73:44:C4:28:3A:D7:2E:D3:66:C7:A3:10:5C:52:6D:15:3A:06:60:8F:A1:2F:93:EA:AF:44:80:A9:F2:FA:62:94",
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
      "not_before": "2024-01-16 08:51:52+00:00",
      "not_after": "2024-04-15 08:51:51+00:00",
      "is_expired": false,
      "days_until_expiration": 87,
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "keyUsage": "Digital Signature",
        "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
        "basicConstraints": "CA:FALSE",
        "subjectKeyIdentifier": "E4:B7:01:4A:1E:B0:8A:04:E8:3D:A0:95:4E:20:9E:E0:71:07:AC:F8",
        "authorityKeyIdentifier": "14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6",
        "authorityInfoAccess": "OCSP - URI:http://r3.o.lencr.org\nCA Issuers - URI:http://r3.i.lencr.org/",
        "subjectAltName": "DNS:boppreh.com",
        "certificatePolicies": "Policy: 2.23.140.1.2.1",
        "ct_precert_scts": "Signed Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 48:B0:E3:6B:DA:A6:47:34:0F:E5:6A:02:FA:9D:30:EB:\n                1C:52:01:CB:56:DD:2C:81:D9:BB:BF:AB:39:D8:84:73\n    Timestamp : Jan 16 09:51:52.657 2024 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:46:02:21:00:85:9A:35:BF:B0:FE:73:28:74:81:C2:\n                B0:19:E2:DB:8D:D9:E7:29:DC:A9:45:6E:42:AB:1B:2D:\n                47:3F:C0:B0:31:02:21:00:97:B8:4F:11:79:79:45:C6:\n                1C:75:0C:48:06:E4:C6:4F:D8:6A:F2:5F:B3:18:80:2A:\n                C5:51:CB:D7:42:94:79:56\nSigned Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : A2:E2:BF:D6:1E:DE:2F:2F:07:A0:D6:4E:6D:37:A7:DC:\n                65:43:B0:C6:B5:2E:A2:DA:B7:8A:F8:9A:6D:F5:17:D8\n    Timestamp : Jan 16 09:51:52.667 2024 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:45:02:21:00:DE:7A:89:CB:95:CD:DF:B1:98:6F:70:\n                02:22:F5:C6:68:A3:C4:28:0A:3F:F5:E8:73:E0:EB:49:\n                D1:83:8D:BC:D0:02:20:44:78:34:CF:BA:AE:F6:42:80:\n                2F:7A:34:E2:69:6B:3F:EA:26:C7:86:3B:6E:83:13:87:\n                06:22:19:14:95:8E:26"
      },
      "pem": "-----BEGIN CERTIFICATE-----\nMIIEGTCCAwGgAwIBAgISBGSYDgIRxFwVtP9j4/4uiyQWMA0GCSqGSIb3DQEBCwUA\nMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\nEwJSMzAeFw0yNDAxMTYwODUxNTJaFw0yNDA0MTUwODUxNTFaMBYxFDASBgNVBAMT\nC2JvcHByZWguY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENvLiIbH+onz0\nKWHkXIQpWKlya7/UVVt8aMSfpOUa0DsSYjIvio8J7pDhtgvrQ9GVCSgxPVyRIr4f\nlB9DtL0z3aOCAg4wggIKMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEF\nBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5LcBSh6wigTo\nPaCVTiCe4HEHrPgwHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYI\nKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMuby5sZW5jci5vcmcw\nIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8wFgYDVR0RBA8wDYIL\nYm9wcHJlaC5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwggEFBgorBgEEAdZ5AgQC\nBIH2BIHzAPEAdwBIsONr2qZHNA/lagL6nTDrHFIBy1bdLIHZu7+rOdiEcwAAAY0R\nrzlRAAAEAwBIMEYCIQCFmjW/sP5zKHSBwrAZ4tuN2ecp3KlFbkKrGy1HP8CwMQIh\nAJe4TxF5eUXGHHUMSAbkxk/YavJfsxiAKsVRy9dClHlWAHYAouK/1h7eLy8HoNZO\nbTen3GVDsMa1LqLat4r4mm31F9gAAAGNEa85WwAABAMARzBFAiEA3nqJy5XN37GY\nb3ACIvXGaKPEKAo/9ehz4OtJ0YONvNACIER4NM+6rvZCgC96NOJpaz/qJseGO26D\nE4cGIhkUlY4mMA0GCSqGSIb3DQEBCwUAA4IBAQCXBzrRNJD2GZ6hW8+dAk8QVPnS\nKfxmL1qO+m2qpYQL58h4IwJ18x5r5R35oGTPKzjI57VU90/eboDdJM2kbmfKomrz\n+AubPNLpAwhAMKK8CI7MsUCbEPwy2wEID2wqD3+O2Y4ZCHeh+V2DQ7IMamifC8Rf\nS/BduePPGeliXAuXJwfpaPc9UfbkFfZuJhJHKGjRUXAp/3rQFxjmrA3YRmgFhg2A\nSgI4HJ5dab+23SeJSnqS57pMzPLm3KYCoYXNS+Sh8CE0tRpJifEj49mtFON7u6wi\n3Rr5RQ2KggO+cwiPql++f01ebnnQdI6BhcKU2dOkpuwN1e6RjX3XSHLHG6kT\n-----END CERTIFICATE-----\n"
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
      "days_until_expiration": 606,
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
    },
    {
      "serial_number": "85078200265644417569109389142156118711",
      "fingerprint_sha256": "6D:99:FB:26:5E:B1:C5:B3:74:47:65:FC:BC:64:8F:3C:D8:E1:BF:FA:FD:C4:C2:F9:9B:9D:47:CF:7F:F1:C2:4F",
      "subject": {
        "C": "US",
        "O": "Internet Security Research Group",
        "CN": "ISRG Root X1"
      },
      "issuer": {
        "O": "Digital Signature Trust Co.",
        "CN": "DST Root CA X3"
      },
      "subject_alternative_names": [],
      "key_type": "RSA",
      "key_length_in_bits": 4096,
      "all_key_usage": [
        "Certificate Sign",
        "CRL Sign"
      ],
      "not_before": "2021-01-20 19:14:03+00:00",
      "not_after": "2024-09-30 18:14:03+00:00",
      "is_expired": false,
      "days_until_expiration": 256,
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "basicConstraints": "CA:TRUE",
        "keyUsage": "Certificate Sign, CRL Sign",
        "authorityInfoAccess": "CA Issuers - URI:http://apps.identrust.com/roots/dstrootcax3.p7c",
        "authorityKeyIdentifier": "C4:A7:B1:A4:7B:2C:71:FA:DB:E1:4B:90:75:FF:C4:15:60:85:89:10",
        "certificatePolicies": "Policy: 2.23.140.1.2.1\nPolicy: 1.3.6.1.4.1.44947.1.1.1\n  CPS: http://cps.root-x1.letsencrypt.org",
        "crlDistributionPoints": "Full Name:\n  URI:http://crl.identrust.com/DSTROOTCAX3CRL.crl",
        "subjectKeyIdentifier": "79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E"
      },
      "pem": "-----BEGIN CERTIFICATE-----\nMIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/\nMSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\nDkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB\nAQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC\nov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL\nwYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D\nLtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK\n4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5\nbHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y\nsR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ\nXmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4\nFQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc\nSLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql\nPRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND\nTwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1\nc3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx\n+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB\nATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu\nb3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E\nU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu\nMA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC\n5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW\n9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG\nWCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O\nhe8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC\nDfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5\n-----END CERTIFICATE-----\n"
    }
  ]
}
```