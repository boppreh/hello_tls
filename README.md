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

```pyrhon
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
    "date": "2024-01-14 23:47:56+00:00"
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
      "serial_number": "279832348808219465711972934848066615033582",
      "fingerprint_sha256": "A4:22:D9:41:80:79:9E:9B:7E:35:17:E6:4C:7B:50:B8:D6:C1:4A:9B:9C:6B:BD:93:DC:94:C2:9F:46:E2:CA:A5",
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
      "not_before": "2023-11-17 09:47:19+00:00",
      "not_after": "2024-02-15 09:47:18+00:00",
      "is_expired": false,
      "days_until_expiration": 31,
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "keyUsage": "Digital Signature",
        "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
        "basicConstraints": "CA:FALSE",
        "subjectKeyIdentifier": "75:57:13:C3:E0:82:B5:37:63:9B:90:C6:89:ED:79:B1:CE:30:0B:2F",
        "authorityKeyIdentifier": "14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6",
        "authorityInfoAccess": "OCSP - URI:http://r3.o.lencr.org\nCA Issuers - URI:http://r3.i.lencr.org/",
        "subjectAltName": "DNS:boppreh.com",
        "certificatePolicies": "Policy: 2.23.140.1.2.1",
        "ct_precert_scts": "Signed Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 3B:53:77:75:3E:2D:B9:80:4E:8B:30:5B:06:FE:40:3B:\n                67:D8:4F:C3:F4:C7:BD:00:0D:2D:72:6F:E1:FA:D4:17\n    Timestamp : Nov 17 10:47:19.570 2023 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:45:02:20:68:04:CC:39:20:39:86:6B:0D:BE:43:39:\n                00:8A:3B:52:0E:4B:02:3E:EB:0D:02:3F:83:48:09:91:\n                C0:51:3A:86:02:21:00:C1:A4:E6:BB:07:4D:2E:AB:3F:\n                D0:37:86:6C:A8:9B:1F:54:E0:6A:8D:89:96:2A:71:7C:\n                D2:D3:AE:C6:AF:B4:30\nSigned Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 76:FF:88:3F:0A:B6:FB:95:51:C2:61:CC:F5:87:BA:34:\n                B4:A4:CD:BB:29:DC:68:42:0A:9F:E6:67:4C:5A:3A:74\n    Timestamp : Nov 17 10:47:19.673 2023 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:46:02:21:00:AB:6C:29:44:FF:46:49:BE:05:DD:54:\n                18:84:63:9F:37:B1:39:2B:28:85:BE:0D:39:17:B4:C0:\n                7D:8F:2F:12:B8:02:21:00:8C:0F:B4:01:D8:8A:B3:44:\n   
             FD:AB:0B:42:69:2A:94:B4:C6:F7:99:C2:08:B3:B3:7C:\n                44:59:1A:DD:B0:C7:79:99"
      }
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
      "days_until_expiration": 609,
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
      }
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
      "days_until_expiration": 259,
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "basicConstraints": "CA:TRUE",
        "keyUsage": "Certificate Sign, CRL Sign",
        "authorityInfoAccess": "CA Issuers - URI:http://apps.identrust.com/roots/dstrootcax3.p7c",
        "authorityKeyIdentifier": "C4:A7:B1:A4:7B:2C:71:FA:DB:E1:4B:90:75:FF:C4:15:60:85:89:10",
        "certificatePolicies": "Policy: 2.23.140.1.2.1\nPolicy: 1.3.6.1.4.1.44947.1.1.1\n  CPS: http://cps.root-x1.letsencrypt.org",
        "crlDistributionPoints": "Full Name:\n  URI:http://crl.identrust.com/DSTROOTCAX3CRL.crl",
        "subjectKeyIdentifier": "79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E"
      }
    }
  ]
}
```
