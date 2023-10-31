# Hello TLS!

This is a pure Python, single-file, dependency-less implementation of SSL/TLS Client Hello and basic scaning.

Its purpose is to quickly discover what cipher suites and SSL/TLS protocols are enabled on a server. Since the server doesn't advertise this list, instead picking from what is offered by the client, hello_tls.py sends a sequence of Client Hello with different cipher suite and protocol combinations. It usually needs less than 8 requests and 300 ms, but for servers with many cipher suites or high latency, bumping `max_workers` splits discovery over many threads.

There's no actual cryptography, just sending a stream of bytes and seeing if the server reply vaguely looks ok or not. Supports TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, and SSLv3. Optionally, the certificate chain can be fetched and parsed, at the cost of relying on pyOpenSSL.

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
    host: str,
    port: int = 443,
    protocols: Sequence[Protocol] = tuple(Protocol),
    enumerate_cipher_suites: bool = True,
    fetch_cert_chain: bool = True,
    server_name_indication: str | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    timeout_in_seconds: float | None = DEFAULT_TIMEOUT,
    proxy: str | None = None,
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
    host='boppreh.com',
    port=443,
    protocols={
        SSLv3: None,
        TLS1_0: None,
        TLS1_1: None,
        TLS1_2: ProtocolResult(
            has_compression=False,
            has_cipher_suite_order=True,
            groups=[],
            cipher_suites=[TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, ...]
        ),
        TLS1_3: ProtocolResult(
            has_compression=False,
            has_cipher_suite_order=False,
            groups=[x25519],
            cipher_suites=[TLS_CHACHA20_POLY1305_SHA256, ...]
        )
    },
    certificate_chain=[
        Certificate(serial_number, ...)
        Certificate(serial_number, ...)
        Certificate(serial_number, ...)
    ]
)
```

## As a command line application

```bash
python -m hello_tls boppreh.com
```
```json
{
  "host": "boppreh.com",
  "port": 443,
  "protocols": {
    "TLS1_3": {
      "has_compression": false,
      "has_cipher_suite_order": false,
      "groups": [
        "x25519"
      ],
      "cipher_suites": [
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384"
      ]
    },
    "TLS1_2": {
      "has_compression": false,
      "has_cipher_suite_order": true,
      "groups": [],
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
      "serial_number": "414465106860707586851651369676697477353074",
      "fingerprint_sha256": "81:3E:78:A7:2F:E6:74:E3:2C:84:F1:4D:2E:E0:E8:B1:F6:FC:CF:2C:66:E5:21:20:4F:F7:D9:44:76:3F:60:C5",
      "subject": {
        "CN": "boppreh.com"
      },
      "issuer": {
        "C": "US",
        "O": "Let's Encrypt",
        "CN": "R3"
      },
      "key_type": "EC",
      "key_length_in_bits": 256,
      "not_before": "2023-09-18T10:42:02",
      "not_after": "2023-12-17T10:42:01",
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "keyUsage": "Digital Signature",
        "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
        "basicConstraints": "CA:FALSE",
        "subjectKeyIdentifier": "AF:F2:C0:54:5D:24:02:0A:D3:AA:91:C0:CD:35:90:A1:E1:64:91:2C",
        "authorityKeyIdentifier": "14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6",
        "authorityInfoAccess": "OCSP - URI:http://r3.o.lencr.org\nCA Issuers - URI:http://r3.i.lencr.org/",
        "subjectAltName": "DNS:boppreh.com",
        "certificatePolicies": "Policy: 2.23.140.1.2.1",
        "ct_precert_scts": "Signed Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 7A:32:8C:54:D8:B7:2D:B6:20:EA:38:E0:52:1E:E9:84:\n                16:70:32:13:85:4D:3B:D2:2B:C1:3A:57:A3:52:EB:52\n    Timestamp : Sep 18 11:42:02.639 2023 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:46:02:21:00:BB:06:8C:8A:86:0A:D6:B1:1D:65:71:\n                FF:69:79:67:FF:87:9B:95:BD:4B:47:A1:2D:C1:9E:73:\n                B0:89:87:EA:BD:02:21:00:9F:DA:17:BE:7E:11:23:EA:\n                21:A5:47:39:92:63:20:BE:3A:06:44:F9:57:80:D3:A3:\n                97:E4:C1:EC:41:D8:C3:FC\nSigned Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : E8:3E:D0:DA:3E:F5:06:35:32:E7:57:28:BC:89:6B:C9:\n                03:D3:CB:D1:11:6B:EC:EB:69:E1:77:7D:6D:06:BD:6E\n    Timestamp : Sep 18 11:42:02.639 2023 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:45:02:20:1E:25:A7:43:E0:5F:A9:E6:25:4F:9B:00:\n                F8:39:ED:EC:B7:45:4D:85:C4:84:B1:FB:3E:46:A9:92:\n                21:F1:B8:1E:02:21:00:8D:CD:76:4B:FE:A5:CB:8C:DA:\n                1F:F9:BB:A9:48:62:9B:4E:43:AE:00:E7:A4:51:50:3D:\n                BD:AA:78:68:41:34:A1"
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
      "key_type": "RSA",
      "key_length_in_bits": 2048,
      "not_before": "2020-09-04T00:00:00",
      "not_after": "2025-09-15T16:00:00",
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
      "key_type": "RSA",
      "key_length_in_bits": 4096,
      "not_before": "2021-01-20T19:14:03",
      "not_after": "2024-09-30T18:14:03",
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
