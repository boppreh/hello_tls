# Hello TLS!

This is a pure Python, single-file, dependency-less implementation of SSL/TLS Client Hello and basic scaning.

Its purpose is to quickly discover what cipher suites and SSL/TLS protocols are enabled on a server. Since the server doesn't advertise this list, instead picking from what is offered by the client, hello_tls.py sends a sequence of Client Hello with different cipher suite and protocol combinations. It usually needs less than 8 requests and 300 ms, but for servers with many cipher suites or high latency, bumping `max_workers` splits discovery over many threads.

There's no actual cryptography, just sending a stream of bytes and seeing if the server reply vaguely looks ok or not. Supports TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, and *maybe* SSLv3 (untested). Optionally, the certificate chain can be fetched and parsed, at the cost of relying on pyOpenSSL.

```python
def scan_server(
    server_name: str,
    port: int = 443,
    fetch_certificate_chain: bool = True,
    max_workers: int = 5,
    timeout_in_seconds: float | None = DEFAULT_TIMEOUT
    ) -> ServerScanResult:
    ...

scan_server('google.com')
# ServerScanResult(
#     certificate_chain=[Certificate(...)],
#     protocol_support={'SSLv3': False, 'TLS_1_0': True, 'TLS_1_1': True, 'TLS_1_2': True, 'TLS_1_3': True},
#     cipher_suites_tls_1_2=[CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, ...],
#     cipher_suites_tls_1_3=[CipherSuite.TLS_AES_256_GCM_SHA384, ...],
# )
```

or, as CLI that print JSON:

```json
$ python hello_tls.py google.com
{
  "protocol_support": {
    "SSLv3": false,
    "TLS_1_0": true,
    "TLS_1_1": true,
    "TLS_1_2": true,
    "TLS_1_3": true
  },
  "cipher_suites_tls_1_2": [
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
  ],
  "cipher_suites_tls_1_3": [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256"
  ],
  "certificate_chain": [
    {
      "serial_number": 264635363111603634211880343082321729508,
      "subject": {
        "CN": "*.google.com"
      },
      "issuer": {
        "C": "US",
        "O": "Google Trust Services LLC",
        "CN": "GTS CA 1C3"
      },
      "not_before": "2023-09-28T05:26:21",
      "not_after": "2023-12-21T05:26:20",
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "keyUsage": "Digital Signature",
        "extendedKeyUsage": "TLS Web Server Authentication",
        "basicConstraints": "CA:FALSE",
        "subjectKeyIdentifier": "5C:11:A8:72:02:50:45:DC:4F:08:A5:CD:0D:FA:EC:A7:35:B2:43:DE",
        "authorityKeyIdentifier": "8A:74:7F:AF:85:CD:EE:95:CD:3D:9C:D0:E2:46:14:F3:71:35:1D:27",
        "authorityInfoAccess": "OCSP - URI:http://ocsp.pki.goog/gts1c3\nCA Issuers - URI:http://pki.goog/repo/certs/gts1c3.der",
        "subjectAltName": "DNS:*.google.com, DNS:*.appengine.google.com, DNS:*.bdn.dev, DNS:*.origin-test.bdn.dev, DNS:*.cloud.google.com, DNS:*.crowdsource.google.com, DNS:*.datacompute.google.com, DNS:*.google.ca, DNS:*.google.cl, DNS:*.google.co.in, DNS:*.google.co.jp, DNS:*.google.co.uk, DNS:*.google.com.ar, DNS:*.google.com.au, DNS:*.google.com.br, DNS:*.google.com.co, DNS:*.google.com.mx, DNS:*.google.com.tr, DNS:*.google.com.vn, DNS:*.google.de, DNS:*.google.es, DNS:*.google.fr, DNS:*.google.hu, DNS:*.google.it, DNS:*.google.nl, DNS:*.google.pl, DNS:*.google.pt, DNS:*.googleadapis.com, DNS:*.googleapis.cn, DNS:*.googlevideo.com, DNS:*.gstatic.cn, DNS:*.gstatic-cn.com, DNS:googlecnapps.cn, DNS:*.googlecnapps.cn, DNS:googleapps-cn.com, DNS:*.googleapps-cn.com, DNS:gkecnapps.cn, DNS:*.gkecnapps.cn, DNS:googledownloads.cn, DNS:*.googledownloads.cn, DNS:recaptcha.net.cn, DNS:*.recaptcha.net.cn, DNS:recaptcha-cn.net, DNS:*.recaptcha-cn.net, DNS:widevine.cn, DNS:*.widevine.cn, DNS:ampproject.org.cn, DNS:*.ampproject.org.cn, DNS:ampproject.net.cn, DNS:*.ampproject.net.cn, DNS:google-analytics-cn.com, DNS:*.google-analytics-cn.com, DNS:googleadservices-cn.com, DNS:*.googleadservices-cn.com, DNS:googlevads-cn.com, DNS:*.googlevads-cn.com, DNS:googleapis-cn.com, DNS:*.googleapis-cn.com, DNS:googleoptimize-cn.com, DNS:*.googleoptimize-cn.com, DNS:doubleclick-cn.net, DNS:*.doubleclick-cn.net, DNS:*.fls.doubleclick-cn.net, DNS:*.g.doubleclick-cn.net, DNS:doubleclick.cn, DNS:*.doubleclick.cn, DNS:*.fls.doubleclick.cn, DNS:*.g.doubleclick.cn, DNS:dartsearch-cn.net, DNS:*.dartsearch-cn.net, DNS:googletraveladservices-cn.com, DNS:*.googletraveladservices-cn.com, DNS:googletagservices-cn.com, DNS:*.googletagservices-cn.com, DNS:googletagmanager-cn.com, DNS:*.googletagmanager-cn.com, DNS:googlesyndication-cn.com, DNS:*.googlesyndication-cn.com, DNS:*.safeframe.googlesyndication-cn.com, DNS:app-measurement-cn.com, DNS:*.app-measurement-cn.com, DNS:gvt1-cn.com, DNS:*.gvt1-cn.com, DNS:gvt2-cn.com, DNS:*.gvt2-cn.com, DNS:2mdn-cn.net, DNS:*.2mdn-cn.net, DNS:googleflights-cn.net, DNS:*.googleflights-cn.net, DNS:admob-cn.com, DNS:*.admob-cn.com, DNS:googlesandbox-cn.com, DNS:*.googlesandbox-cn.com, DNS:*.safenup.googlesandbox-cn.com, DNS:*.gstatic.com, DNS:*.metric.gstatic.com, DNS:*.gvt1.com, DNS:*.gcpcdn.gvt1.com, DNS:*.gvt2.com, DNS:*.gcp.gvt2.com, DNS:*.url.google.com, DNS:*.youtube-nocookie.com, DNS:*.ytimg.com, DNS:android.com, DNS:*.android.com, DNS:*.flash.android.com, DNS:g.cn, DNS:*.g.cn, DNS:g.co, DNS:*.g.co, DNS:goo.gl, DNS:www.goo.gl, DNS:google-analytics.com, DNS:*.google-analytics.com, DNS:google.com, DNS:googlecommerce.com, DNS:*.googlecommerce.com, DNS:ggpht.cn, DNS:*.ggpht.cn, DNS:urchin.com, DNS:*.urchin.com, DNS:youtu.be, DNS:youtube.com, DNS:*.youtube.com, DNS:youtubeeducation.com, DNS:*.youtubeeducation.com, DNS:youtubekids.com, DNS:*.youtubekids.com, DNS:yt.be, DNS:*.yt.be, DNS:android.clients.google.com, DNS:developer.android.google.cn, DNS:developers.android.google.cn, DNS:source.android.google.cn",
        "certificatePolicies": "Policy: 2.23.140.1.2.1\nPolicy: 1.3.6.1.4.1.11129.2.5.3",
        "crlDistributionPoints": "Full Name:\n  URI:http://crls.pki.goog/gts1c3/QOvJ0N1sT2A.crl",
        "ct_precert_scts": "Signed Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 7A:32:8C:54:D8:B7:2D:B6:20:EA:38:E0:52:1E:E9:84:\n                16:70:32:13:85:4D:3B:D2:2B:C1:3A:57:A3:52:EB:52\n    Timestamp : Sep 28 06:26:23.210 2023 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:45:02:21:00:D6:B7:8E:9F:C0:72:04:FE:61:22:A1:\n                62:19:1E:58:1C:1B:C6:3C:44:8F:95:FE:C2:C3:7F:B9:\n                91:04:2A:CB:1A:02:20:35:E3:19:C2:F6:3A:E1:7E:1D:\n                93:65:3E:FF:32:32:C9:39:43:98:47:2D:9D:25:C6:E0:\n                A4:92:AE:6E:E5:F0:AD\nSigned Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : E8:3E:D0:DA:3E:F5:06:35:32:E7:57:28:BC:89:6B:C9:\n                03:D3:CB:D1:11:6B:EC:EB:69:E1:77:7D:6D:06:BD:6E\n    Timestamp : Sep 28 06:26:23.163 2023 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:45:02:21:00:D3:C4:84:79:A4:9B:B2:23:5B:3E:84:\n                73:56:5D:57:58:C5:C1:53:4D:F5:C7:A5:4D:CB:1F:9F:\n                34:D6:36:30:F3:02:20:38:5F:05:11:CB:53:7E:B8:D6:\n                C4:BF:7D:5E:E2:FF:81:25:E9:9D:1C:22:63:A7:47:4D:\n                BE:9B:0C:7B:C5:DF:07"
      }
    },
    {
      "serial_number": 159612451717983579589660725350,
      "subject": {
        "C": "US",
        "O": "Google Trust Services LLC",
        "CN": "GTS CA 1C3"
      },
      "issuer": {
        "C": "US",
        "O": "Google Trust Services LLC",
        "CN": "GTS Root R1"
      },
      "not_before": "2020-08-13T00:00:42",
      "not_after": "2027-09-30T00:00:42",
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "keyUsage": "Digital Signature, Certificate Sign, CRL Sign",
        "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
        "basicConstraints": "CA:TRUE, pathlen:0",
        "subjectKeyIdentifier": "8A:74:7F:AF:85:CD:EE:95:CD:3D:9C:D0:E2:46:14:F3:71:35:1D:27",
        "authorityKeyIdentifier": "E4:AF:2B:26:71:1A:2B:48:27:85:2F:52:66:2C:EF:F0:89:13:71:3E",
        "authorityInfoAccess": "OCSP - URI:http://ocsp.pki.goog/gtsr1\nCA Issuers - URI:http://pki.goog/repo/certs/gtsr1.der",
        "crlDistributionPoints": "Full Name:\n  URI:http://crl.pki.goog/gtsr1/gtsr1.crl",
        "certificatePolicies": "Policy: 1.3.6.1.4.1.11129.2.5.3\n  CPS: https://pki.goog/repository/\nPolicy: 2.23.140.1.2.1\nPolicy: 2.23.140.1.2.2"
      }
    },
    {
      "serial_number": 159159747900478145820483398898491642637,
      "subject": {
        "C": "US",
        "O": "Google Trust Services LLC",
        "CN": "GTS Root R1"
      },
      "issuer": {
        "C": "BE",
        "O": "GlobalSign nv-sa",
        "OU": "Root CA",
        "CN": "GlobalSign Root CA"
      },
      "not_before": "2020-06-19T00:00:42",
      "not_after": "2028-01-28T00:00:42",
      "signature_algorithm": "sha256WithRSAEncryption",
      "extensions": {
        "keyUsage": "Digital Signature, Certificate Sign, CRL Sign",
        "basicConstraints": "CA:TRUE",
        "subjectKeyIdentifier": "E4:AF:2B:26:71:1A:2B:48:27:85:2F:52:66:2C:EF:F0:89:13:71:3E",
        "authorityKeyIdentifier": "60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B",
        "authorityInfoAccess": "OCSP - URI:http://ocsp.pki.goog/gsr1\nCA Issuers - URI:http://pki.goog/gsr1/gsr1.crt",
        "crlDistributionPoints": "Full Name:\n  URI:http://crl.pki.goog/gsr1/gsr1.crl",
        "certificatePolicies": "Policy: 2.23.140.1.2.1\nPolicy: 2.23.140.1.2.2\nPolicy: 1.3.6.1.4.1.11129.2.5.3.2\nPolicy: 1.3.6.1.4.1.11129.2.5.3.3"
      }
    }
  ]
}
```