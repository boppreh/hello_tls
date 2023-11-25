from . import scan_server, Protocol, DEFAULT_TIMEOUT, DEFAULT_MAX_WORKERS, to_json_obj, parse_target

import os
import sys
import json
import logging
import argparse
parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("target", help="server to scan, in the form of 'example.com', 'example.com:443', or even a full URL")
parser.add_argument("--timeout", "-t", dest="timeout", type=float, default=DEFAULT_TIMEOUT, help="socket connection timeout in seconds")
parser.add_argument("--max-workers", "-w", type=int, default=DEFAULT_MAX_WORKERS, help="maximum number of threads/concurrent connections to use for scanning")
parser.add_argument("--server-name-indication", "-s", default='', help="value to be used in the SNI extension, defaults to the target host")
parser.add_argument("--certs", "-c", default=True, action=argparse.BooleanOptionalAction, help="fetch the certificate chain using pyOpenSSL")
parser.add_argument("--enumerate", "-e", dest='enumerate', default=True, action=argparse.BooleanOptionalAction, help="enumerate supported protocols, cipher suites, groups, compression, etc")
parser.add_argument("--protocols", "-p", dest='protocols_str', default=','.join(p.name for p in Protocol), help="comma separated list of TLS/SSL protocols to test")
parser.add_argument("--proxy", default=None, help="HTTP proxy to use for the connection, defaults to the env variable 'http_proxy' else no proxy")
parser.add_argument("--verbose", "-v", action="count", default=0, help="increase output verbosity")
parser.add_argument("--progress", default=False, action=argparse.BooleanOptionalAction, help="write lines with progress percentages to stderr")
args = parser.parse_args()

logging.basicConfig(
    datefmt='%Y-%m-%d %H:%M:%S',
    format='{asctime}.{msecs:0<3.0f} {module} {threadName} {levelname}: {message}',
    style='{',
    level=[logging.WARNING, logging.INFO, logging.DEBUG][min(2, args.verbose)]
)

if not args.protocols_str:
    parser.error("no protocols to test")
try:
    protocols = [Protocol[p] for p in args.protocols_str.split(',')]
except KeyError as e:
    parser.error(f'invalid protocol name "{e.args[0]}", must be one of {", ".join(p.name for p in Protocol)}')

host, port = parse_target(args.target)

if args.certs and protocols == [Protocol.SSLv3]:
    parser.error("SSLv3 is not supported by pyOpenSSL, so `--protocols SSLv3` must be used with `--no-certs`")

proxy = os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY') if args.proxy is None else args.proxy

if args.progress:
    progress = lambda current, total: print(f'{current/total:.0%}', flush=True, file=sys.stderr)
    print('0%', flush=True, file=sys.stderr)
else:
    progress = lambda current, total: None

results = scan_server(
    host,
    port=port,
    protocols=protocols,
    enumerate_options=args.enumerate,
    fetch_cert_chain=args.certs,
    server_name_indication=args.server_name_indication,
    max_workers=args.max_workers,
    timeout_in_seconds=args.timeout,
    proxy=proxy,
    progress=progress,
)

json.dump(to_json_obj(results), sys.stdout, indent=2)