from .scan import scan_server, DEFAULT_TIMEOUT, DEFAULT_MAX_WORKERS, parse_target, ConnectionSettings
from .protocol import ClientHello
from .names_and_numbers import Protocol

import os
import sys
import json
import logging
import argparse
from typing import Any
import dataclasses
from enum import Enum
from datetime import datetime
parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("target", help="server to scan, in the form of 'example.com', 'example.com:443', or even a full URL")
parser.add_argument("--timeout", "-t", dest="timeout", type=float, default=DEFAULT_TIMEOUT, help="socket connection timeout in seconds")
parser.add_argument("--max-workers", "-w", type=int, default=DEFAULT_MAX_WORKERS, help="maximum number of threads/concurrent connections to use for scanning")
parser.add_argument("--server-name-indication", "-s", default='', help="value to be used in the SNI extension, defaults to the target host")
parser.add_argument("--certs", "-c", default=True, action=argparse.BooleanOptionalAction, help="fetch the certificate chain using pyOpenSSL")
parser.add_argument("--enumerate-cipher-suites", "-C", dest='enumerate_cipher_suites', default=True, action=argparse.BooleanOptionalAction, help="enumerate supported cipher suites")
parser.add_argument("--enumerate-groups", "-G", dest='enumerate_groups', default=True, action=argparse.BooleanOptionalAction, help="enumerate supported groups")
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

def to_json_obj(o: Any) -> Any:
    """
    Converts an object to a JSON-serializable structure, replacing dataclasses, enums, sets, datetimes, etc.
    """
    if isinstance(o, dict):
        return {to_json_obj(key): to_json_obj(value) for key, value in o.items()}
    elif dataclasses.is_dataclass(o):
        return to_json_obj(dataclasses.asdict(o))
    elif isinstance(o, set):
        return sorted(to_json_obj(item) for item in o)
    elif isinstance(o, (tuple, list)):
        return [to_json_obj(item) for item in o]
    elif isinstance(o, Enum):
        return o.name
    elif isinstance(o, datetime):
        return o.isoformat(' ')
    return o


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
    ConnectionSettings(
        host=host,
        port=port,
        proxy=proxy,
        timeout_in_seconds=args.timeout
    ),
    ClientHello(
        protocols=protocols,
        server_name=args.server_name_indication or host
    ),
    do_enumerate_cipher_suites=args.enumerate_cipher_suites,
    do_enumerate_groups=args.enumerate_groups,
    fetch_cert_chain=args.certs,
    max_workers=args.max_workers,
    progress=progress,
)

json.dump(to_json_obj(results), sys.stdout, indent=2)