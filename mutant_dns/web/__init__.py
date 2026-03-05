"""
mutant-dns web dashboard.

Requires optional dependencies: pip install mutant-dns[web]
"""


def main():
    """CLI entry point for mutant-dns-web. Validates deps before importing."""
    import argparse
    import sys

    from mutant_dns import __version__

    p = argparse.ArgumentParser(
        prog='mutant-dns-web',
        description='Visual web dashboard for mutant-dns tunnel traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  mutant-dns-web\n  mutant-dns-web --port 8080 --dns-port 5353',
    )
    p.add_argument('--version', action='version', version='mutant-dns ' + __version__)
    p.add_argument('--host', default='0.0.0.0',
                   help='Web server bind address  [default: 0.0.0.0]')
    p.add_argument('--port', type=int, default=9090,
                   help='Web server port  [default: 9090]')
    p.add_argument('--dns-port', type=int, default=5353,
                   help='DNS tunnel server port  [default: 5353]')
    args = p.parse_args()

    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        print('[error] Web dependencies not installed. Run:\n'
              '  pip install "mutant-dns[web]"', file=sys.stderr)
        sys.exit(1)

    from .app import app, SERVER_PORT, WEB_PORT
    import mutant_dns.web.app as webapp

    webapp.SERVER_PORT = args.dns_port
    webapp.WEB_PORT = args.port

    uvicorn.run(app, host=args.host, port=args.port)
