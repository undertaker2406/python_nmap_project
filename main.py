"""NetRecon — entry point.

Chạy không tham số  -> vào menu tương tác
Có tham số          -> chế độ dòng lệnh (argparse)
"""
from __future__ import annotations

import argparse
import sys

from interface.menu import MainMenu


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netrecon", description="NetRecon — network recon tool")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("scan", help="Port scan")
    sp.add_argument("targets", nargs="+")
    sp.add_argument("-p", "--profile", default="quick",
                    choices=["quick", "standard", "full_tcp", "udp", "custom"])
    sp.add_argument("--custom-args", default="")
    sp.add_argument("--custom-ports", default="")

    tr = sub.add_parser("trace", help="Traceroute")
    tr.add_argument("targets", nargs="+")
    tr.add_argument("--port", type=int, default=80)

    nse = sub.add_parser("nse", help="Chạy NSE scripts")
    nse.add_argument("targets", nargs="+")
    nse.add_argument("--scripts", required=True)
    nse.add_argument("--ports", default="")
    nse.add_argument("--extra", default="")

    disc = sub.add_parser("discover", help="Host discovery")
    disc.add_argument("--subnet", default=None)
    disc.add_argument("--no-os", action="store_true")

    rp = sub.add_parser("report", help="Sinh báo cáo")
    rp.add_argument("scope", choices=["global", "target", "scan"])
    rp.add_argument("--id", type=int, default=None)
    rp.add_argument("--formats", nargs="+", default=["json", "md", "html"])

    return p


def _run_cli(args: argparse.Namespace) -> int:
    if args.cmd == "scan":
        from modules import PortScanner
        r = PortScanner().scan(args.targets, profile=args.profile,
                               custom_args=args.custom_args,
                               custom_ports=args.custom_ports)
        print(r)
        return 0

    if args.cmd == "trace":
        from modules import Traceroute
        print(Traceroute().run(args.targets, port=args.port))
        return 0

    if args.cmd == "nse":
        from modules import NSERunner
        print(NSERunner().run(args.targets, scripts=args.scripts,
                              ports=args.ports, extra_args=args.extra))
        return 0

    if args.cmd == "discover":
        from modules import HostDiscovery
        hosts = HostDiscovery().discover(subnet=args.subnet,
                                          run_os_detection=not args.no_os)
        for h in hosts:
            print(h)
        return 0

    if args.cmd == "report":
        from analysis import ReportGenerator
        rg = ReportGenerator()
        paths = rg.generate(args.scope, args.id, formats=args.formats)
        for fmt, p in paths.items():
            print(f"{fmt}: {p}")
        return 0

    return 1


def main() -> int:
    parser = _build_parser()
    if len(sys.argv) == 1:
        MainMenu().run()
        return 0
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return 1
    return _run_cli(args)


if __name__ == "__main__":
    raise SystemExit(main())