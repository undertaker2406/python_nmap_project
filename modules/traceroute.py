"""Traceroute module — dùng nmap --traceroute, lưu hops vào DB."""
from __future__ import annotations

import nmap

from config import NMAP_TIMEOUT
from core.scanner import BaseScanner, ScanError
from database import traceroute_repo
from utils.logger import get_logger, get_scan_logger
from utils.validator import validate_target

log = get_logger(__name__)


class Traceroute(BaseScanner):
    def __init__(self, nmap_path: str | None = None):
        super().__init__(nmap_path)
        self.slog = get_scan_logger("traceroute")

    def run(self, targets: list[str], port: int = 80) -> dict:
        if not targets:
            raise ScanError("Danh sách target rỗng")
        clean = [validate_target(t) for t in targets]
        results: dict = {}

        for target in clean:
            results[target] = self._trace_one(target, port)
        return results

    def _trace_one(self, target: str, port: int) -> dict:
        args = f"-T4 -p {port} --traceroute"
        scan_id, target_id = self._record_scan_start(target, "traceroute", args)
        self.slog.info("[TRACE] %s -> nmap %s %s", target, args, target)

        try:
            self.nm.scan(hosts=target, arguments=args, timeout=NMAP_TIMEOUT)
        except nmap.PortScannerError as e:
            self.slog.exception("[TRACE] nmap error on %s", target)
            self._record_scan_end(scan_id, status="failed", raw=str(e))
            return {"error": str(e), "scan_id": scan_id}

        if target not in self.nm.all_hosts():
            self.slog.warning("[TRACE] %s không phản hồi", target)
            self._record_scan_end(scan_id, status="completed")
            return {"error": "no-response", "scan_id": scan_id}

        host = self.nm[target]
        hops_raw = host.get("trace", {}).get("hops", []) or []
        hops = self._parse_hops(hops_raw)

        traceroute_repo.add_hops(scan_id, hops)
        self._record_scan_end(scan_id, status="completed")
        self.slog.info("[TRACE] %s -> %d hop(s)", target, len(hops))

        return {
            "scan_id": scan_id,
            "target_id": target_id,
            "target": target,
            "hops": hops,
        }

    def _parse_hops(self, raw: list[dict]) -> list[dict]:
        """nmap trả {ttl, ipaddr, rtt, host}; chuẩn hoá lại."""
        out = []
        for i, h in enumerate(raw, start=1):
            rtt = h.get("rtt")
            try:
                rtt = float(rtt) if rtt not in (None, "") else None
            except (TypeError, ValueError):
                rtt = None
            out.append({
                "hop_number": h.get("ttl", i),
                "hop_ip": h.get("ipaddr") or "",
                "hop_hostname": h.get("host") or "",
                "rtt": rtt,
            })
        return out