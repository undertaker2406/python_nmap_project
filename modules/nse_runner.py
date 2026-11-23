"""Nmap NSE runner — chạy --script với validate an toàn."""
from __future__ import annotations

import json

import nmap

from config import NMAP_TIMEOUT
from core.scanner import BaseScanner, ScanError
from database import scans_repo
from utils.logger import get_logger, get_scan_logger
from utils.validator import validate_target, validate_nse_script

log = get_logger(__name__)


class NSERunner(BaseScanner):
    def __init__(self, nmap_path: str | None = None):
        super().__init__(nmap_path)
        self.slog = get_scan_logger("nse_runner")

    def run(self, targets: list[str], scripts: list[str] | str,
            ports: str = "", extra_args: str = "") -> dict:
        """
        Args:
            targets: list IP/hostname.
            scripts: 1 script ('http-title') hoặc list ('vuln', 'safe')
                     hoặc nhiều cách nhau phẩy.
            ports:   '80,443' nếu muốn giới hạn.
            extra_args: vd '-sV' để script lấy được version.
        """
        if not targets:
            raise ScanError("Danh sách target rỗng")

        script_arg = self._normalize_scripts(scripts)
        clean = [validate_target(t) for t in targets]
        results: dict = {}

        for target in clean:
            results[target] = self._run_one(target, script_arg, ports, extra_args)
        return results

    # ---- internals ----

    def _normalize_scripts(self, scripts: list[str] | str) -> str:
        if isinstance(scripts, str):
            parts = [s.strip() for s in scripts.split(",") if s.strip()]
        else:
            parts = [s.strip() for s in scripts if s and s.strip()]
        if not parts:
            raise ScanError("Cần ít nhất 1 NSE script")
        # validate từng cái (chặn path traversal, ký tự lạ)
        for p in parts:
            validate_nse_script(p)
        return ",".join(parts)

    def _run_one(self, target: str, script_arg: str,
                 ports: str, extra_args: str) -> dict:
        parts = [f"--script {script_arg}"]
        if ports:
            parts.append(f"-p {ports}")
        if extra_args:
            parts.append(extra_args)
        args = " ".join(parts)

        scan_id, target_id = self._record_scan_start(target, "nse", args)
        self.slog.info("[NSE] %s -> nmap %s %s", target, args, target)

        try:
            self.nm.scan(hosts=target, arguments=args, timeout=NMAP_TIMEOUT)
        except nmap.PortScannerError as e:
            self.slog.exception("[NSE] nmap error on %s", target)
            self._record_scan_end(scan_id, status="failed", raw=str(e))
            return {"error": str(e), "scan_id": scan_id}

        if target not in self.nm.all_hosts():
            self.slog.warning("[NSE] %s không phản hồi", target)
            self._record_scan_end(scan_id, status="completed")
            return {"error": "no-response", "scan_id": scan_id}

        host = self.nm[target]
        script_results = self._extract_scripts(host)

        try:
            raw_xml = self.nm.get_nmap_last_output()
        except Exception:
            raw_xml = None

        # Lưu raw output vào DB
        scans_repo.finish(scan_id, status="completed", raw_output=raw_xml)

        self.slog.info("[NSE] %s -> %d script result(s)",
                       target, len(script_results))
        return {
            "scan_id": scan_id,
            "target_id": target_id,
            "target": target,
            "scripts_run": script_arg,
            "results": script_results,
        }

    def _extract_scripts(self, host: dict) -> list[dict]:
        """Gom output NSE theo port + theo host script."""
        out: list[dict] = []

        # Script per port
        for proto in ("tcp", "udp"):
            for port_num, info in (host.get(proto) or {}).items():
                for name, data in (info.get("script") or {}).items():
                    out.append({
                        "port": int(port_num),
                        "protocol": proto,
                        "script": name,
                        "output": data if isinstance(data, str) else json.dumps(data),
                    })

        # Host script (không gắn port)
        for name, data in (host.get("script") or {}).items():
            out.append({
                "port": None,
                "protocol": None,
                "script": name,
                "output": data if isinstance(data, str) else json.dumps(data),
            })

        return out