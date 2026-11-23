"""Port Scanning: 5 profile (Quick / Standard / Full TCP / UDP / Custom).

Tự động sync (1 target) hay async (nhiều target) thông qua core.App.
"""
from __future__ import annotations

from core import App
from config import SCAN_PROFILES
from database import ports_repo, scans_repo
from utils.logger import get_logger, get_scan_logger
from utils.validator import (
    validate_target, validate_scan_profile, validate_port_spec,
)

log = get_logger(__name__)

# Map số menu -> tên profile (khớp interface/menu.py sau này)
PROFILE_BY_KEY = {
    "1": "quick",
    "2": "standard",
    "3": "full_tcp",
    "4": "udp",
    "5": "custom",
}


class PortScanner:
    def __init__(self, app: App | None = None):
        self.app = app or App()
        self.slog = get_scan_logger("port_scanner")

    # ---- public API ----

    def scan(self, targets: list[str], profile: str | int = "quick",
             custom_args: str = "", custom_ports: str = "") -> dict:
        """
        Args:
            targets: list IP / hostname / CIDR.
            profile: 'quick' | 'standard' | 'full_tcp' | 'udp' | 'custom'
                     hoặc key menu '1'..'5'.
            custom_args: chỉ dùng khi profile='custom' (vd '-sS -T4').
            custom_ports: port spec khi custom không đưa vào custom_args
                          (vd '22,80,443' hoặc '1-1000').
        """
        profile_name = PROFILE_BY_KEY.get(str(profile), profile)
        validate_scan_profile(profile_name)

        clean = [validate_target(t) for t in targets]
        if not clean:
            raise ValueError("Danh sách target rỗng")

        if profile_name == "custom":
            custom_args = self._build_custom_args(custom_args, custom_ports)

        self.slog.info(
            "[PORT] %d target(s) profile=%s args=%r",
            len(clean), profile_name, custom_args or SCAN_PROFILES[profile_name]["args"],
        )

        raw = self.app.scan(
            clean, profile=profile_name,
            custom_args=custom_args, detect_os=False,
        )

        return self._summarize(raw)

    # ---- helpers ----

    def _build_custom_args(self, args: str, ports: str) -> str:
        base = (args or "").strip()
        if ports:
            validate_port_spec(ports)
            base = f"{base} -p {ports}".strip()
        if not base:
            raise ValueError("Custom scan cần custom_args hoặc custom_ports")
        return base

    def _summarize(self, raw: dict) -> dict:
        """raw từ App -> dict dễ in + thống kê."""
        summary = {"targets": {}, "total_open": 0, "scanned": len(raw)}
        for target, info in raw.items():
            if "error" in info:
                summary["targets"][target] = {"error": info["error"]}
                continue

            scan_id = info.get("scan_id")
            ports = [p.to_dict() for p in ports_repo.list_by_scan(scan_id)]
            open_ports = [p for p in ports if p["state"] == "open"]

            summary["targets"][target] = {
                "scan_id": scan_id,
                "ports": ports,
                "open_count": len(open_ports),
            }
            summary["total_open"] += len(open_ports)

        self.slog.info(
            "[PORT] done: %d target(s), %d open port(s)",
            summary["scanned"], summary["total_open"],
        )
        return summary