"""Abstract base cho mọi scanner (sync & async)."""
from __future__ import annotations

from abc import ABC, abstractmethod

import nmap

from config import SCAN_PROFILES, NMAP_TIMEOUT, OS_DETECTION_ARGS
from database import db_manager, scans_repo, ports_repo, targets_repo
from utils.logger import get_scan_logger, get_logger
from utils.validator import validate_target

log = get_logger(__name__)


class ScanError(RuntimeError):
    """Raise khi nmap trả lỗi hoặc target không hợp lệ."""


class BaseScanner(ABC):
    """Mọi scanner kế thừa class này.

    Subclass chỉ cần implement `run(targets, profile, custom_args)`.
    """

    def __init__(self, nmap_path: str | None = None):
        self.nm = nmap.PortScanner(nmap_search_path=(nmap_path,)) \
            if nmap_path else nmap.PortScanner()
        self.log = get_scan_logger(self.__class__.__name__)
        self.log.info("Scanner %s initialized", self.__class__.__name__)

    # ---- helpers dùng chung ----

    def build_args(self, profile: str, custom_args: str = "") -> str:
        if profile == "custom":
            if not custom_args.strip():
                raise ScanError("Profile 'custom' yêu cầu custom_args")
            return custom_args.strip()
        return SCAN_PROFILES[profile]["args"]

    def _ensure_target_in_db(self, target: str) -> int:
        """Đảm bảo target tồn tại trong DB, trả target_id."""
        t = targets_repo.upsert(target)
        return t.id

    def _record_scan_start(self, target: str, profile: str, args: str) -> tuple[int, int]:
        target_id = self._ensure_target_in_db(target)
        cmd = f"nmap {args} {target}".strip()
        scan_id = scans_repo.create(target_id, profile, command=cmd)
        self.log.info("Scan started id=%s target=%s profile=%s args=%r",
                      scan_id, target, profile, args)
        return scan_id, target_id

    def _extract_ports(self, host_data: dict) -> list[dict]:
        """host_data = nm[ip] (dict của python-nmap) -> list port dict."""
        out: list[dict] = []
        for proto in ("tcp", "udp"):
            for port_num, info in host_data.get(proto, {}).items():
                out.append({
                    "port": int(port_num),
                    "protocol": proto,
                    "state": info.get("state"),
                    "service": info.get("name"),
                    "product": info.get("product"),
                    "version": info.get("version"),
                    "extra_info": info.get("extrainfo") or info.get("reason"),
                })
        return out

    def _extract_os(self, host_data: dict) -> dict:
        """Lấy OS tốt nhất (accuracy cao nhất)."""
        best = {"os_family": None, "os_match": None, "os_accuracy": None}
        matches = host_data.get("osmatch") or []
        if not matches:
            return best
        top = max(matches, key=lambda m: int(m.get("accuracy", 0)))
        classes = top.get("osclass") or []
        family = classes[0].get("osfamily") if classes else None
        return {
            "os_family": family,
            "os_match": top.get("name"),
            "os_accuracy": int(top.get("accuracy", 0)),
        }

    def _save_result(self, scan_id: int, target_id: int, ip: str, host_data: dict) -> None:
        ports = self._extract_ports(host_data)
        if ports:
            ports_repo.add_ports(scan_id, target_id, ports)

        os_info = self._extract_os(host_data)
        if os_info["os_family"] or os_info["os_match"]:
            targets_repo.update_os(ip, **os_info)

        self.log.info("Scan id=%s target=%s -> %d port(s)",
                      scan_id, ip, len(ports))

    def _record_scan_end(self, scan_id: int, status: str, raw: str | None = None) -> None:
        scans_repo.finish(scan_id, status=status, raw_output=raw)
        self.log.info("Scan id=%s finished status=%s", scan_id, status)

    # ---- abstract ----

    @abstractmethod
    def run(self, targets: list[str], profile: str = "quick",
            custom_args: str = "") -> dict:
        """Chạy scan. Trả dict tổng hợp {target: {...}}.

        Sync hay async tuỳ subclass.
        """
        raise NotImplementedError