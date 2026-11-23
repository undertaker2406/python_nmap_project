"""Scanner đồng bộ — dùng khi chỉ scan 1 target."""
from __future__ import annotations

import nmap

from config import NMAP_TIMEOUT, OS_DETECTION_ARGS
from core.scanner import BaseScanner, ScanError
from utils.logger import get_scan_logger
from utils.validator import validate_target, validate_scan_profile


class SyncScanner(BaseScanner):
    """Scan tuần tự từng target. Phù hợp khi len(targets) == 1."""

    def __init__(self, nmap_path: str | None = None):
        super().__init__(nmap_path)
        self.log = get_scan_logger("sync_scanner")

    def run(self, targets: list[str], profile: str = "quick",
            custom_args: str = "", detect_os: bool = False) -> dict:
        if not targets:
            raise ScanError("Danh sách target rỗng")

        profile = validate_scan_profile(profile)
        results: dict = {}

        for raw in targets:
            target = validate_target(raw)
            results[target] = self._scan_one(target, profile, custom_args, detect_os)

        return results

    # ---- internals ----

    def _scan_one(self, target: str, profile: str,
                  custom_args: str, detect_os: bool) -> dict:
        args = self.build_args(profile, custom_args)
        if detect_os:
            args = f"{args} {OS_DETECTION_ARGS}"

        scan_id, target_id = self._record_scan_start(target, profile, args)
        self.log.info("[SYNC] %s -> nmap %s %s", target, args, target)

        try:
            self.nm.scan(hosts=target, arguments=args, timeout=NMAP_TIMEOUT)
        except nmap.PortScannerError as e:
            self.log.exception("[SYNC] nmap error on %s", target)
            self._record_scan_end(scan_id, status="failed", raw=str(e))
            return {"error": str(e), "scan_id": scan_id}

        # nmap có thể trả 0 host nếu filter
        if target not in self.nm.all_hosts():
            self.log.warning("[SYNC] %s không phản hồi", target)
            self._record_scan_end(scan_id, status="completed", raw=None)
            return {"error": "no-response", "scan_id": scan_id}

        host_data = self.nm[target]
        self._save_result(scan_id, target_id, target, host_data)

        try:
            raw_xml = self.nm.get_nmap_last_output()
        except Exception:
            raw_xml = None

        self._record_scan_end(scan_id, status="completed", raw=raw_xml)
        return {
            "scan_id": scan_id,
            "target_id": target_id,
            "host": host_data,
        }