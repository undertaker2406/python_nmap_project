"""Scanner bất đồng bộ — nhiều target, chạy song song bằng thread pool.

Lưu ý quan trọng:
- nmap.PortScanner KHÔNG thread-safe -> mỗi thread tạo instance riêng.
- SQLite write phải tuần tự -> dùng threading.Lock quanh repo write
  HOẶC để từng thread tự mở session (SessionLocal đã check_same_thread=False).
- Giới hạn số luồng = MAX_CONCURRENT_SCANS.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import nmap

from config import NMAP_TIMEOUT, MAX_CONCURRENT_SCANS, OS_DETECTION_ARGS
from core.scanner import BaseScanner, ScanError
from utils.logger import get_scan_logger
from utils.validator import validate_target, validate_scan_profile


class AsyncScanner(BaseScanner):
    """Chạy song song nhiều target. Tự chọn sync nếu chỉ có 1 target."""

    # Lock bảo vệ phần ghi DB (SQLite không cho nhiều writer)
    _db_lock = threading.Lock()

    def __init__(self, nmap_path: str | None = None,
                 max_workers: int = MAX_CONCURRENT_SCANS):
        super().__init__(nmap_path)
        self.log = get_scan_logger("async_scanner")
        self.nmap_path = nmap_path
        self.max_workers = max(1, max_workers)

    def _new_portscanner(self) -> nmap.PortScanner:
        if self.nmap_path:
            return nmap.PortScanner(nmap_search_path=(self.nmap_path,))
        return nmap.PortScanner()

    def run(self, targets: list[str], profile: str = "quick",
            custom_args: str = "", detect_os: bool = False) -> dict:
        if not targets:
            raise ScanError("Danh sách target rỗng")

        profile = validate_scan_profile(profile)
        clean = [validate_target(t) for t in targets]

        if len(clean) == 1:
            self.log.info("[ASYNC] chỉ có 1 target -> fallback sync")
            return self._scan_one(clean[0], profile, custom_args, detect_os)

        results: dict = {}
        workers = min(self.max_workers, len(clean))
        self.log.info("[ASYNC] scanning %d targets with %d workers, profile=%s",
                      len(clean), workers, profile)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._scan_one, t, profile, custom_args, detect_os): t
                for t in clean
            }
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    results[target] = fut.result()
                except Exception as e:
                    self.log.exception("[ASYNC] worker failed for %s", target)
                    results[target] = {"error": str(e)}
        return results

    # ---- worker ----

    def _scan_one(self, target: str, profile: str,
                  custom_args: str, detect_os: bool) -> dict:
        args = self.build_args(profile, custom_args)
        if detect_os:
            args = f"{args} {OS_DETECTION_ARGS}"

        # DB write có lock (SQLite serialized writer)
        with self._db_lock:
            scan_id, target_id = self._record_scan_start(target, profile, args)

        self.log.info("[ASYNC] %s -> nmap %s %s", target, args, target)

        nm = self._new_portscanner()   # instance riêng cho thread này
        try:
            nm.scan(hosts=target, arguments=args, timeout=NMAP_TIMEOUT)
        except nmap.PortScannerError as e:
            self.log.exception("[ASYNC] nmap error on %s", target)
            with self._db_lock:
                self._record_scan_end(scan_id, status="failed", raw=str(e))
            return {"error": str(e), "scan_id": scan_id}

        if target not in nm.all_hosts():
            self.log.warning("[ASYNC] %s không phản hồi", target)
            with self._db_lock:
                self._record_scan_end(scan_id, status="completed")
            return {"error": "no-response", "scan_id": scan_id}

        host_data = nm[target]

        with self._db_lock:
            self._save_result(scan_id, target_id, target, host_data)
            try:
                raw_xml = nm.get_nmap_last_output()
            except Exception:
                raw_xml = None
            self._record_scan_end(scan_id, status="completed", raw=raw_xml)

        return {
            "scan_id": scan_id,
            "target_id": target_id,
            "host": host_data,
        }