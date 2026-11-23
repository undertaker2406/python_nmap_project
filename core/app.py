"""Facade: chọn SyncScanner hay AsyncScanner tự động."""
from __future__ import annotations

from config import MAX_CONCURRENT_SCANS
from core.sync_scanner import SyncScanner
from core.async_scanner import AsyncScanner
from utils.logger import get_logger, get_scan_logger
from utils.validator import validate_scan_profile

log = get_logger(__name__)


class App:
    """Singleton facade — nơi CLI/interface gọi vào."""

    def __init__(self, nmap_path: str | None = None):
        self.nmap_path = nmap_path

    def scan(self, targets: list[str], profile: str = "quick",
             custom_args: str = "", detect_os: bool = False) -> dict:
        """
        Tự động route:
            - 1 target  -> SyncScanner
            - >1 target -> AsyncScanner (nhiều thread)
        """
        validate_scan_profile(profile)
        slog = get_scan_logger("app")
        slog.info("App.scan targets=%d profile=%s detect_os=%s",
                  len(targets), profile, detect_os)

        if len(targets) == 1:
            scanner = SyncScanner(self.nmap_path)
        else:
            scanner = AsyncScanner(self.nmap_path, max_workers=MAX_CONCURRENT_SCANS)

        return scanner.run(
            targets=targets, profile=profile,
            custom_args=custom_args, detect_os=detect_os,
        )