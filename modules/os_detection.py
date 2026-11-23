"""OS detection — wrapper quanh App.scan(detect_os=True)."""
from core import App
from utils.logger import get_logger, get_scan_logger
from utils.validator import validate_target

log = get_logger(__name__)


class OSDetector:
    def __init__(self, app: App | None = None):
        self.app = app or App()
        self.slog = get_scan_logger("os_detection")

    def detect(self, targets: list[str]) -> dict:
        """Detect OS cho list target. Trả dict {target: result}."""
        clean = [validate_target(t) for t in targets]
        if not clean:
            log.warning("OSDetector.detect: danh sách rỗng")
            return {}

        self.slog.info("[OS] detecting on %d target(s)", len(clean))
        results = self.app.scan(clean, profile="quick", detect_os=True)

        ok = sum(1 for v in results.values() if "host" in v)
        self.slog.info("[OS] done: %d/%d target(s) có kết quả", ok, len(clean))
        return results

    def detect_one(self, target: str) -> dict:
        return self.detect([target]).get(target, {})