"""Logger tập trung cho NetRecon.

Cách dùng:
    from utils.logger import get_logger, get_scan_logger
    log = get_logger(__name__)              # netrecon.<module>
    slog = get_scan_logger("port_scanner")  # netrecon.scan.port_scanner -> ghi vào scan.log
"""
import logging
from logging.handlers import RotatingFileHandler

from config import (
    LOG_FILE, SCAN_LOG_FILE, ERROR_LOG_FILE,
    LOG_LEVEL, LOG_FORMAT, LOG_DATE_FORMAT,
    LOG_MAX_BYTES, LOG_BACKUP_COUNT,
)

ROOT_NAME = "netrecon"
_SCAN_PREFIX = f"{ROOT_NAME}.scan"


class _ScanFilter(logging.Filter):
    """Chỉ cho record thuộc namespace netrecon.scan* đi qua."""
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.startswith(_SCAN_PREFIX)


def _rotating(path, level):
    h = RotatingFileHandler(
        path, maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT, encoding="utf-8",
    )
    h.setLevel(level)
    h.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    return h


def _setup_root() -> logging.Logger:
    root = logging.getLogger(ROOT_NAME)
    if root.handlers:              # tránh add trùng khi import lại
        return root

    root.setLevel(LOG_LEVEL)
    root.propagate = False

    # netrecon.log  -> mọi level
    root.addHandler(_rotating(LOG_FILE, logging.DEBUG))

    # scan.log      -> chỉ log thuộc netrecon.scan*
    scan_h = _rotating(SCAN_LOG_FILE, logging.INFO)
    scan_h.addFilter(_ScanFilter())
    root.addHandler(scan_h)

    # error.log     -> ERROR trở lên
    root.addHandler(_rotating(ERROR_LOG_FILE, logging.ERROR))

    # console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    root.addHandler(console)

    return root


_setup_root()


def get_logger(name: str = ROOT_NAME) -> logging.Logger:
    if name == ROOT_NAME or name.startswith(f"{ROOT_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{ROOT_NAME}.{name}")


def get_scan_logger(name: str = "scan") -> logging.Logger:
    """Trả về logger nằm dưới namespace scan -> tự ghi vào scan.log."""
    if name.startswith(_SCAN_PREFIX):
        full = name
    elif name.startswith("scan."):
        full = f"{ROOT_NAME}.{name}"
    else:
        full = f"{_SCAN_PREFIX}.{name}"
    return logging.getLogger(full)