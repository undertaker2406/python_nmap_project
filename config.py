"""Cấu hình toàn cục cho NetRecon."""
from pathlib import Path

# ---------- Thư mục gốc ----------
BASE_DIR = Path(__file__).resolve().parent

DATA_DIR         = BASE_DIR / "data"
LOGS_DIR         = BASE_DIR / "logs"
REPORTS_DIR      = BASE_DIR / "reports"
DB_STORAGE_DIR   = BASE_DIR / "database_storage"

for _d in (DATA_DIR, LOGS_DIR, REPORTS_DIR, DB_STORAGE_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------- Files ----------
DB_PATH      = DB_STORAGE_DIR / "netrecon.db"
DB_URL       = f"sqlite:///{DB_PATH}"
TARGETS_FILE = DATA_DIR / "targets.txt"

LOG_FILE       = LOGS_DIR / "netrecon.log"
SCAN_LOG_FILE  = LOGS_DIR / "scan.log"
ERROR_LOG_FILE = LOGS_DIR / "error.log"

# ---------- Logging ----------
LOG_LEVEL          = "INFO"
LOG_FORMAT         = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT    = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES      = 5 * 1024 * 1024   # 5 MB
LOG_BACKUP_COUNT   = 5

# ---------- Scan profiles ----------
SCAN_PROFILES = {
    "quick":     {"args": "-T4 -F",                      "label": "Quick Scan"},
    "standard":  {"args": "-T4 -sV -p 1-1000",           "label": "Standard Scan"},
    "full_tcp":  {"args": "-T4 -sV -p-",                 "label": "Full TCP Scan"},
    "udp":       {"args": "-T4 -sU --top-ports 100",     "label": "UDP Scan"},
    "custom":    {"args": "",                            "label": "Custom Scan"},
}

# ---------- Scan runtime ----------
NMAP_TIMEOUT          = 600        # giây / 1 target
MAX_CONCURRENT_SCANS  = 10         # cho async scan
DEFAULT_PORTS         = "1-1000"

# ---------- Traceroute ----------
TRACEROUTE_MAX_HOPS = 30

# ---------- OS detection ----------
OS_DETECTION_ARGS = "-O --osscan-guess"