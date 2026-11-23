"""Tiện ích mạng: lấy subnet nội bộ, expand CIDR, ping check, MAC vendor."""
import ipaddress
import socket
import subprocess
import sys

from utils.logger import get_logger

log = get_logger(__name__)


def get_local_ip() -> str:
    """Lấy IP LAN của máy (không cần kết nối thật tới 8.8.8.8)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_local_subnet() -> str:
    """Trả về CIDR /24 của mạng LAN hiện tại, vd: '192.168.1.0/24'."""
    ip = get_local_ip()
    # Giả định /24 cho mạng nội bộ — có thể nâng cấp để đọc netmask
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    log.info("Local subnet detected: %s", net)
    return str(net)


def expand_targets(targets: list[str]) -> list[str]:
    """Expand CIDR thành danh sách IP; giữ nguyên IP/hostname."""
    out: list[str] = []
    seen: set[str] = set()

    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if "/" in t and net.num_addresses > 1:
                # Bỏ network + broadcast
                hosts = net.hosts() if net.num_addresses > 2 else iter(net)
                for ip in hosts:
                    s = str(ip)
                    if s not in seen:
                        seen.add(s)
                        out.append(s)
                continue
        except ValueError:
            pass

        if t not in seen:
            seen.add(t)
            out.append(t)

    log.info("Expanded %d target(s) -> %d host(s)", len(targets), len(out))
    return out


def is_host_alive(ip: str, timeout: float = 1.0) -> bool:
    """Ping nhanh 1 IP (fallback khi không muốn dùng nmap -sn)."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        return r.returncode == 0
    except Exception:
        return False


def reverse_dns(ip: str, timeout: float = 1.0) -> str | None:
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def format_ports(ports: list[int], limit: int = 20) -> str:
    """Format đẹp: 22, 80, 443 ... (+N more)."""
    if not ports:
        return "(none)"
    shown = ", ".join(str(p) for p in ports[:limit])
    if len(ports) > limit:
        shown += f" ... (+{len(ports) - limit} more)"
    return shown