"""Validate IP / CIDR / hostname / port range / NSE script."""
import ipaddress
import re

from utils.logger import get_logger

log = get_logger(__name__)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_PORT_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")

_IPV4_LIKE_RE = re.compile(r"^[\d\.]+$")

def _looks_like_ipv4(target: str) -> bool:
    return bool(_IPV4_LIKE_RE.match(target))

class ValidationError(ValueError):
    """Raise khi input không hợp lệ."""



def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_hostname(host: str) -> bool:
    return bool(_HOSTNAME_RE.match(host))


def is_valid_target(target: str) -> bool:
    """Target hợp lệ = IP | CIDR | hostname."""
    if _looks_like_ipv4(target):
        return is_valid_ip(target)          # 999.1.1.1 -> False
    return (
        is_valid_ip(target)
        or is_valid_cidr(target)
        or is_valid_hostname(target)
    )


def validate_target(target: str) -> str:
    """Trả về target đã strip, raise nếu sai."""
    t = (target or "").strip()
    if not t:
        raise ValidationError("Target rỗng")
    if not is_valid_target(t):
        raise ValidationError(f"Target không hợp lệ: {t!r}")
    return t


def validate_targets(targets: list[str]) -> list[str]:
    """Validate list, tự bỏ trùng, giữ thứ tự."""
    seen, out = set(), []
    for t in targets:
        v = validate_target(t)
        if v not in seen:
            seen.add(v)
            out.append(v)
    if not out:
        raise ValidationError("Danh sách target rỗng")
    return out


def parse_port_range(spec: str) -> list[int]:
    """'22', '22-80', '22,80,443', '1-100' -> list[int]."""
    if not spec:
        raise ValidationError("Port spec rỗng")
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = _PORT_RE.match(chunk)
        if not m:
            raise ValidationError(f"Port spec sai: {chunk!r}")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if not (0 < lo <= 65535 and 0 < hi <= 65535 and lo <= hi):
            raise ValidationError(f"Port ngoài phạm vi: {chunk!r}")
        ports.update(range(lo, hi + 1))
    if not ports:
        raise ValidationError("Không parse được port nào")
    return sorted(ports)


def validate_port_spec(spec: str) -> str:
    """Chấp nhận cả '1-1000' lẫn '22,80,443', trả string chuẩn hoá."""
    parse_port_range(spec)  # raise nếu sai
    return spec.strip()


def validate_nse_script(name: str) -> str:
    """Chặn path traversal và ký tự lạ trong tên NSE script."""
    n = (name or "").strip()
    if not n:
        raise ValidationError("NSE script rỗng")
    if not re.match(r"^[A-Za-z0-9_\-,\.]+$", n):
        raise ValidationError(f"NSE script không hợp lệ: {name!r}")
    return n


def validate_scan_profile(profile: str) -> str:
    from config import SCAN_PROFILES
    if profile not in SCAN_PROFILES:
        raise ValidationError(
            f"Profile {profile!r} không tồn tại. "
            f"Hợp lệ: {', '.join(SCAN_PROFILES.keys())}"
        )
    return profile