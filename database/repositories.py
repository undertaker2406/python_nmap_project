"""CRUD repositories cho từng model."""
from datetime import datetime

from sqlalchemy import select, func

from database.db_manager import db_manager
from database.models import Target, Scan, Port, TracerouteHop
from utils.logger import get_logger

log = get_logger(__name__)


class TargetRepository:
    def upsert(self, ip: str, **fields) -> Target:
        with db_manager.session() as s:
            t = s.execute(select(Target).where(Target.ip == ip)).scalar_one_or_none()
            if t is None:
                t = Target(ip=ip, **fields)
                s.add(t)
                log.info("New target discovered: %s", ip)
            else:
                for k, v in fields.items():
                    setattr(t, k, v)
                t.last_seen = datetime.utcnow()
            s.flush()
            return t

    def get_by_ip(self, ip: str) -> Target | None:
        with db_manager.session() as s:
            return s.execute(select(Target).where(Target.ip == ip)).scalar_one_or_none()

    def list_all(self) -> list[Target]:
        with db_manager.session() as s:
            return list(s.execute(select(Target)).scalars())

    def update_os(self, ip: str, os_family, os_match, accuracy) -> None:
        self.upsert(ip, os_family=os_family, os_match=os_match, os_accuracy=accuracy)
        log.info("OS updated for %s -> %s (%s%%)", ip, os_family, accuracy)

    def count(self) -> int:
        with db_manager.session() as s:
            return s.execute(select(func.count(Target.id))).scalar_one()


class ScanRepository:
    def create(self, target_id: int, scan_type: str, command: str = "") -> int:
        with db_manager.session() as s:
            sc = Scan(target_id=target_id, scan_type=scan_type, command=command)
            s.add(sc)
            s.flush()
            return sc.id

    def finish(self, scan_id: int, status: str = "completed",
               raw_output: str | None = None) -> None:
        with db_manager.session() as s:
            sc = s.get(Scan, scan_id)
            if sc is None:
                return
            sc.finished_at = datetime.utcnow()
            sc.status = status
            if raw_output is not None:
                sc.raw_output = raw_output

    def get(self, scan_id: int) -> Scan | None:
        with db_manager.session() as s:
            return s.get(Scan, scan_id)

    def history(self, limit: int = 50, target_id: int | None = None) -> list[Scan]:
        with db_manager.session() as s:
            stmt = select(Scan).order_by(Scan.started_at.desc()).limit(limit)
            if target_id is not None:
                stmt = stmt.where(Scan.target_id == target_id)
            return list(s.execute(stmt).scalars())


class PortRepository:
    def add_ports(self, scan_id: int, target_id: int, ports: list[dict]) -> None:
        if not ports:
            return
        with db_manager.session() as s:
            for p in ports:
                s.add(Port(
                    scan_id=scan_id, target_id=target_id,
                    port=p["port"], protocol=p.get("protocol", "tcp"),
                    state=p.get("state"), service=p.get("service"),
                    product=p.get("product"), version=p.get("version"),
                    extra_info=p.get("extra_info"),
                ))
        log.info("Saved %d port(s) for target_id=%s scan_id=%s",
                 len(ports), target_id, scan_id)

    def list_by_scan(self, scan_id: int) -> list[Port]:
        with db_manager.session() as s:
            return list(s.execute(
                select(Port).where(Port.scan_id == scan_id).order_by(Port.port)
            ).scalars())

    def list_by_target(self, target_id: int) -> list[Port]:
        with db_manager.session() as s:
            return list(s.execute(
                select(Port).where(Port.target_id == target_id).order_by(Port.port)
            ).scalars())


class TracerouteRepository:
    def add_hops(self, scan_id: int, hops: list[dict]) -> None:
        if not hops:
            return
        with db_manager.session() as s:
            for h in hops:
                s.add(TracerouteHop(
                    scan_id=scan_id,
                    hop_number=h["hop_number"],
                    hop_ip=h.get("hop_ip"),
                    hop_hostname=h.get("hop_hostname"),
                    rtt=h.get("rtt"),
                ))
        log.info("Saved %d traceroute hop(s) for scan_id=%s", len(hops), scan_id)

    def list_by_scan(self, scan_id: int) -> list[TracerouteHop]:
        with db_manager.session() as s:
            return list(s.execute(
                select(TracerouteHop)
                .where(TracerouteHop.scan_id == scan_id)
                .order_by(TracerouteHop.hop_number)
            ).scalars())


# ---- singleton instances ----
targets_repo    = TargetRepository()
scans_repo      = ScanRepository()
ports_repo      = PortRepository()
traceroute_repo = TracerouteRepository()