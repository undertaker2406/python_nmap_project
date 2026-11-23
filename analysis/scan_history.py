"""Scan history: truy vấn / lọc / quản lý lịch sử scan trong DB.

Khác analyzer:
- analyzer  -> tính toán, thống kê, phân tích chi tiết 1 scan
- history   -> liệt kê, lọc, xoá, lấy scan gần nhất
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, delete, func

from database import db_manager
from database.models import Target, Scan
from utils.logger import get_logger

log = get_logger(__name__)


class ScanHistory:
    # ------------------------------------------------------------
    # Liệt kê + lọc
    # ------------------------------------------------------------
    def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        target_id: int | None = None,
        target_ip: str | None = None,
        scan_type: str | None = None,
        status: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> list[dict]:
        """
        Liệt kê scan theo nhiều filter. Trả list dict đã kèm target_ip/hostname.
        Sắp xếp mới nhất trước.
        """
        with db_manager.session() as s:
            stmt = (
                select(Scan, Target)
                .join(Target, Scan.target_id == Target.id)
                .order_by(Scan.started_at.desc())
                .limit(limit)
                .offset(offset)
            )
            if target_id is not None:
                stmt = stmt.where(Scan.target_id == target_id)
            if target_ip is not None:
                stmt = stmt.where(Target.ip == target_ip)
            if scan_type is not None:
                stmt = stmt.where(Scan.scan_type == scan_type)
            if status is not None:
                stmt = stmt.where(Scan.status == status)
            if date_from is not None:
                stmt = stmt.where(Scan.started_at >= date_from)
            if date_to is not None:
                stmt = stmt.where(Scan.started_at <= date_to)

            rows = s.execute(stmt).all()

        out = [self._to_dict(sc, t) for sc, t in rows]
        log.info("list_scans: %d record(s)", len(out))
        return out

    def count(self, target_id: int | None = None) -> int:
        with db_manager.session() as s:
            stmt = select(func.count(Scan.id))
            if target_id is not None:
                stmt = stmt.where(Scan.target_id == target_id)
            return s.execute(stmt).scalar_one()

    # ------------------------------------------------------------
    # Lấy 1 scan / scan gần nhất
    # ------------------------------------------------------------
    def get_scan(self, scan_id: int) -> dict | None:
        with db_manager.session() as s:
            row = s.execute(
                select(Scan, Target)
                .join(Target, Scan.target_id == Target.id)
                .where(Scan.id == scan_id)
            ).first()
        return self._to_dict(*row) if row else None

    def latest_scan(self, target_id: int) -> dict | None:
        """Scan gần nhất (completed) của 1 target."""
        with db_manager.session() as s:
            row = s.execute(
                select(Scan, Target)
                .join(Target, Scan.target_id == Target.id)
                .where(Scan.target_id == target_id)
                .where(Scan.status == "completed")
                .order_by(Scan.finished_at.desc())
                .limit(1)
            ).first()
        return self._to_dict(*row) if row else None

    def previous_scan(self, target_id: int, before_scan_id: int) -> dict | None:
        """Scan liền trước `before_scan_id` của cùng target (dùng để diff sau này)."""
        with db_manager.session() as s:
            cur = s.get(Scan, before_scan_id)
            if cur is None:
                return None
            row = s.execute(
                select(Scan, Target)
                .join(Target, Scan.target_id == Target.id)
                .where(Scan.target_id == target_id)
                .where(Scan.id < before_scan_id)
                .where(Scan.status == "completed")
                .order_by(Scan.id.desc())
                .limit(1)
            ).first()
        return self._to_dict(*row) if row else None

    # ------------------------------------------------------------
    # Xoá
    # ------------------------------------------------------------
    def delete_scan(self, scan_id: int) -> bool:
        with db_manager.session() as s:
            sc = s.get(Scan, scan_id)
            if sc is None:
                return False
            s.delete(sc)   # cascade xoá ports + hops
        log.info("Deleted scan id=%s", scan_id)
        return True

    def delete_older_than(self, before: datetime,
                          target_id: int | None = None) -> int:
        """Xoá scan cũ hơn mốc thời gian. Trả số record đã xoá."""
        with db_manager.session() as s:
            stmt = delete(Scan).where(Scan.started_at < before)
            if target_id is not None:
                stmt = stmt.where(Scan.target_id == target_id)
            result = s.execute(stmt)
            n = result.rowcount or 0
        log.info("Deleted %d scan(s) older than %s", n, before.isoformat())
        return n

    # ------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------
    @staticmethod
    def _to_dict(sc: Scan, t: Target) -> dict:
        return {
            "scan_id":         sc.id,
            "target_id":       sc.target_id,
            "target_ip":       t.ip,
            "target_hostname": t.hostname,
            "scan_type":       sc.scan_type,
            "command":         sc.command,
            "status":          sc.status,
            "started_at":      sc.started_at.isoformat() if sc.started_at else None,
            "finished_at":     sc.finished_at.isoformat() if sc.finished_at else None,
        }