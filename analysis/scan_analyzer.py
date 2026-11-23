"""Scan analysis: thống kê tổng quan + phân tích 1 lần scan.

Chỉ dùng dữ liệu đã có trong DB. Không ghi DB, không chấm điểm rủi ro.
"""
from __future__ import annotations

from collections import Counter

from sqlalchemy import select

from database import db_manager
from database.models import Target, Scan, Port
from utils.logger import get_logger

log = get_logger(__name__)


class ScanAnalyzer:
    """Đọc DB -> trả dict JSON-serializable (datetime đã chuyển isoformat)."""

    # ------------------------------------------------------------
    # 1. Thống kê tổng quan
    # ------------------------------------------------------------
    def summarize(self, target_id: int | None = None) -> dict:
        """
        Thống kê toàn DB (hoặc 1 target nếu truyền target_id).

        Return:
            {
              "scope": {"target_id": ...},
              "targets":  {"total": N, "by_status": {...}},
              "scans":    {"total": N, "by_type": {...}, "by_status": {...}},
              "ports":    {
                  "total_open": N,
                  "by_protocol": {"tcp": N, "udp": N},
                  "top_ports":    [{"port": 22, "count": 5}, ...],
                  "top_services": [{"service": "ssh", "count": 5}, ...]
              },
              "os_distribution": {"Linux": N, "Windows": N, ...}
            }
        """
        with db_manager.session() as s:
            t_q = select(Target)
            if target_id is not None:
                t_q = t_q.where(Target.id == target_id)
            targets = list(s.execute(t_q).scalars())

            sc_q = select(Scan)
            if target_id is not None:
                sc_q = sc_q.where(Scan.target_id == target_id)
            scans = list(s.execute(sc_q).scalars())

            p_q = select(Port)
            if target_id is not None:
                p_q = p_q.where(Port.target_id == target_id)
            ports = list(s.execute(p_q).scalars())

        # ---- targets ----
        status_counter = Counter((t.status or "unknown") for t in targets)
        os_counter     = Counter(t.os_family for t in targets if t.os_family)

        # ---- scans ----
        type_counter   = Counter(sc.scan_type for sc in scans)
        status_sc      = Counter((sc.status or "unknown") for sc in scans)

        # ---- ports ----
        open_ports     = [p for p in ports if p.state == "open"]
        proto_counter  = Counter(p.protocol for p in open_ports)
        port_counter   = Counter(p.port for p in open_ports)
        svc_counter    = Counter(p.service for p in open_ports if p.service)

        result = {
            "scope": {"target_id": target_id},
            "targets": {
                "total": len(targets),
                "by_status": dict(status_counter),
            },
            "scans": {
                "total": len(scans),
                "by_type": dict(type_counter),
                "by_status": dict(status_sc),
            },
            "ports": {
                "total_open": len(open_ports),
                "by_protocol": dict(proto_counter),
                "top_ports": [
                    {"port": port, "count": cnt}
                    for port, cnt in port_counter.most_common(10)
                ],
                "top_services": [
                    {"service": svc, "count": cnt}
                    for svc, cnt in svc_counter.most_common(10)
                ],
            },
            "os_distribution": dict(os_counter),
        }
        log.info("summarize(target_id=%s): targets=%d scans=%d open_ports=%d",
                 target_id, len(targets), len(scans), len(open_ports))
        return result

    # ------------------------------------------------------------
    # 2. Phân tích 1 lần scan
    # ------------------------------------------------------------
    def analyze_scan(self, scan_id: int) -> dict:
        """
        Phân tích chi tiết 1 scan theo scan_id.

        Return:
            {
              "scan": {
                  "scan_id": ..., "target_id": ..., "target_ip": ...,
                  "target_hostname": ..., "scan_type": ..., "command": ...,
                  "started_at": "iso", "finished_at": "iso"|None, "status": ...
              },
              "summary": {"total": N, "open": N, "closed": N,
                          "filtered": N, "other": N},
              "ports":   {"open": [...], "closed": [...],
                          "filtered": [...], "other": [...]},
              "services": [
                  {"port": 22, "protocol": "tcp", "service": "ssh",
                   "product": "OpenSSH", "version": "8.9"}
              ]
            }
        """
        with db_manager.session() as s:
            scan = s.get(Scan, scan_id)
            if scan is None:
                raise ValueError(f"Scan id={scan_id} không tồn tại")

            target = s.get(Target, scan.target_id)
            ports  = list(s.execute(
                select(Port).where(Port.scan_id == scan_id).order_by(Port.port)
            ).scalars())

            scan_info = {
                "scan_id":         scan.id,
                "target_id":       scan.target_id,
                "target_ip":       target.ip if target else None,
                "target_hostname": target.hostname if target else None,
                "scan_type":       scan.scan_type,
                "command":         scan.command,
                "started_at":      scan.started_at.isoformat() if scan.started_at else None,
                "finished_at":     scan.finished_at.isoformat() if scan.finished_at else None,
                "status":          scan.status,
            }
            port_dicts = [p.to_dict() for p in ports]

        # ---- gom port theo state ----
        by_state = {"open": [], "closed": [], "filtered": [], "other": []}
        for p in port_dicts:
            state = p["state"] or "other"
            key = state if state in by_state else "other"
            by_state[key].append(p)

        # ---- services (chỉ port open) ----
        services = [
            {
                "port":     p["port"],
                "protocol": p["protocol"],
                "service":  p["service"],
                "product":  p["product"],
                "version":  p["version"],
            }
            for p in by_state["open"]
        ]

        summary = {
            "total":    len(port_dicts),
            "open":     len(by_state["open"]),
            "closed":   len(by_state["closed"]),
            "filtered": len(by_state["filtered"]),
            "other":    len(by_state["other"]),
        }

        log.info("analyze_scan(scan_id=%s): total=%d open=%d",
                 scan_id, summary["total"], summary["open"])

        return {
            "scan":     scan_info,
            "summary":  summary,
            "ports":    by_state,
            "services": services,
        }