"""Report generator: xuất báo cáo JSON / Markdown / HTML.

Ba scope:
    - global  : toàn DB
    - target  : 1 target cụ thể
    - scan    : 1 lần scan (kèm chi tiết port)

Không phụ thuộc thư viện ngoài. HTML dùng inline CSS.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from config import REPORTS_DIR
from analysis.scan_analyzer import ScanAnalyzer
from analysis.scan_history import ScanHistory
from utils.logger import get_logger

log = get_logger(__name__)

SUPPORTED_FORMATS = ("json", "md", "html")


class ReportGenerator:
    def __init__(self, output_dir: Path | None = None):
        self.out_dir = Path(output_dir) if output_dir else REPORTS_DIR
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.analyzer = ScanAnalyzer()
        self.history = ScanHistory()

    # ------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------
    def generate(self, scope: str = "global",
                 scope_id: int | None = None,
                 formats: tuple[str, ...] | list[str] = SUPPORTED_FORMATS,
                 recent_limit: int = 30) -> dict[str, Path]:
        """
        scope: "global" | "target" | "scan"
        scope_id: bắt buộc khi scope != global
        formats: subset của ("json", "md", "html")
        recent_limit: số scan lịch sử đưa vào báo cáo

        Return: {"json": Path, "md": Path, "html": Path} (chỉ gồm format đã yêu cầu)
        """
        formats = [f.lower() for f in formats]
        for f in formats:
            if f not in SUPPORTED_FORMATS:
                raise ValueError(f"Format không hỗ trợ: {f!r}. Chọn: {SUPPORTED_FORMATS}")

        data = self._collect(scope, scope_id, recent_limit)
        stem = self._filename(scope, scope_id)

        out: dict[str, Path] = {}
        for fmt in formats:
            path = self.out_dir / f"{stem}.{fmt}"
            if fmt == "json":
                content = self._build_json(data)
            elif fmt == "md":
                content = self._build_markdown(data)
            else:
                content = self._build_html(data)
            path.write_text(content, encoding="utf-8")
            log.info("Report [%s] -> %s", fmt, path)
            out[fmt] = path

        log.info("Generated %d report(s) for scope=%s id=%s",
                 len(out), scope, scope_id)
        return out

    # convenience
    def generate_global(self, formats=SUPPORTED_FORMATS) -> dict[str, Path]:
        return self.generate("global", None, formats)

    def generate_for_target(self, target_id: int,
                            formats=SUPPORTED_FORMATS) -> dict[str, Path]:
        return self.generate("target", target_id, formats)

    def generate_for_scan(self, scan_id: int,
                          formats=SUPPORTED_FORMATS) -> dict[str, Path]:
        return self.generate("scan", scan_id, formats)

    # ------------------------------------------------------------
    # Collect data
    # ------------------------------------------------------------
    def _collect(self, scope: str, scope_id: int | None, recent_limit: int) -> dict:
        meta = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scope": scope,
            "scope_id": scope_id,
        }

        if scope == "global":
            meta["title"] = "NetRecon — Global Report"
            return {
                "meta": meta,
                "summary": self.analyzer.summarize(),
                "scans": self.history.list_scans(limit=recent_limit),
                "scan_details": [],
            }

        if scope == "target":
            if scope_id is None:
                raise ValueError("scope='target' yêu cầu scope_id")
            meta["title"] = f"NetRecon — Target Report (id={scope_id})"
            scans = self.history.list_scans(target_id=scope_id, limit=recent_limit)
            target_ip = scans[0]["target_ip"] if scans else None
            meta["target_ip"] = target_ip
            return {
                "meta": meta,
                "summary": self.analyzer.summarize(target_id=scope_id),
                "scans": scans,
                "scan_details": [],
            }

        if scope == "scan":
            if scope_id is None:
                raise ValueError("scope='scan' yêu cầu scope_id")
            detail = self.analyzer.analyze_scan(scope_id)
            meta["title"] = f"NetRecon — Scan Report (id={scope_id})"
            meta["target_ip"] = detail["scan"]["target_ip"]
            return {
                "meta": meta,
                "summary": None,
                "scans": [{
                    "scan_id":         detail["scan"]["scan_id"],
                    "target_id":       detail["scan"]["target_id"],
                    "target_ip":       detail["scan"]["target_ip"],
                    "target_hostname": detail["scan"]["target_hostname"],
                    "scan_type":       detail["scan"]["scan_type"],
                    "command":         detail["scan"]["command"],
                    "status":          detail["scan"]["status"],
                    "started_at":      detail["scan"]["started_at"],
                    "finished_at":     detail["scan"]["finished_at"],
                }],
                "scan_details": [detail],
            }

        raise ValueError(f"scope không hợp lệ: {scope!r}")

    def _filename(self, scope: str, scope_id: int | None) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if scope == "global":
            return f"netrecon_global_{ts}"
        return f"netrecon_{scope}{scope_id}_{ts}"

    # ============================================================
    # JSON
    # ============================================================
    def _build_json(self, data: dict) -> str:
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    # ============================================================
    # Markdown
    # ============================================================
    def _build_markdown(self, data: dict) -> str:
        m = data["meta"]
        L: list[str] = []
        L.append(f"# {m['title']}")
        L.append("")
        L.append(f"- **Generated:** {m['generated_at']}")
        L.append(f"- **Scope:** `{m['scope']}`"
                 + (f" (id={m['scope_id']})" if m["scope_id"] is not None else ""))
        if m.get("target_ip"):
            L.append(f"- **Target:** `{m['target_ip']}`")
        L.append("")

        if data.get("summary"):
            L += self._md_summary(data["summary"])

        if data.get("scans"):
            L.append("## Scan History")
            L.append("")
            rows = [
                [s["scan_id"], f"`{s['target_ip']}`", s["scan_type"],
                 s["status"], s["started_at"], s["finished_at"] or "—"]
                for s in data["scans"]
            ]
            L.append(self._md_table(
                ["Scan ID", "Target", "Type", "Status", "Started", "Finished"],
                rows,
            ))
            L.append("")

        for detail in data.get("scan_details", []):
            L += self._md_scan_detail(detail)

        L.append("---")
        L.append(f"*Generated by NetRecon at {m['generated_at']}*")
        return "\n".join(L) + "\n"

    def _md_summary(self, s: dict) -> list[str]:
        L: list[str] = []
        L.append("## Summary")
        L.append("")

        L.append("### Targets")
        L.append("")
        rows = [["Tổng", s["targets"]["total"]]]
        rows += [[k, v] for k, v in s["targets"]["by_status"].items()]
        L.append(self._md_table(["Chỉ số", "Giá trị"], rows))
        L.append("")

        L.append("### Scans")
        L.append("")
        rows = [
            ["Tổng", s["scans"]["total"]],
            ["By type", ", ".join(f"{k}={v}" for k, v in s["scans"]["by_type"].items()) or "—"],
            ["By status", ", ".join(f"{k}={v}" for k, v in s["scans"]["by_status"].items()) or "—"],
        ]
        L.append(self._md_table(["Chỉ số", "Giá trị"], rows))
        L.append("")

        L.append("### Ports (open)")
        L.append("")
        rows = [
            ["Tổng open", s["ports"]["total_open"]],
            ["By protocol", ", ".join(f"{k}={v}" for k, v in s["ports"]["by_protocol"].items()) or "—"],
        ]
        L.append(self._md_table(["Chỉ số", "Giá trị"], rows))
        L.append("")

        if s["ports"]["top_ports"]:
            L.append("**Top ports**")
            L.append("")
            L.append(self._md_table(
                ["Port", "Số lần mở"],
                [[p["port"], p["count"]] for p in s["ports"]["top_ports"]],
            ))
            L.append("")

        if s["ports"]["top_services"]:
            L.append("**Top services**")
            L.append("")
            L.append(self._md_table(
                ["Service", "Số lần"],
                [[x["service"], x["count"]] for x in s["ports"]["top_services"]],
            ))
            L.append("")

        if s["os_distribution"]:
            L.append("### OS Distribution")
            L.append("")
            L.append(self._md_table(
                ["OS Family", "Số target"],
                [[k, v] for k, v in s["os_distribution"].items()],
            ))
            L.append("")
        return L

    def _md_scan_detail(self, d: dict) -> list[str]:
        s = d["scan"]
        L: list[str] = []
        L.append(f"## Scan detail — ID {s['scan_id']}")
        L.append("")
        L.append(self._md_table(
            ["Trường", "Giá trị"],
            [
                ["Target", f"`{s['target_ip']}`" + (f" ({s['target_hostname']})" if s["target_hostname"] else "")],
                ["Scan type", s["scan_type"]],
                ["Command", f"`{s['command']}`"],
                ["Status", s["status"]],
                ["Started", s["started_at"]],
                ["Finished", s["finished_at"] or "—"],
            ],
        ))
        L.append("")

        sm = d["summary"]
        L.append("### Summary")
        L.append("")
        L.append(self._md_table(
            ["State", "Số port"],
            [["open", sm["open"]], ["closed", sm["closed"]],
             ["filtered", sm["filtered"]], ["other", sm["other"]],
             ["**Tổng**", sm["total"]]],
        ))
        L.append("")

        if d["services"]:
            L.append("### Services (open)")
            L.append("")
            L.append(self._md_table(
                ["Port", "Proto", "Service", "Product", "Version"],
                [[p["port"], p["protocol"], p["service"] or "—",
                  p["product"] or "—", p["version"] or "—"]
                 for p in d["services"]],
            ))
            L.append("")
        return L

    @staticmethod
    def _md_table(headers: list, rows: list) -> str:
        out = ["| " + " | ".join(str(h) for h in headers) + " |"]
        out.append("|" + "|".join(["---"] * len(headers)) + "|")
        for r in rows:
            out.append("| " + " | ".join(str(c) for c in r) + " |")
        return "\n".join(out)

    # ============================================================
    # HTML
    # ============================================================
    def _build_html(self, data: dict) -> str:
        m = data["meta"]
        e = html.escape

        parts: list[str] = []
        parts.append("<!DOCTYPE html>")
        parts.append("<html lang='vi'><head><meta charset='UTF-8'>")
        parts.append(f"<title>{e(m['title'])}</title>")
        parts.append(self._html_css())
        parts.append("</head><body>")

        parts.append(f"<h1>{e(m['title'])}</h1>")
        parts.append("<div class='meta'>")
        parts.append(f"<div><strong>Generated:</strong> {e(m['generated_at'])}</div>")
        parts.append(f"<div><strong>Scope:</strong> <code>{e(m['scope'])}</code>"
                     + (f" (id={m['scope_id']})" if m["scope_id"] is not None else "")
                     + "</div>")
        if m.get("target_ip"):
            parts.append(f"<div><strong>Target:</strong> <code>{e(m['target_ip'])}</code></div>")
        parts.append("</div>")

        if data.get("summary"):
            parts.append(self._html_summary(data["summary"]))

        if data.get("scans"):
            parts.append("<h2>Scan History</h2>")
            rows = [
                [s["scan_id"], f"<code>{e(s['target_ip'])}</code>", s["scan_type"],
                 s["status"], s["started_at"], s["finished_at"] or "—"]
                for s in data["scans"]
            ]
            parts.append(self._html_table(
                ["Scan ID", "Target", "Type", "Status", "Started", "Finished"], rows,
            ))

        for detail in data.get("scan_details", []):
            parts.append(self._html_scan_detail(detail))

        parts.append(f"<hr><p class='meta'>Generated by NetRecon at {e(m['generated_at'])}</p>")
        parts.append("</body></html>")
        return "\n".join(parts)

    def _html_summary(self, s: dict) -> str:
        e = html.escape
        parts = ["<h2>Summary</h2>"]

        parts.append("<h3>Targets</h3>")
        rows = [["Tổng", s["targets"]["total"]]]
        rows += [[k, v] for k, v in s["targets"]["by_status"].items()]
        parts.append(self._html_table(["Chỉ số", "Giá trị"], rows))

        parts.append("<h3>Scans</h3>")
        rows = [
            ["Tổng", s["scans"]["total"]],
            ["By type", e(", ".join(f"{k}={v}" for k, v in s["scans"]["by_type"].items()) or "—")],
            ["By status", e(", ".join(f"{k}={v}" for k, v in s["scans"]["by_status"].items()) or "—")],
        ]
        parts.append(self._html_table(["Chỉ số", "Giá trị"], rows))

        parts.append("<h3>Ports (open)</h3>")
        rows = [
            ["Tổng open", s["ports"]["total_open"]],
            ["By protocol", e(", ".join(f"{k}={v}" for k, v in s["ports"]["by_protocol"].items()) or "—")],
        ]
        parts.append(self._html_table(["Chỉ số", "Giá trị"], rows))

        if s["ports"]["top_ports"]:
            parts.append("<h4>Top ports</h4>")
            parts.append(self._html_table(
                ["Port", "Số lần mở"],
                [[p["port"], p["count"]] for p in s["ports"]["top_ports"]],
            ))

        if s["ports"]["top_services"]:
            parts.append("<h4>Top services</h4>")
            parts.append(self._html_table(
                ["Service", "Số lần"],
                [[x["service"], x["count"]] for x in s["ports"]["top_services"]],
            ))

        if s["os_distribution"]:
            parts.append("<h3>OS Distribution</h3>")
            parts.append(self._html_table(
                ["OS Family", "Số target"],
                [[k, v] for k, v in s["os_distribution"].items()],
            ))
        return "".join(parts)

    def _html_scan_detail(self, d: dict) -> str:
        e = html.escape
        s = d["scan"]
        parts = [f"<h2>Scan detail — ID {s['scan_id']}</h2>"]
        parts.append(self._html_table(
            ["Trường", "Giá trị"],
            [
                ["Target", f"<code>{e(s['target_ip'] or '')}</code>"
                           + (f" ({e(s['target_hostname'])})" if s["target_hostname"] else "")],
                ["Scan type", e(s["scan_type"])],
                ["Command", f"<code>{e(s['command'] or '')}</code>"],
                ["Status", e(s["status"] or "")],
                ["Started", e(s["started_at"] or "")],
                ["Finished", e(s["finished_at"] or "—")],
            ],
        ))

        sm = d["summary"]
        parts.append("<h3>Summary</h3>")
        parts.append(self._html_table(
            ["State", "Số port"],
            [["open", sm["open"]], ["closed", sm["closed"]],
             ["filtered", sm["filtered"]], ["other", sm["other"]],
             ["<strong>Tổng</strong>", sm["total"]]],
        ))

        if d["services"]:
            parts.append("<h3>Services (open)</h3>")
            rows = []
            for p in d["services"]:
                state_cls = "badge-open"
                rows.append([
                    f"<span class='badge {state_cls}'>{p['port']}</span>",
                    e(p["protocol"]),
                    e(p["service"] or "—"),
                    e(p["product"] or "—"),
                    e(p["version"] or "—"),
                ])
            parts.append(self._html_table(
                ["Port", "Proto", "Service", "Product", "Version"], rows,
            ))
        return "".join(parts)

    @staticmethod
    def _html_table(headers: list, rows: list) -> str:
        e = html.escape
        out = ["<table><thead><tr>"]
        for h in headers:
            out.append(f"<th>{e(str(h))}</th>")
        out.append("</tr></thead><tbody>")
        for r in rows:
            out.append("<tr>")
            for c in r:
                # cho phép cell đã là HTML (badge/code) -> chỉ escape nếu không bắt đầu bằng '<'
                cell = str(c)
                out.append(f"<td>{cell if cell.startswith('<') else e(cell)}</td>")
            out.append("</tr>")
        out.append("</tbody></table>")
        return "".join(out)

    @staticmethod
    def _html_css() -> str:
        return """<style>
body { font-family: -apple-system, system-ui, "Segoe UI", Roboto, sans-serif;
       max-width: 1100px; margin: 2em auto; padding: 0 1.2em;
       color: #222; background: #fafafa; line-height: 1.55; }
h1 { border-bottom: 2px solid #0066cc; padding-bottom: .3em; color: #004499; }
h2 { color: #0066cc; margin-top: 2em; border-left: 4px solid #0066cc; padding-left: .6em; }
h3 { color: #334; margin-top: 1.6em; }
h4 { color: #556; }
code { background: #eef2f5; padding: .1em .35em; border-radius: 3px; font-size: .92em; }
.meta { color: #555; background: #fff; padding: .8em 1em; border-radius: 6px;
        box-shadow: 0 1px 2px rgba(0,0,0,.06); margin-bottom: 1.5em; }
.meta div { margin: .15em 0; }
table { border-collapse: collapse; width: 100%; margin: .8em 0 1.4em;
        background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,.08); border-radius: 6px; overflow: hidden; }
th, td { padding: .55em .85em; border-bottom: 1px solid #eaeef1; text-align: left; }
th { background: #f0f4f8; font-weight: 600; color: #223; }
tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #f7fbfd; }
.badge { display: inline-block; padding: .1em .55em; border-radius: 999px;
         font-size: .82em; font-weight: 600; }
.badge-open { background: #d4edda; color: #155724; }
.badge-closed { background: #f8d7da; color: #721c24; }
.badge-filtered { background: #fff3cd; color: #856404; }
hr { border: none; border-top: 1px solid #ddd; margin: 2em 0 1em; }
</style>"""