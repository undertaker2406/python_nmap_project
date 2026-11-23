"""Menu chính — wrapper tương tác quanh các module đã có."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from modules import HostDiscovery, PortScanner, Traceroute, NSERunner
from analysis import ScanAnalyzer, ScanHistory, ReportGenerator
from interface.input_handler import InputHandler

console = Console()
ih = InputHandler


class MainMenu:
    def __init__(self):
        self.host_discovery = HostDiscovery()
        self.port_scanner   = PortScanner()
        self.traceroute     = Traceroute()
        self.nse_runner     = NSERunner()
        self.analyzer       = ScanAnalyzer()
        self.history        = ScanHistory()
        self.reporter       = ReportGenerator()

    # ============================================================
    # Loop
    # ============================================================
    def run(self) -> None:
        while True:
            console.clear()
            console.print(self._banner())
            choice = console.input("[bold cyan]Chọn [0-8]: [/bold cyan]").strip()

            actions = {
                "1": self.menu_host_discovery,
                "2": self.menu_port_scanning,
                "3": self.menu_traceroute,
                "4": self.menu_nse,
                "5": self.menu_analysis,
                "6": self.menu_history,
                "7": self.menu_report,
                "8": self.menu_os_detection,
                "0": self.menu_exit,
            }
            fn = actions.get(choice)
            if fn is None:
                console.print("[red]Lựa chọn không hợp lệ.[/red]")
                console.input("[dim]Enter để tiếp tục...[/dim]")
                continue
            try:
                if fn() == "EXIT":
                    break
            except KeyboardInterrupt:
                console.print("\n[yellow]Đã huỷ thao tác.[/yellow]")
            except Exception as e:
                console.print(f"[red]Lỗi: {e}[/red]")
            console.input("\n[dim]Enter để quay lại menu...[/dim]")

    @staticmethod
    def _banner() -> Panel:
        content = (
            "[bold]1.[/bold] Host Discovery       "
            "[bold]2.[/bold] Port Scanning\n"
            "[bold]3.[/bold] Traceroute           "
            "[bold]4.[/bold] Nmap NSE\n"
            "[bold]5.[/bold] Scan Analysis        "
            "[bold]6.[/bold] Scan History\n"
            "[bold]7.[/bold] Generate Report      "
            "[bold]8.[/bold] OS Detection\n"
            "[bold]0.[/bold] Thoát"
        )
        return Panel(content, title="[bold cyan]NetRecon[/bold cyan]",
                     border_style="cyan", expand=False)

    # ============================================================
    # 1. Host Discovery
    # ============================================================
    def menu_host_discovery(self):
        subnet = ih.ask_subnet()
        os_detect = ih.ask_yes_no("Chạy OS detection cho host tìm được?", True)
        console.print(f"\n[cyan]Đang quét {subnet}...[/cyan]\n")

        hosts = self.host_discovery.discover(subnet=subnet,
                                             run_os_detection=os_detect)
        if not hosts:
            console.print("[yellow]Không tìm thấy host nào.[/yellow]")
            return

        table = Table(title=f"Host Discovery — {len(hosts)} host(s)",
                      show_lines=False)
        for col in ("IP", "Hostname", "MAC", "Vendor", "OS"):
            table.add_column(col)
        for h in hosts:
            os_info = h.get("os") or {}
            os_str = f"{os_info.get('os_family') or ''} {os_info.get('os_accuracy') or ''}".strip() or "—"
            table.add_row(h["ip"], h["hostname"] or "—",
                          h["mac"] or "—", h["vendor"] or "—", os_str)
        console.print(table)
        console.print(f"[green]✔ Đã ghi {len(hosts)} host vào DB + data/targets.txt[/green]")

    # ============================================================
    # 2. Port Scanning
    # ============================================================
    def menu_port_scanning(self):
        targets = ih.ask_targets()
        profile = ih.ask_scan_profile()
        custom_args = ""
        custom_ports = ""

        if profile == "custom":
            custom_args = ih.ask_custom_args()
            custom_ports = ih.ask_ports(skip_allowed=True)

        console.print(f"\n[cyan]Đang scan {len(targets)} target(s) "
                      f"với profile '{profile}'...[/cyan]\n")

        result = self.port_scanner.scan(
            targets, profile=profile,
            custom_args=custom_args, custom_ports=custom_ports,
        )
        self._print_port_result(result)

    def _print_port_result(self, result: dict) -> None:
        for target, info in result["targets"].items():
            if "error" in info:
                console.print(f"[red]{target}: {info['error']}[/red]")
                continue
            ports = info.get("ports", [])
            open_ports = [p for p in ports if p["state"] == "open"]

            table = Table(title=f"{target} — {len(open_ports)} open / {len(ports)} total")
            for col in ("Port", "Proto", "State", "Service", "Version"):
                table.add_column(col)
            for p in ports:
                style = "green" if p["state"] == "open" else "dim"
                ver = " ".join(filter(None, [p["product"], p["version"]])) or "—"
                table.add_row(
                    f"[{style}]{p['port']}[/{style}]",
                    p["protocol"], p["state"],
                    p["service"] or "—", ver,
                )
            console.print(table)

        console.print(f"\n[green]✔ Tổng {result['total_open']} open port(s) "
                      f"trên {result['scanned']} target(s)[/green]")

    # ============================================================
    # 3. Traceroute
    # ============================================================
    def menu_traceroute(self):
        targets = ih.ask_targets()
        port = ih.ask_int("Port cho probe", default=80, lo=1, hi=65535)
        console.print(f"\n[cyan]Traceroute tới {len(targets)} target...[/cyan]\n")

        result = self.traceroute.run(targets, port=port)
        for target, info in result.items():
            if "error" in info:
                console.print(f"[red]{target}: {info['error']}[/red]")
                continue
            table = Table(title=f"Traceroute — {target}")
            for col in ("Hop", "IP", "Hostname", "RTT (ms)"):
                table.add_column(col)
            for h in info["hops"]:
                table.add_row(str(h["hop_number"]), h["hop_ip"] or "*",
                              h["hop_hostname"] or "—",
                              f"{h['rtt']:.2f}" if h["rtt"] else "—")
            console.print(table)

    # ============================================================
    # 4. Nmap NSE
    # ============================================================
    def menu_nse(self):
        targets = ih.ask_targets()
        scripts = ih.ask_nse_scripts()
        ports   = ih.ask_ports(skip_allowed=True)
        extra   = ""
        if ih.ask_yes_no("Thêm -sV để script lấy version?", True):
            extra = "-sV"

        console.print(f"\n[cyan]Chạy NSE '{scripts}' trên {len(targets)} target...[/cyan]\n")
        result = self.nse_runner.run(targets, scripts=scripts,
                                     ports=ports, extra_args=extra)

        for target, info in result.items():
            if "error" in info:
                console.print(f"[red]{target}: {info['error']}[/red]")
                continue
            table = Table(title=f"NSE — {target} — {len(info['results'])} result(s)")
            for col in ("Port", "Script", "Output"):
                table.add_column(col, overflow="fold")
            for r in info["results"]:
                table.add_row(
                    str(r["port"]) if r["port"] else "host",
                    r["script"],
                    (r["output"] or "")[:200],
                )
            console.print(table)

    # ============================================================
    # 5. Scan Analysis
    # ============================================================
    def menu_analysis(self):
        console.print("[bold]a.[/bold] Phân tích 1 scan  "
                      "[bold]b.[/bold] Thống kê tổng quan  "
                      "[bold]c.[/bold] Thống kê 1 target")
        ch = console.input("[cyan]Chọn [a/b/c]: [/cyan]").strip().lower()

        if ch == "a":
            scan_id = ih.ask_scan_id()
            try:
                detail = self.analyzer.analyze_scan(scan_id)
            except ValueError as e:
                console.print(f"[red]{e}[/red]")
                return
            self._render_scan_detail(detail)
        elif ch == "b":
            summary = self.analyzer.summarize()
            self._render_summary(summary, "Toàn DB")
        elif ch == "c":
            from database import targets_repo
            targets = targets_repo.list_all()
            if not targets:
                console.print("[yellow]DB chưa có target nào.[/yellow]")
                return
            self._print_targets(targets)
            tid = ih.ask_int("Chọn target_id", lo=1)
            summary = self.analyzer.summarize(target_id=tid)
            self._render_summary(summary, f"Target id={tid}")
        else:
            console.print("[red]Lựa chọn không hợp lệ.[/red]")

    def _render_summary(self, s: dict, scope_label: str) -> None:
        t1 = Table(title=f"Targets — {scope_label}")
        t1.add_column("Chỉ số"); t1.add_column("Giá trị")
        t1.add_row("Tổng", str(s["targets"]["total"]))
        for k, v in s["targets"]["by_status"].items():
            t1.add_row(f"  {k}", str(v))
        console.print(t1)

        t2 = Table(title="Scans")
        t2.add_column("Chỉ số"); t2.add_column("Giá trị")
        t2.add_row("Tổng", str(s["scans"]["total"]))
        for k, v in s["scans"]["by_type"].items():
            t2.add_row(f"  type={k}", str(v))
        for k, v in s["scans"]["by_status"].items():
            t2.add_row(f"  status={k}", str(v))
        console.print(t2)

        t3 = Table(title="Ports open")
        t3.add_column("Chỉ số"); t3.add_column("Giá trị")
        t3.add_row("Tổng open", str(s["ports"]["total_open"]))
        for k, v in s["ports"]["by_protocol"].items():
            t3.add_row(f"  {k}", str(v))
        console.print(t3)

        if s["ports"]["top_ports"]:
            t4 = Table(title="Top ports")
            t4.add_column("Port"); t4.add_column("Số lần mở")
            for p in s["ports"]["top_ports"]:
                t4.add_row(str(p["port"]), str(p["count"]))
            console.print(t4)

        if s["ports"]["top_services"]:
            t5 = Table(title="Top services")
            t5.add_column("Service"); t5.add_column("Số lần")
            for x in s["ports"]["top_services"]:
                t5.add_row(x["service"], str(x["count"]))
            console.print(t5)

        if s["os_distribution"]:
            t6 = Table(title="OS Distribution")
            t6.add_column("OS Family"); t6.add_column("Số target")
            for k, v in s["os_distribution"].items():
                t6.add_row(k, str(v))
            console.print(t6)

    def _render_scan_detail(self, d: dict) -> None:
        s = d["scan"]
        console.print(Panel(
            f"Target: [cyan]{s['target_ip']}[/cyan]  "
            f"Type: [bold]{s['scan_type']}[/bold]  "
            f"Status: [bold]{s['status']}[/bold]\n"
            f"Started: {s['started_at']}   Finished: {s['finished_at'] or '—'}",
            title=f"Scan #{s['scan_id']}",
        ))
        sm = d["summary"]
        console.print(f"Summary: total={sm['total']}  "
                      f"[green]open={sm['open']}[/green]  "
                      f"closed={sm['closed']}  filtered={sm['filtered']}")

        if d["services"]:
            table = Table(title="Services (open)")
            for col in ("Port", "Proto", "Service", "Product", "Version"):
                table.add_column(col)
            for p in d["services"]:
                table.add_row(
                    str(p["port"]), p["protocol"],
                    p["service"] or "—", p["product"] or "—", p["version"] or "—",
                )
            console.print(table)

    @staticmethod
    def _print_targets(targets) -> None:
        table = Table(title="Targets trong DB")
        for col in ("ID", "IP", "Hostname", "Status", "OS"):
            table.add_column(col)
        for t in targets:
            table.add_row(str(t.id), t.ip, t.hostname or "—",
                          t.status or "—", t.os_family or "—")
        console.print(table)

    # ============================================================
    # 6. Scan History
    # ============================================================
    def menu_history(self):
        console.print("[bold]a.[/bold] Liệt kê gần đây  "
                      "[bold]b.[/bold] Lọc theo target  "
                      "[bold]c.[/bold] Lọc theo loại  "
                      "[bold]d.[/bold] Xoá 1 scan")
        ch = console.input("[cyan]Chọn [a/b/c/d]: [/cyan]").strip().lower()

        if ch == "a":
            limit = ih.ask_int("Số record", default=20, lo=1, hi=500)
            rows = self.history.list_scans(limit=limit)
        elif ch == "b":
            ip = ih.ask_target()
            rows = self.history.list_scans(target_ip=ip, limit=50)
        elif ch == "c":
            stype = ih.ask("Scan type (quick/standard/full_tcp/udp/custom/nse/traceroute)")
            rows = self.history.list_scans(scan_type=stype, limit=50)
        elif ch == "d":
            sid = ih.ask_scan_id()
            ok = self.history.delete_scan(sid)
            console.print(f"[{'green' if ok else 'red'}]"
                          f"{'Đã xoá' if ok else 'Không tìm thấy'} scan #{sid}[/]")
            return
        else:
            console.print("[red]Lựa chọn không hợp lệ.[/red]")
            return

        if not rows:
            console.print("[yellow]Không có record nào khớp.[/yellow]")
            return
        self._print_scan_rows(rows)

    @staticmethod
    def _print_scan_rows(rows: list[dict]) -> None:
        table = Table(title=f"Scan History — {len(rows)} record(s)")
        for col in ("ID", "Target", "Type", "Status", "Started", "Finished"):
            table.add_column(col)
        for s in rows:
            table.add_row(
                str(s["scan_id"]), s["target_ip"], s["scan_type"],
                s["status"], s["started_at"] or "—", s["finished_at"] or "—",
            )
        console.print(table)

    # ============================================================
    # 7. Generate Report
    # ============================================================
    def menu_report(self):
        console.print("[bold]a.[/bold] Global  "
                      "[bold]b.[/bold] Theo target  "
                      "[bold]c.[/bold] Theo 1 scan")
        ch = console.input("[cyan]Chọn [a/b/c]: [/cyan]").strip().lower()

        try:
            if ch == "a":
                paths = self.reporter.generate_global()
            elif ch == "b":
                from database import targets_repo
                targets = targets_repo.list_all()
                if not targets:
                    console.print("[yellow]DB chưa có target.[/yellow]")
                    return
                self._print_targets(targets)
                tid = ih.ask_int("Chọn target_id", lo=1)
                paths = self.reporter.generate_for_target(tid)
            elif ch == "c":
                sid = ih.ask_scan_id()
                paths = self.reporter.generate_for_scan(sid)
            else:
                console.print("[red]Lựa chọn không hợp lệ.[/red]")
                return
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            return

        console.print("\n[green]✔ Đã tạo báo cáo:[/green]")
        for fmt, p in paths.items():
            console.print(f"  [bold]{fmt:>4}[/bold] → {p}")

    # ============================================================
    # 8. OS Detection
    # ============================================================
    def menu_os_detection(self):
        from modules import OSDetector
        targets = ih.ask_targets()
        console.print(f"\n[cyan]OS detection cho {len(targets)} target...[/cyan]\n")
        result = OSDetector().detect(targets)

        table = Table(title="OS Detection")
        for col in ("Target", "Status", "OS family", "OS match"):
            table.add_column(col)
        from database import targets_repo
        for t in targets:
            res = result.get(t, {})
            tgt = targets_repo.get_by_ip(t)
            status = "error" if "error" in res else "ok"
            table.add_row(
                t, status,
                (tgt.os_family if tgt else None) or "—",
                (tgt.os_match if tgt else None) or "—",
            )
        console.print(table)

    # ============================================================
    # 0. Exit
    # ============================================================
    def menu_exit(self):
        if ih.ask_yes_no("Thoát NetRecon?", True):
            console.print("[cyan]Tạm biệt.[/cyan]")
            return "EXIT"
        return None