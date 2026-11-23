"""Nhập liệu an toàn — vòng lặp lại khi sai, không bao giờ raise ra menu."""
from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm

from config import SCAN_PROFILES
from utils.validator import (
    ValidationError, validate_target, validate_targets,
    validate_port_spec, validate_nse_script, validate_scan_profile,
)

console = Console()


class InputHandler:
    # ---- primitives ----
    @staticmethod
    def ask(prompt: str, default: str | None = None, allow_empty: bool = False) -> str:
        while True:
            raw = Prompt.ask(f"[cyan]{prompt}[/cyan]",
                             default=default if default is not None else "")
            s = (raw or "").strip()
            if s or allow_empty:
                return s
            console.print("[red]Không được để trống.[/red]")

    @staticmethod
    def ask_int(prompt: str, default: int | None = None,
                lo: int | None = None, hi: int | None = None) -> int:
        while True:
            try:
                v = IntPrompt.ask(f"[cyan]{prompt}[/cyan]",
                                  default=default if default is not None else "")
                if lo is not None and v < lo:
                    console.print(f"[red]Phải ≥ {lo}[/red]")
                    continue
                if hi is not None and v > hi:
                    console.print(f"[red]Phải ≤ {hi}[/red]")
                    continue
                return v
            except (ValueError, KeyboardInterrupt):
                console.print("[red]Nhập số nguyên hợp lệ.[/red]")

    @staticmethod
    def ask_yes_no(prompt: str, default: bool = False) -> bool:
        return Confirm.ask(f"[cyan]{prompt}[/cyan]", default=default)

    # ---- domain ----
    @staticmethod
    def ask_target() -> str:
        while True:
            try:
                return validate_target(InputHandler.ask("Target (IP / CIDR / hostname)"))
            except ValidationError as e:
                console.print(f"[red]{e}[/red]")

    @staticmethod
    def ask_targets() -> list[str]:
        console.print("[dim]Nhập nhiều target, cách nhau dấu phẩy. "
                      "VD: 192.168.1.1, 192.168.1.10, example.com[/dim]")
        while True:
            raw = InputHandler.ask("Targets (cách nhau bởi dấu phẩy)")
            try:
                parts = [p.strip() for p in raw.split(",") if p.strip()]
                return validate_targets(parts)
            except ValidationError as e:
                console.print(f"[red]{e}[/red]")

    @staticmethod
    def ask_subnet(default: str | None = None) -> str:
        while True:
            try:
                raw = InputHandler.ask(
                    "Subnet cần quét (Enter để tự lấy LAN hiện tại)",
                    default=default or "",
                    allow_empty=True,
                )
                if not raw:
                    from utils.network_utils import get_local_subnet
                    return get_local_subnet()
                return validate_target(raw)
            except ValidationError as e:
                console.print(f"[red]{e}[/red]")

    @staticmethod
    def ask_scan_profile() -> str:
        console.print()
        for key, prof in SCAN_PROFILES.items():
            console.print(f"  [bold]{key:<10}[/bold] {prof['label']:<18} "
                          f"[dim]{prof['args'] or '(tuỳ chỉnh)'}[/dim]")
        console.print()
        while True:
            p = InputHandler.ask("Chọn profile", default="quick").lower()
            try:
                return validate_scan_profile(p)
            except ValidationError as e:
                console.print(f"[red]{e}[/red]")

    @staticmethod
    def ask_ports(skip_allowed: bool = True) -> str:
        while True:
            raw = InputHandler.ask(
                "Ports (VD 22,80,443 hoặc 1-1000; Enter để bỏ qua)",
                allow_empty=skip_allowed,
            )
            if not raw:
                return ""
            try:
                return validate_port_spec(raw)
            except ValidationError as e:
                console.print(f"[red]{e}[/red]")

    @staticmethod
    def ask_nse_scripts() -> str:
        console.print("[dim]VD: http-title, hoặc 'vuln', hoặc 'http-title,ssl-cert'[/dim]")
        while True:
            raw = InputHandler.ask("NSE scripts")
            try:
                parts = [p.strip() for p in raw.split(",") if p.strip()]
                for p in parts:
                    validate_nse_script(p)
                return ",".join(parts)
            except ValidationError as e:
                console.print(f"[red]{e}[/red]")

    @staticmethod
    def ask_custom_args() -> str:
        while True:
            raw = InputHandler.ask("Custom nmap args (VD -sS -sV -T4)")
            if raw:
                return raw
            console.print("[red]Custom scan cần args (hoặc chọn profile khác).[/red]")

    @staticmethod
    def ask_scan_id() -> int:
        return InputHandler.ask_int("Scan ID", lo=1)