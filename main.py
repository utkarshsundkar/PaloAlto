"""
Palo Alto Policy Push Agent — Main Entry Point
Run:  python main.py
Or:   double-click run_agent.bat
"""

import logging
import sys
import time

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich         import box

import config
from excel_reader  import ExcelReader, PolicyWorkbook
from excel_reader  import (AddressObject, ServiceObject,
                            SecurityZone, NATPolicy, SecurityPolicy)
from excel_writer  import ExcelWriter
from ssh_client    import PaloAltoSSHClient
from policy_pusher import PolicyPusher

# ──────────────────────────────────────────────────
#  Logging
# ──────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("paloalto.main")
console = Console()


# ──────────────────────────────────────────────────
#  Summary table
# ──────────────────────────────────────────────────
def _item_type(item) -> str:
    if isinstance(item, AddressObject):  return "[cyan]Address Object[/]"
    if isinstance(item, ServiceObject):  return "[cyan]Service Object[/]"
    if isinstance(item, SecurityZone):   return "[cyan]Security Zone[/]"
    if isinstance(item, NATPolicy):      return "[cyan]NAT Policy[/]"
    if isinstance(item, SecurityPolicy): return "[cyan]Security Policy[/]"
    return "?"


def _print_summary(pwb: PolicyWorkbook) -> None:
    all_items = (
        pwb.address_objects + pwb.service_objects +
        pwb.security_zones  + pwb.nat_policies    +
        pwb.security_policies
    )

    tbl = Table(title="Push Results", box=box.ROUNDED,
                header_style="bold cyan", show_lines=True)
    tbl.add_column("Type",    no_wrap=True)
    tbl.add_column("Name",    style="white")
    tbl.add_column("Status",  no_wrap=True)
    tbl.add_column("Detail",  style="dim", overflow="fold")

    for item in all_items:
        s = item.status
        if   s == "PUSHED":  badge = "[bold green]✔ PUSHED[/]"
        elif s == "FAILED":  badge = "[bold red]✘ FAILED[/]"
        elif s == "DRY-RUN": badge = "[bold yellow]~ DRY-RUN[/]"
        else:                badge = f"[dim]{s}[/]"
        tbl.add_row(_item_type(item), item.name, badge, item.error_msg or "")

    console.print(tbl)

    total   = len(all_items)
    pushed  = sum(1 for i in all_items if i.status == "PUSHED")
    failed  = sum(1 for i in all_items if i.status == "FAILED")
    dry     = sum(1 for i in all_items if i.status == "DRY-RUN")

    if config.DRY_RUN:
        console.print(f"\n[yellow]DRY-RUN:[/] {dry}/{total} items would be pushed.\n")
    else:
        console.print(
            f"\n[green]Pushed:[/] {pushed}  |  "
            f"[red]Failed:[/] {failed}  |  "
            f"[white]Total:[/] {total}\n"
        )


# ──────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────
def main() -> int:
    t0 = time.time()

    console.print(Panel.fit(
        "[bold bright_orange]Palo Alto Policy Push Agent[/]\n"
        f"[dim]Target : [white]{config.PALOALTO_HOST}:{config.PALOALTO_PORT}[/white]\n"
        f"vsys   : [white]{config.VSYS}[/white]\n"
        f"File   : [white]{config.EXCEL_FILE}[/white]\n"
        f"Mode   : {'[yellow]DRY-RUN[/]' if config.DRY_RUN else '[green]LIVE[/]'}  |  "
        f"Auto-commit: {'[green]YES[/]' if config.AUTO_COMMIT else '[yellow]NO[/]'}[/]",
        border_style="bright_orange",
        title="[bold white]🔥 PA Agent[/]",
    ))

    # ── Step 1: Read Excel ──────────────────────────────
    console.print("\n[bold]1/4[/] Reading workbook …")
    try:
        pwb = ExcelReader(config.EXCEL_FILE).read_all()
    except FileNotFoundError as e:
        console.print(f"[bold red]ERROR:[/] {e}")
        return 1

    total = (len(pwb.address_objects) + len(pwb.service_objects) +
             len(pwb.security_zones)  + len(pwb.nat_policies)    +
             len(pwb.security_policies))

    console.print(
        f"   [green]{total}[/] items loaded from [white]{config.EXCEL_FILE}[/]  "
        f"([white]{len(pwb.address_objects)}[/] addr · "
        f"[white]{len(pwb.service_objects)}[/] svc · "
        f"[white]{len(pwb.security_zones)}[/] zones · "
        f"[white]{len(pwb.nat_policies)}[/] NAT · "
        f"[white]{len(pwb.security_policies)}[/] policies)"
    )

    if total == 0:
        console.print("[yellow]Nothing to push. Exiting.[/]")
        return 0

    # ── Step 2: SSH Connect ─────────────────────────────
    console.print("\n[bold]2/4[/] Connecting to Palo Alto …")
    ssh = None
    if not config.DRY_RUN:
        try:
            ssh = PaloAltoSSHClient(
                host=config.PALOALTO_HOST,
                port=config.PALOALTO_PORT,
                username=config.PALOALTO_USERNAME,
                password=config.PALOALTO_PASSWORD,
                timeout=config.SSH_TIMEOUT,
                cmd_timeout=config.CMD_TIMEOUT,
                banner_timeout=config.BANNER_TIMEOUT,
            )
            ssh.connect()
            console.print(f"   [green]Connected[/] to {config.PALOALTO_HOST}")
        except Exception as exc:
            console.print(f"[bold red]SSH failed:[/] {exc}")
            log.error(f"SSH connection failed: {exc}")
            return 1
    else:
        console.print("   [yellow]DRY-RUN — SSH skipped[/]")

    # ── Step 3: Push ─────────────────────────────────────
    console.print("\n[bold]3/4[/] Pushing policies …")
    try:
        pusher = PolicyPusher(ssh=ssh, dry_run=config.DRY_RUN)
        pusher.push_all(pwb)
    finally:
        if ssh:
            ssh.disconnect()

    # ── Step 4: Write results ────────────────────────────
    console.print("\n[bold]4/4[/] Writing results to Excel …")
    try:
        ExcelWriter(config.EXCEL_FILE).write_results(pwb)
        console.print(f"   Results saved → [white]{config.EXCEL_FILE}[/]")
    except Exception as exc:
        console.print(f"[bold red]Write failed:[/] {exc}")
        log.error(str(exc))

    elapsed = time.time() - t0
    console.print(f"\n[dim]Done in {elapsed:.1f}s | Log: {config.LOG_FILE}[/]")
    _print_summary(pwb)

    failed = sum(
        1 for i in (pwb.address_objects + pwb.service_objects +
                    pwb.security_zones  + pwb.nat_policies    +
                    pwb.security_policies)
        if i.status == "FAILED"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
