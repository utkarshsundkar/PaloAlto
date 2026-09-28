"""
Security Policy Agent
Dedicated agent for managing, validating, and pushing Palo Alto Networks security policies.
Can read security policies from the predefined Python policy list or from policies.xlsx.
"""

import argparse
import logging
import sys
import time
from typing import Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import config
from cli_builder import CLIBuilder
from excel_reader import ExcelReader, PolicyWorkbook, SecurityPolicy
from excel_writer import ExcelWriter
from policy_pusher import _has_error
from security_policies_list import export_policies_to_excel, get_security_policies
from ssh_client import PaloAltoSSHClient

# ─────────────────────────────────────────────────────────────
# Console & encoding setup for Windows
# ─────────────────────────────────────────────────────────────
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("paloalto.security_agent")
console = Console(highlight=False)


class SecurityPolicyAgent:
    """
    Dedicated agent for deploying Palo Alto Security Policies.
    """

    def __init__(
        self,
        ssh: PaloAltoSSHClient | None = None,
        dry_run: bool = False,
        auto_commit: bool = True,
    ):
        self.ssh = ssh
        self.dry_run = dry_run
        self.auto_commit = auto_commit
        self.builder = CLIBuilder()

    def print_policies_table(self, policies: Sequence[SecurityPolicy], title: str = "Security Policies") -> None:
        """Display a formatted Rich table of policies."""
        tbl = Table(title=title, box=box.ROUNDED, header_style="bold cyan", show_lines=True)
        tbl.add_column("#", style="dim", width=4)
        tbl.add_column("Rule Name", style="bold white")
        tbl.add_column("Src Zone", style="green")
        tbl.add_column("Dst Zone", style="magenta")
        tbl.add_column("Src Addr", style="dim")
        tbl.add_column("Dst Addr", style="dim")
        tbl.add_column("Application", style="yellow")
        tbl.add_column("Service", style="cyan")
        tbl.add_column("Action", style="bold")
        tbl.add_column("Status", no_wrap=True)

        for idx, pol in enumerate(policies, start=1):
            action_styled = f"[bold green]{pol.action.upper()}[/]" if pol.action.lower() == "allow" else f"[bold red]{pol.action.upper()}[/]"
            s = pol.status
            if s == "PUSHED":
                status_styled = "[bold green]OK PUSHED[/]"
            elif s == "FAILED":
                status_styled = "[bold red]FAIL[/]"
            elif s == "DRY-RUN":
                status_styled = "[bold yellow]DRY-RUN[/]"
            else:
                status_styled = f"[dim]{s}[/]"

            tbl.add_row(
                str(idx),
                pol.name,
                pol.srczone,
                pol.dstzone,
                pol.srcaddr,
                pol.dstaddr,
                pol.application,
                pol.service,
                action_styled,
                status_styled,
            )

        console.print(tbl)

    def push_policies(self, policies: list[SecurityPolicy]) -> list[SecurityPolicy]:
        """Push security policy rules via PAN-OS SSH CLI."""
        total = len(policies)
        if total == 0:
            console.print("[yellow]No security policies to push.[/]")
            return policies

        console.print(f"\n[bold]Pushing {total} Security Policies ...[/]\n")

        if not self.dry_run:
            if not self.ssh:
                raise RuntimeError("SSH Client required for live push.")
            self.ssh.configure()

        try:
            for idx, pol in enumerate(policies, start=1):
                name = pol.name
                cmds = self.builder.security_policy(pol)
                console.print(f" [{idx}/{total}] Processing rule: [bold cyan]{name}[/] ({pol.action.upper()})")

                try:
                    for cmd in cmds:
                        if self.dry_run:
                            log.info(f"    [DRY-RUN] {cmd}")
                            continue

                        out = self.ssh.send_cfg_cmd(cmd)
                        err, msg = _has_error(out)
                        if err:
                            raise RuntimeError(f"CLI error: {msg}")

                    pol.status = "DRY-RUN" if self.dry_run else "PUSHED"
                    console.print(f"       [green][OK] Success[/] -> {name}")
                    log.info(f"[OK] Pushed security policy: {name}")

                except Exception as exc:
                    pol.status = "FAILED"
                    pol.error_msg = str(exc)[:300]
                    console.print(f"       [bold red][FAIL] Failed[/] -> {name} ({exc})")
                    log.error(f"[FAIL] Failed security policy {name}: {exc}")

            # Commit changes if in live mode
            if not self.dry_run:
                self.ssh.exit_configure()
                if self.auto_commit:
                    console.print("\n[bold]Committing candidate configuration on firewall ...[/]")
                    commit_out = self.ssh.commit(description="Security Policy Agent Push")
                    log.info(f"Commit output:\n{commit_out.strip()}")
                    console.print("   [green]Commit completed successfully![/]")
            else:
                log.info("[DRY-RUN] Commit skipped.")

        except Exception as exc:
            log.error(f"Error during policy push session: {exc}")
            raise

        return policies


# ─────────────────────────────────────────────────────────────
# Main execution logic
# ─────────────────────────────────────────────────────────────
def run_security_agent(
    source: str = "list",
    dry_run: bool | None = None,
    auto_commit: bool | None = None,
    rule_filter: str | None = None,
    export_to_excel: bool = False,
    display_only: bool = False,
) -> int:
    is_dry_run = config.DRY_RUN if dry_run is None else dry_run
    do_commit = config.AUTO_COMMIT if auto_commit is None else auto_commit

    console.print(Panel.fit(
        "[bold cyan]Palo Alto Security Policy Agent[/]\n"
        f"[dim]Device : [white]{config.PALOALTO_HOST}:{config.PALOALTO_PORT}[/white]\n"
        f"vsys   : [white]{config.VSYS}[/white]\n"
        f"Source : [white]{source.upper()}[/white]  |  "
        f"Mode   : {'[bold yellow]DRY-RUN[/]' if is_dry_run else '[bold green]LIVE PUSH[/]'}  |  "
        f"Commit : {'[green]YES[/]' if do_commit else '[yellow]NO[/]'}[/]",
        border_style="cyan",
        title="[bold white]Security Policy Agent[/]",
    ))

    # Optional Excel export
    if export_to_excel:
        count = export_policies_to_excel(config.EXCEL_FILE)
        console.print(f"[green]Successfully exported {count} predefined security policies to {config.EXCEL_FILE}[/]\n")

    # Load policies according to selected source
    if source == "excel":
        console.print(f"Reading security policies from [white]{config.EXCEL_FILE}[/] ...")
        try:
            reader = ExcelReader(config.EXCEL_FILE)
            policies = reader._read_security_policies()
        except Exception as exc:
            console.print(f"[bold red]Failed reading Excel file: {exc}[/]")
            return 1
    else:
        console.print("Loading predefined security policies from [white]security_policies_list.py[/] ...")
        policies = get_security_policies()

    # Filter if requested
    if rule_filter:
        pattern = rule_filter.lower()
        policies = [p for p in policies if pattern in p.name.lower() or pattern in p.description.lower() or pattern in p.tag.lower()]
        console.print(f"Filtered down to [cyan]{len(policies)}[/] policies matching '{rule_filter}'.")

    agent = SecurityPolicyAgent(dry_run=is_dry_run, auto_commit=do_commit)

    # Just display policies if requested
    if display_only:
        agent.print_policies_table(policies, title=f"Security Policies ({source.upper()})")
        return 0

    if not policies:
        console.print("[yellow]No policies available to push.[/]")
        return 0

    # Show initial table
    agent.print_policies_table(policies, title="Target Policies to Push")

    # Connect SSH if live
    ssh = None
    if not is_dry_run:
        console.print(f"\nConnecting to firewall [bold white]{config.PALOALTO_HOST}[/] ...")
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
            console.print("   [green]Connected successfully.[/]")
            agent.ssh = ssh
        except Exception as exc:
            console.print(f"[bold red]SSH Connection failed: {exc}[/]")
            return 1

    # Push policies
    try:
        updated_policies = agent.push_policies(policies)
    finally:
        if ssh:
            ssh.disconnect()

    # If reading from Excel or updated, write results back
    if source == "excel" or export_to_excel:
        try:
            pwb = PolicyWorkbook(security_policies=updated_policies)
            ExcelWriter(config.EXCEL_FILE).write_results(pwb)
            console.print(f"   Results updated in [white]{config.EXCEL_FILE}[/]")
        except Exception as exc:
            console.print(f"[yellow]Note: Could not update Excel status: {exc}[/]")

    # Print final summary table
    console.print("\n")
    agent.print_policies_table(updated_policies, title="Security Policy Push Results")

    pushed_count = sum(1 for p in updated_policies if p.status == "PUSHED")
    failed_count = sum(1 for p in updated_policies if p.status == "FAILED")
    dry_count = sum(1 for p in updated_policies if p.status == "DRY-RUN")

    if is_dry_run:
        console.print(f"\n[yellow]DRY-RUN COMPLETE:[/] {dry_count}/{len(updated_policies)} policies simulated.")
    else:
        console.print(f"\n[bold]Push Complete:[/] [green]{pushed_count} Pushed[/] | [red]{failed_count} Failed[/] | Total: {len(updated_policies)}")

    return 1 if failed_count > 0 else 0


def main():
    parser = argparse.ArgumentParser(description="Palo Alto Security Policy Agent")
    parser.add_argument(
        "--source",
        choices=["list", "excel"],
        default="list",
        help="Source of policies: 'list' (security_policies_list.py) or 'excel' (policies.xlsx)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=None,
        help="Run without pushing commands to the firewall",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Enforce live execution (overrides DRY_RUN in config.py)",
    )
    parser.add_argument(
        "--no-commit",
        action="store_true",
        help="Do not auto-commit changes after pushing",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Filter security policies by name, description, or tag",
    )
    parser.add_argument(
        "--export-excel",
        action="store_true",
        help="Export predefined policy list into policies.xlsx before pushing",
    )
    parser.add_argument(
        "--list",
        dest="display_only",
        action="store_true",
        help="Display the policies table and exit without connecting",
    )

    args = parser.parse_args()

    dry_run = None
    if args.dry_run:
        dry_run = True
    elif args.live:
        dry_run = False

    auto_commit = False if args.no_commit else None

    exit_code = run_security_agent(
        source=args.source,
        dry_run=dry_run,
        auto_commit=auto_commit,
        rule_filter=args.filter,
        export_to_excel=args.export_excel,
        display_only=args.display_only,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
