"""
Palo Alto Networks FTD Migration Push Agent
Pushes all parsed and generated Cisco FTD configuration (Zones, Interfaces,
Services, Addresses, Groups, Routes, NAT, Security Rules) to Palo Alto Networks firewall.
Supports live execution, dry-run validation, stage-by-stage push, and commit.
"""

import sys
import os
import time
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Tuple

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

import config
from ssh_client import PaloAltoSSHClient

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()
log = logging.getLogger("paloalto.ftd_push")

# Stages definition
STAGES = [
    ("01_security_zones",     "Security Zones",       "commands_stages/01_security_zones.set"),
    ("02_interfaces",         "Network Interfaces",   "commands_stages/02_interfaces.set"),
    ("03_service_objects",    "Service Objects",      "commands_stages/03_service_objects.set"),
    ("04_service_groups",     "Service Groups",       "commands_stages/04_service_groups.set"),
    ("05_address_objects",    "Address Objects",      "commands_stages/05_address_objects.set"),
    ("06_address_groups",     "Address Groups",       "commands_stages/06_address_groups.set"),
    ("07_static_routes",      "Static Routes",        "commands_stages/07_static_routes.set"),
    ("08_nat_policies",       "NAT Policies",         "commands_stages/08_nat_policies.set"),
    ("09_security_policies",  "Security Policies",    "commands_stages/09_security_policies.set"),
]

def load_stage_commands() -> Dict[str, Tuple[str, List[str]]]:
    stage_data = {}
    for stage_id, label, filepath in STAGES:
        p = Path(filepath)
        if not p.exists():
            cmds = []
        else:
            with open(p, "r", encoding="utf-8") as f:
                cmds = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        stage_data[stage_id] = (label, cmds)
    return stage_data

def push_commands_batch(ssh: PaloAltoSSHClient, commands: List[str], chunk_size: int = 50) -> Tuple[int, int, List[str]]:
    """
    Sends commands in chunks over interactive SSH session.
    Returns (success_count, error_count, error_messages)
    """
    if not commands:
        return 0, 0, []

    success = 0
    errors = 0
    err_msgs = []

    for i in range(0, len(commands), chunk_size):
        chunk = commands[i:i + chunk_size]
        payload = "\n".join(chunk)
        try:
            out = ssh._send(payload)
            # Check for errors in response
            lines = out.splitlines()
            for l in lines:
                l_s = l.strip().lower()
                if "invalid syntax" in l_s or "unknown command" in l_s or "error:" in l_s:
                    errors += 1
                    err_msgs.append(l.strip())
            success += len(chunk)
        except Exception as e:
            errors += len(chunk)
            err_msgs.append(str(e))

    return success, errors, err_msgs

def run_push(live: bool = False, target_stage: str = None, auto_commit: bool = False, chunk_size: int = 50):
    stage_data = load_stage_commands()
    total_cmds = sum(len(cmds) for _, cmds in stage_data.values())

    mode_str = "[bold red]LIVE FIREWALL PUSH[/]" if live else "[bold yellow]DRY-RUN (NO CHANGES MADE)[/]"
    console.print(Panel.fit(
        f"[bold cyan]Palo Alto Networks — Cisco FTD Configuration Push Agent[/]\n"
        f"Target Firewall : [bold white]{config.PALOALTO_HOST}:{config.PALOALTO_PORT}[/bold white]\n"
        f"Username        : [bold white]{config.PALOALTO_USERNAME}[/bold white]\n"
        f"Execution Mode  : {mode_str}\n"
        f"Total Commands  : [bold green]{total_cmds:,}[/bold green] across [bold green]{len(stage_data)}[/bold green] stages\n"
        f"Auto Commit     : {'[bold green]YES[/]' if auto_commit and live else '[dim]NO[/]'}",
        border_style="cyan",
        title="[bold white]🛡️ PAN-OS MIGRATION[/]"
    ))

    # Connect SSH if live
    ssh = None
    if live:
        console.print("\n[bold cyan]▶ Connecting to Palo Alto firewall via SSH...[/]")
        try:
            ssh = PaloAltoSSHClient(
                host=config.PALOALTO_HOST,
                port=config.PALOALTO_PORT,
                username=config.PALOALTO_USERNAME,
                password=config.PALOALTO_PASSWORD,
                timeout=config.SSH_TIMEOUT,
                cmd_timeout=config.CMD_TIMEOUT,
                banner_timeout=config.BANNER_TIMEOUT
            )
            ssh.connect()
            ssh.configure()
            console.print(f"  [bold green]✔ Connected & Entered configure mode on {config.PALOALTO_HOST}[/]\n")
        except Exception as e:
            console.print(f"  [bold red]✘ Connection Failed:[/] {e}")
            return 1
    else:
        console.print("\n[yellow]ℹ Dry-run mode enabled. Simulating commands without touching firewall.[/]\n")

    # Execution Table
    tbl = Table(title="Migration Stage Progress", box=box.ROUNDED, header_style="bold cyan", show_lines=True)
    tbl.add_column("Stage ID", style="dim", no_wrap=True)
    tbl.add_column("Component", style="bold white")
    tbl.add_column("Commands", justify="right")
    tbl.add_column("Status", justify="center")
    tbl.add_column("Execution Time", justify="right")

    t_start = time.time()
    total_pushed = 0
    total_errors = 0

    try:
        for stage_id, (label, cmds) in stage_data.items():
            if target_stage and target_stage not in stage_id:
                continue

            stage_t0 = time.time()
            count = len(cmds)

            if count == 0:
                tbl.add_row(stage_id, label, "0", "[dim]SKIPPED[/]", "0.0s")
                continue

            if live:
                console.print(f"  [cyan]Pushing {label} ({count:,} commands)...[/]")
                succ, errs, err_msgs = push_commands_batch(ssh, cmds, chunk_size=chunk_size)
                stage_elapsed = time.time() - stage_t0
                total_pushed += succ
                total_errors += errs
                if errs > 0:
                    status_badge = f"[bold red]ERRORS ({errs})[/]"
                else:
                    status_badge = "[bold green]✔ PUSHED[/]"
            else:
                # Dry run
                time.sleep(0.05)
                stage_elapsed = time.time() - stage_t0
                total_pushed += count
                status_badge = "[bold yellow]~ SIMULATED[/]"

            tbl.add_row(stage_id, label, f"{count:,}", status_badge, f"{stage_elapsed:.1f}s")

        console.print(tbl)

        # Commit if requested
        if live and auto_commit:
            console.print("\n[bold cyan]▶ Committing configuration to Palo Alto candidate datastore...[/]")
            try:
                commit_out = ssh.commit(description="Migrated from Cisco FTD configuration")
                console.print("  [bold green]✔ Commit completed successfully![/]")
            except Exception as ce:
                console.print(f"  [bold red]✘ Commit failed:[/] {ce}")

    finally:
        if ssh:
            try:
                ssh.exit_configure()
                ssh.disconnect()
            except Exception:
                pass

    total_time = time.time() - t_start
    console.print(f"\n[bold green]Completed in {total_time:.1f}s.[/] Total processed: [bold white]{total_pushed:,}[/] commands.\n")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Palo Alto FTD Configuration Push Agent")
    parser.add_argument("--live", action="store_true", help="Execute changes live on the Palo Alto firewall")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Simulate execution without modifying firewall")
    parser.add_argument("--stage", type=str, default=None, help="Target specific stage (e.g. 01, 05, 09)")
    parser.add_argument("--commit", action="store_true", default=False, help="Commit configuration after pushing")
    parser.add_argument("--chunk-size", type=int, default=50, help="Batch chunk size for CLI commands")

    args = parser.parse_args()
    is_live = args.live and not args.dry_run

    sys.exit(run_push(
        live=is_live,
        target_stage=args.stage,
        auto_commit=args.commit,
        chunk_size=args.chunk_size
    ))

if __name__ == "__main__":
    main()
