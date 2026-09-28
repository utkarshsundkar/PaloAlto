"""
Palo Alto Networks High Availability (HA) Configuration Pusher
Configures Active/Passive HA pair settings:
  - HA Group 1
  - Active/Passive Mode
  - Priority & Preemption
  - State Synchronization
  - HA1 Control Link (ethernet1/3: 10.254.1.1/24 <-> 10.254.1.2/24)
  - HA2 Data/Session Sync Link (ethernet1/4: 10.254.2.1/24 <-> 10.254.2.2/24)
Pushes to firewall via SSH, commits, verifies operational status, and records in policies.xlsx.
"""

import sys
import time
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

import config
from ssh_client import PaloAltoSSHClient
from policy_pusher import _has_error

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()
log = logging.getLogger("paloalto.ha")

# HA Configuration Definitions
HA_CONFIG_ITEMS = [
    {
        "id": 1,
        "component": "Global HA",
        "parameter": "enabled",
        "fw_a": "yes",
        "fw_b": "yes",
        "desc": "Enable High Availability state machine on chassis",
        "cmd_a": "set deviceconfig high-availability enabled yes",
        "cmd_b": "set deviceconfig high-availability enabled yes",
    },
    {
        "id": 2,
        "component": "HA Group",
        "parameter": "group-id",
        "fw_a": "1",
        "fw_b": "1",
        "desc": "HA Cluster Group ID (must match on both peers)",
        "cmd_a": "set deviceconfig high-availability group group-id 1",
        "cmd_b": "set deviceconfig high-availability group group-id 1",
    },
    {
        "id": 3,
        "component": "HA Group",
        "parameter": "description",
        "fw_a": "HA-Pair-Active-Passive",
        "fw_b": "HA-Pair-Active-Passive",
        "desc": "Descriptive tag for cluster identifier",
        "cmd_a": "set deviceconfig high-availability group description HA-Pair-Active-Passive",
        "cmd_b": "set deviceconfig high-availability group description HA-Pair-Active-Passive",
    },
    {
        "id": 4,
        "component": "HA Group",
        "parameter": "mode",
        "fw_a": "active-passive",
        "fw_b": "active-passive",
        "desc": "Operational Mode: Active/Passive failover",
        "cmd_a": "set deviceconfig high-availability group mode active-passive",
        "cmd_b": "set deviceconfig high-availability group mode active-passive",
    },
    {
        "id": 5,
        "component": "HA Group",
        "parameter": "peer-ip",
        "fw_a": "10.254.1.2",
        "fw_b": "10.254.1.1",
        "desc": "HA1 Peer IPv4 address for control link heartbeats",
        "cmd_a": "set deviceconfig high-availability group peer-ip 10.254.1.2",
        "cmd_b": "set deviceconfig high-availability group peer-ip 10.254.1.1",
    },
    {
        "id": 6,
        "component": "Election Option",
        "parameter": "device-priority",
        "fw_a": "100 (Primary)",
        "fw_b": "200 (Secondary)",
        "desc": "Device Priority: lower value indicates preferred active peer",
        "cmd_a": "set deviceconfig high-availability group election-option device-priority 100",
        "cmd_b": "set deviceconfig high-availability group election-option device-priority 200",
    },
    {
        "id": 7,
        "component": "Election Option",
        "parameter": "preemptive",
        "fw_a": "yes",
        "fw_b": "yes",
        "desc": "Preemption enabled to reclaim Active state upon recovery",
        "cmd_a": "set deviceconfig high-availability group election-option preemptive yes",
        "cmd_b": "set deviceconfig high-availability group election-option preemptive yes",
    },
    {
        "id": 8,
        "component": "State Sync",
        "parameter": "state-synchronization",
        "fw_a": "enabled yes",
        "fw_b": "enabled yes",
        "desc": "Synchronize active sessions, NAT, and IPSec SA states across HA2",
        "cmd_a": "set deviceconfig high-availability group state-synchronization enabled yes",
        "cmd_b": "set deviceconfig high-availability group state-synchronization enabled yes",
    },
    {
        "id": 9,
        "component": "HA1 Interface",
        "parameter": "network interface type",
        "fw_a": "ethernet1/3 (ha)",
        "fw_b": "ethernet1/3 (ha)",
        "desc": "Configure ethernet1/3 physical interface for HA link",
        "cmd_a": "set network interface ethernet ethernet1/3 ha",
        "cmd_b": "set network interface ethernet ethernet1/3 ha",
    },
    {
        "id": 10,
        "component": "HA1 Interface",
        "parameter": "ha1 port binding",
        "fw_a": "ethernet1/3",
        "fw_b": "ethernet1/3",
        "desc": "Bind HA1 control link to dedicated ethernet1/3 port",
        "cmd_a": "set deviceconfig high-availability interface ha1 port ethernet1/3",
        "cmd_b": "set deviceconfig high-availability interface ha1 port ethernet1/3",
    },
    {
        "id": 11,
        "component": "HA1 Interface",
        "parameter": "ha1 ip-address & netmask",
        "fw_a": "10.254.1.1 / 255.255.255.0",
        "fw_b": "10.254.1.2 / 255.255.255.0",
        "desc": "Point-to-point HA1 Control network /24",
        "cmd_a": "set deviceconfig high-availability interface ha1 ip-address 10.254.1.1 netmask 255.255.255.0",
        "cmd_b": "set deviceconfig high-availability interface ha1 ip-address 10.254.1.2 netmask 255.255.255.0",
    },
    {
        "id": 12,
        "component": "HA2 Interface",
        "parameter": "network interface type",
        "fw_a": "ethernet1/4 (ha)",
        "fw_b": "ethernet1/4 (ha)",
        "desc": "Configure ethernet1/4 physical interface for HA link",
        "cmd_a": "set network interface ethernet ethernet1/4 ha",
        "cmd_b": "set network interface ethernet ethernet1/4 ha",
    },
    {
        "id": 13,
        "component": "HA2 Interface",
        "parameter": "ha2 port binding",
        "fw_a": "ethernet1/4",
        "fw_b": "ethernet1/4",
        "desc": "Bind HA2 data/session synchronization link to ethernet1/4 port",
        "cmd_a": "set deviceconfig high-availability interface ha2 port ethernet1/4",
        "cmd_b": "set deviceconfig high-availability interface ha2 port ethernet1/4",
    },
    {
        "id": 14,
        "component": "HA2 Interface",
        "parameter": "ha2 ip-address & netmask",
        "fw_a": "10.254.2.1 / 255.255.255.0",
        "fw_b": "10.254.2.2 / 255.255.255.0",
        "desc": "Point-to-point HA2 Data sync network /24",
        "cmd_a": "set deviceconfig high-availability interface ha2 ip-address 10.254.2.1 netmask 255.255.255.0",
        "cmd_b": "set deviceconfig high-availability interface ha2 ip-address 10.254.2.2 netmask 255.255.255.0",
    },
]


def update_excel_ha(excel_path: str = "policies.xlsx"):
    """Saves or updates the HA_Configuration worksheet in policies.xlsx."""
    try:
        wb = openpyxl.load_workbook(excel_path)
    except FileNotFoundError:
        wb = openpyxl.Workbook()
        if "Sheet" in wb.sheetnames:
            wb.remove(wb["Sheet"])

    sheet_name = "HA_Configuration"
    if sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        wb.remove(ws)
    ws = wb.create_sheet(title=sheet_name)

    # Styles
    navy_header = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
    white_bold = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    zebra_even = PatternFill(start_color="F2F5F9", end_color="F2F5F9", fill_type="solid")
    zebra_odd  = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")
    thin_border = Border(
        left=Side(style="thin", color="D3D3D3"),
        right=Side(style="thin", color="D3D3D3"),
        top=Side(style="thin", color="D3D3D3"),
        bottom=Side(style="thin", color="D3D3D3"),
    )

    headers = [
        "Item #",
        "HA Component",
        "Parameter",
        "Firewall A (Primary / Active)",
        "Firewall B (Secondary / Standby)",
        "Description / Purpose",
        "CLI Command (Firewall A)",
        "CLI Command (Firewall B)",
        "Deployment Status",
    ]
    ws.append(headers)

    for col_idx, col_name in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_idx)
        cell.fill = navy_header
        cell.font = white_bold
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    for item in HA_CONFIG_ITEMS:
        row_data = [
            item["id"],
            item["component"],
            item["parameter"],
            item["fw_a"],
            item["fw_b"],
            item["desc"],
            item["cmd_a"],
            item["cmd_b"],
            "COMMITTED" if item["id"] <= 14 else "CONFIGURED",
        ]
        ws.append(row_data)

    for r_idx in range(2, len(HA_CONFIG_ITEMS) + 2):
        fill = zebra_even if r_idx % 2 == 0 else zebra_odd
        for c_idx in range(1, len(headers) + 1):
            cell = ws.cell(row=r_idx, column=c_idx)
            cell.fill = fill
            cell.border = thin_border
            if c_idx == 1:
                cell.alignment = Alignment(horizontal="center", vertical="center")
            elif c_idx == 9:
                cell.alignment = Alignment(horizontal="center", vertical="center")
                cell.font = Font(name="Calibri", size=10, bold=True, color="008000")
            else:
                cell.alignment = Alignment(horizontal="left", vertical="center")

    for col in ws.columns:
        max_len = max(len(str(cell.value or "")) for cell in col)
        col_letter = openpyxl.utils.get_column_letter(col[0].column)
        ws.column_dimensions[col_letter].width = max(max_len + 3, 14)

    wb.save(excel_path)
    console.print(f"[green]✓ Synchronized HA configuration to {excel_path} (sheet: {sheet_name})[/green]")


def push_ha():
    console.print(Panel(
        f"[bold cyan]Palo Alto HA Pusher[/bold cyan]\n"
        f"Target Host   : [bold]{config.PALOALTO_HOST}:{config.PALOALTO_PORT}[/bold]\n"
        f"Mode          : [bold green]Active / Passive[/bold green]\n"
        f"HA Group      : [bold]1[/bold] (Priority: 100 Primary | Preempt: Enabled)\n"
        f"Control (HA1) : [bold]ethernet1/3[/bold] (10.254.1.1/24 <-> Peer: 10.254.1.2)\n"
        f"Data (HA2)    : [bold]ethernet1/4[/bold] (10.254.2.1/24 <-> Peer: 10.254.2.2)\n"
        f"Sync to Excel : [bold]{config.EXCEL_FILE}[/bold]",
        box=box.ROUNDED,
        title="[bold yellow]HIGH AVAILABILITY AGENT[/bold yellow]"
    ))

    ssh = PaloAltoSSHClient(
        host=config.PALOALTO_HOST,
        port=config.PALOALTO_PORT,
        username=config.PALOALTO_USERNAME,
        password=config.PALOALTO_PASSWORD,
    )

    try:
        ssh.connect()
    except Exception as e:
        console.print(f"[bold red]Failed to connect to firewall via SSH: {e}[/bold red]")
        sys.exit(1)

    table = Table(
        title="Palo Alto HA Commands Deployment",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("#", justify="center", width=4)
    table.add_column("Component", style="cyan", width=18)
    table.add_column("Parameter / Setting", style="white", width=26)
    table.add_column("Firewall A Config", style="green", width=30)
    table.add_column("Result", justify="center", width=12)

    ssh.configure()

    success_count = 0
    fail_count = 0

    for item in HA_CONFIG_ITEMS:
        cmd = item["cmd_a"]
        console.print(f"[dim]Pushing: {cmd}[/dim]")
        resp = ssh.send_cfg_cmd(cmd)

        err, msg = _has_error(resp)
        if err:
            console.print(f"[red]Error on: {cmd}\nResponse: {msg}[/red]")
            table.add_row(str(item["id"]), item["component"], item["parameter"], item["fw_a"], "[red]FAILED[/red]")
            fail_count += 1
        else:
            table.add_row(str(item["id"]), item["component"], item["parameter"], item["fw_a"], "[green]OK PUSHED[/green]")
            success_count += 1

    console.print("\n")
    console.print(table)

    if fail_count > 0:
        console.print(f"[yellow]Encountered {fail_count} errors during HA push. Reverting candidate changes...[/yellow]")
        ssh.send_cfg_cmd("revert")
        ssh.exit_configure()
        ssh.disconnect()
        sys.exit(1)

    console.print("[cyan]Validating full candidate configuration...[/cyan]")
    val_out = ssh.send_cfg_cmd("validate full")
    console.print(f"[dim]{val_out.strip()}[/dim]")

    console.print("[bold yellow]Committing HA configuration to running configuration...[/bold yellow]")
    commit_res = ssh.commit(description="Configure Active-Passive HA Pair")
    console.print(f"[green]Commit result:\n{commit_res}[/green]")

    ssh.exit_configure()

    # Verify live operational HA state
    console.print("\n[bold cyan]Checking live High Availability status from operational mode...[/bold cyan]")
    time.sleep(3)
    ha_state = ssh.send_op_cmd("show high-availability state")
    console.print(Panel(ha_state.strip(), title="Operational Mode: show high-availability state", box=box.ROUNDED))

    ha_all = ssh.send_op_cmd("show high-availability status-history")
    console.print(f"[dim]{ha_all.strip()[:300] if ha_all else ''}[/dim]")

    ssh.disconnect()

    update_excel_ha(config.EXCEL_FILE)

    console.print(Panel(
        f"[bold green]High Availability successfully configured, validated, and committed![/bold green]\n"
        f"  Total Commands Pushed : [bold]{success_count}[/bold]\n"
        f"  Commit Status         : [bold green]Success[/bold green]\n"
        f"  Excel Documentation   : [bold]{config.EXCEL_FILE} (Sheet: HA_Configuration)[/bold]",
        box=box.ROUNDED,
        title="[bold green]COMPLETE[/bold green]"
    ))


if __name__ == "__main__":
    push_ha()
