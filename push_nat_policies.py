"""
Palo Alto Networks NAT Policy Pusher
Configures comprehensive outbound and inbound NAT policies matching
the configured zones (Inside_zone, Outside_zone, DMZ_zone, VPN_zone, Guest_zone).
"""

import sys
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import openpyxl

import config
from ssh_client import PaloAltoSSHClient
from cli_builder import CLIBuilder
from excel_reader import NATPolicy
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
log = logging.getLogger("paloalto.nat")

# Enterprise NAT policies tailored to the environment
NAT_POLICIES = [
    NATPolicy(
        row_index=2,
        name="Inside-Internet-PAT",
        srczone="Inside_zone",
        dstzone="Outside_zone",
        srcaddr="10.10.10.0/24, 10.10.20.0/24, 10.10.30.0/24, 10.10.50.0/24",
        dstaddr="any",
        service="any",
        nat_type="ipv4",
        snat_type="dynamic-ip-and-port",
        snat_interface="",
        snat_ip="203.0.113.10",
        dnat_address="",
        dnat_port="",
        description="Outbound PAT for internal enterprise subnets to Internet",
        tag="FPR2140-MUM-1",
    ),
    NATPolicy(
        row_index=3,
        name="Guest-Internet-PAT",
        srczone="Guest_zone",
        dstzone="Outside_zone",
        srcaddr="10.99.0.0/24",
        dstaddr="any",
        service="any",
        nat_type="ipv4",
        snat_type="dynamic-ip-and-port",
        snat_interface="",
        snat_ip="203.0.113.11",
        dnat_address="",
        dnat_port="",
        description="Outbound PAT for isolated guest Wi-Fi network",
        tag="FPR2140-MUM-1",
    ),
    NATPolicy(
        row_index=4,
        name="VPN-Outbound-PAT",
        srczone="VPN_zone",
        dstzone="Outside_zone",
        srcaddr="10.10.40.0/24",
        dstaddr="any",
        service="any",
        nat_type="ipv4",
        snat_type="dynamic-ip-and-port",
        snat_interface="",
        snat_ip="203.0.113.12",
        dnat_address="",
        dnat_port="",
        description="Outbound PAT for remote VPN client egress traffic",
        tag="FPR2140-MUM-1",
    ),
    NATPolicy(
        row_index=5,
        name="DMZ-Web-Server-DNAT",
        srczone="Outside_zone",
        dstzone="Outside_zone",
        srcaddr="any",
        dstaddr="203.0.113.20",
        service="service-https",
        nat_type="ipv4",
        snat_type="none",
        snat_interface="",
        snat_ip="",
        dnat_address="10.20.20.10",
        dnat_port="443",
        description="Inbound HTTPS DNAT port forwarding for DMZ web server",
        tag="FPR2140-MUM-1",
    ),
    NATPolicy(
        row_index=6,
        name="DMZ-Mail-Server-DNAT",
        srczone="Outside_zone",
        dstzone="Outside_zone",
        srcaddr="any",
        dstaddr="203.0.113.25",
        service="any",
        nat_type="ipv4",
        snat_type="none",
        snat_interface="",
        snat_ip="",
        dnat_address="10.20.20.30",
        dnat_port="",
        description="Inbound 1-to-1 DNAT forwarding for DMZ mail server",
        tag="FPR2140-MUM-1",
    ),
]


def sync_nat_to_excel(excel_path: str = config.EXCEL_FILE) -> None:
    """Updates policies.xlsx NAT_Policies sheet with current NAT policies."""
    try:
        wb = openpyxl.load_workbook(excel_path)
        sheet_name = getattr(config, "SHEET_NAT_POLICIES", "NAT_Policies")
        if sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            if ws.max_row > 1:
                ws.delete_rows(2, ws.max_row - 1)
        else:
            ws = wb.create_sheet(sheet_name)

        for row_idx, nat in enumerate(NAT_POLICIES, start=2):
            row_data = [
                nat.name,
                nat.srczone,
                nat.dstzone,
                nat.srcaddr,
                nat.dstaddr,
                nat.service,
                nat.nat_type,
                nat.snat_type,
                nat.snat_interface,
                nat.snat_ip,
                nat.dnat_address,
                nat.dnat_port,
                nat.description,
                nat.tag,
                "PUSHED",
                "",
            ]
            for col_idx, val in enumerate(row_data, start=1):
                ws.cell(row=row_idx, column=col_idx, value=val)

        wb.save(excel_path)
        console.print(f"[dim]Synced {len(NAT_POLICIES)} NAT policies into {excel_path}[/]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not update Excel NAT sheet: {e}[/]")


def push_nat_policies() -> int:
    console.print(Panel.fit(
        "[bold cyan]Palo Alto NAT Policy Configuration[/]\n"
        f"[dim]Target Firewall : [white]{config.PALOALTO_HOST}:{config.PALOALTO_PORT}[/white]\n"
        f"NAT Rules Count : [white]{len(NAT_POLICIES)}[/white][/]",
        border_style="cyan",
        title="[bold white]NAT Configuration[/]",
    ))

    # Display plan table
    tbl = Table(title="Target NAT Policies", box=box.ROUNDED, header_style="bold cyan", show_lines=True)
    tbl.add_column("#", style="dim", width=4)
    tbl.add_column("Rule Name", style="bold white")
    tbl.add_column("Type", style="yellow")
    tbl.add_column("Src Zone", style="green")
    tbl.add_column("Dst Zone", style="magenta")
    tbl.add_column("Translation", style="cyan")
    tbl.add_column("Status", no_wrap=True)

    for idx, nat in enumerate(NAT_POLICIES, start=1):
        trans = f"SNAT -> {nat.snat_ip}" if nat.snat_ip else f"DNAT -> {nat.dnat_address}:{nat.dnat_port or 'same'}"
        nat_type_str = "Outbound SNAT/PAT" if nat.snat_ip else "Inbound DNAT"
        tbl.add_row(str(idx), nat.name, nat_type_str, nat.srczone, nat.dstzone, trans, "[yellow]PENDING[/]")

    console.print(tbl)

    builder = CLIBuilder()

    console.print(f"\nConnecting to firewall [bold white]{config.PALOALTO_HOST}[/] ...")
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

    ssh.configure()
    del_base = f"delete vsys {config.VSYS}" if getattr(config, "USE_VSYS_PREFIX", False) else "delete"

    results = []
    try:
        console.print(f"\n[bold]Pushing {len(NAT_POLICIES)} NAT Policies ...[/]\n")
        for idx, nat in enumerate(NAT_POLICIES, start=1):
            name = nat.name
            console.print(f" [{idx}/{len(NAT_POLICIES)}] Processing NAT Rule: [bold cyan]{name}[/]")
            
            # Reset existing rule so clean settings apply
            ssh.send_cfg_cmd(f'{del_base} rulebase nat rules "{name}"')

            cmds = builder.nat_policy(nat)
            failed = False
            for cmd in cmds:
                out = ssh.send_cfg_cmd(cmd)
                err, msg = _has_error(out)
                if err:
                    console.print(f"       [bold red][FAIL][/] {msg}")
                    nat.status = "FAILED"
                    nat.error_msg = msg
                    failed = True
                    break

            if not failed:
                nat.status = "PUSHED"
                console.print(f"       [green][OK] Success[/] -> {name}")
            results.append(nat)

        console.print("\n[bold]Committing NAT configuration on firewall ...[/]")
        commit_out = ssh.commit(description="Configured enterprise NAT policies")
        console.print("   [green]Commit completed successfully![/]")

    finally:
        ssh.disconnect()

    # Sync to Excel
    sync_nat_to_excel()

    # Final summary table
    res_tbl = Table(title="NAT Policy Push Results", box=box.ROUNDED, header_style="bold cyan", show_lines=True)
    res_tbl.add_column("#", style="dim", width=4)
    res_tbl.add_column("Rule Name", style="bold white")
    res_tbl.add_column("Src Zone", style="green")
    res_tbl.add_column("Dst Zone", style="magenta")
    res_tbl.add_column("Translation", style="cyan")
    res_tbl.add_column("Status", no_wrap=True)

    for idx, nat in enumerate(results, start=1):
        trans = f"SNAT -> {nat.snat_ip}" if nat.snat_ip else f"DNAT -> {nat.dnat_address}:{nat.dnat_port or 'same'}"
        status_styled = "[bold green]OK PUSHED[/]" if nat.status == "PUSHED" else "[bold red]FAIL[/]"
        res_tbl.add_row(str(idx), nat.name, nat.srczone, nat.dstzone, trans, status_styled)

    console.print("\n")
    console.print(res_tbl)

    pushed_count = sum(1 for n in results if n.status == "PUSHED")
    failed_count = sum(1 for n in results if n.status == "FAILED")
    console.print(f"\n[bold]NAT Push Complete:[/] [green]{pushed_count} Pushed[/] | [red]{failed_count} Failed[/] | Total: {len(results)}\n")

    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(push_nat_policies())
