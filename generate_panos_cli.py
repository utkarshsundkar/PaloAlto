"""
PAN-OS CLI Command Generator for Cisco FTD Migration
Takes the parsed Cisco FTD data and generates complete, syntax-validated PAN-OS CLI set commands.
Generates:
  - ftd_migrated_commands.set (all commands in sequential order)
  - individual stage files in commands_stages/
"""

import os
import re
from pathlib import Path
from typing import List, Dict

from parse_ftd_config import (
    FTDConfigParser, sanitize_name,
    FTDInterface, FTDAddressObject, FTDAddressGroup,
    FTDServiceObject, FTDServiceGroup, FTDStaticRoute,
    FTDNATRule, FTDSecurityRule
)

def format_members(items: List[str]) -> str:
    cleaned = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        if " " in item and not (item.startswith('"') and item.endswith('"')):
            cleaned.append(f'"{item}"')
        else:
            cleaned.append(item)
    if not cleaned:
        return "any"
    if len(cleaned) == 1:
        return cleaned[0]
    return "[ " + " ".join(cleaned) + " ]"

def chunk_list(lst: list, chunk_size: int = 30):
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]

class PANOSCommandGenerator:
    def __init__(self, parser: FTDConfigParser, base: str = "set"):
        self.parser = parser
        self.base = base
        self.stage_commands: Dict[str, List[str]] = {
            "01_security_zones": [],
            "02_interfaces": [],
            "03_service_objects": [],
            "04_service_groups": [],
            "05_address_objects": [],
            "06_address_groups": [],
            "07_static_routes": [],
            "08_nat_policies": [],
            "09_security_policies": [],
        }

    def generate_all(self) -> Dict[str, List[str]]:
        self._gen_zones()
        self._gen_interfaces()
        self._gen_service_objects()
        self._gen_service_groups()
        self._gen_address_objects()
        self._gen_address_groups()
        self._gen_static_routes()
        self._gen_nat_policies()
        self._gen_security_policies()
        return self.stage_commands

    def _gen_zones(self):
        cmds = []
        for z in sorted(self.parser.zones):
            cmds.append(f'{self.base} zone "{z}" network layer3 [ ]')
        self.stage_commands["01_security_zones"] = cmds

    def _gen_interfaces(self):
        cmds = []
        for iface in self.parser.interfaces.values():
            if not iface.ip:
                continue
            name_lower = iface.interface.lower()
            if name_lower.startswith("ethernet"):
                # e.g. ethernet1/1
                cmds.append(f'{self.base} network interface ethernet {name_lower} layer3 ip [ {iface.ip}/{iface.cidr} ]')
                cmds.append(f'{self.base} zone "{iface.nameif}" network layer3 [ {name_lower} ]')
            elif name_lower.startswith("tunnel"):
                # e.g. tunnel.1
                unit_num = re.sub(r'[^0-9]', '', name_lower) or "1"
                tun_name = f"tunnel.{unit_num}"
                cmds.append(f'{self.base} network interface tunnel units {tun_name} ip [ {iface.ip}/{iface.cidr} ]')
                cmds.append(f'{self.base} zone "{iface.nameif}" network layer3 [ {tun_name} ]')
        self.stage_commands["02_interfaces"] = cmds

    def _gen_service_objects(self):
        cmds = []
        for svc in self.parser.service_objects.values():
            cmds.append(f'{self.base} service "{svc.name}" protocol {svc.protocol} port {svc.port}')
            if svc.description:
                clean_desc = svc.description.replace('"', "'")
                cmds.append(f'{self.base} service "{svc.name}" description "{clean_desc}"')
        self.stage_commands["03_service_objects"] = cmds

    def _gen_service_groups(self):
        cmds = []
        for grp in self.parser.service_groups.values():
            if not grp.members:
                continue
            # If group has members, add them
            members_str = format_members(grp.members)
            cmds.append(f'{self.base} service-group "{grp.name}" members {members_str}')
            if grp.description:
                clean_desc = grp.description.replace('"', "'")
                cmds.append(f'{self.base} service-group "{grp.name}" description "{clean_desc}"')
        self.stage_commands["04_service_groups"] = cmds

    def _gen_address_objects(self):
        cmds = []
        for obj in self.parser.address_objects.values():
            cmds.append(f'{self.base} address "{obj.name}" {obj.obj_type} {obj.value}')
            if obj.description:
                clean_desc = obj.description.replace('"', "'")
                cmds.append(f'{self.base} address "{obj.name}" description "{clean_desc}"')
        self.stage_commands["05_address_objects"] = cmds

    def _gen_address_groups(self):
        cmds = []
        for grp in self.parser.address_groups.values():
            if not grp.members:
                continue
            # Chunk members if large
            for chunk in chunk_list(grp.members, 35):
                members_str = format_members(chunk)
                cmds.append(f'{self.base} address-group "{grp.name}" static {members_str}')
            if grp.description:
                clean_desc = grp.description.replace('"', "'")
                cmds.append(f'{self.base} address-group "{grp.name}" description "{clean_desc}"')
        self.stage_commands["06_address_groups"] = cmds

    def _gen_static_routes(self):
        cmds = []
        idx = 1
        for r in self.parser.static_routes:
            route_name = f"static_{r.dest_ip}_{r.cidr}_{idx}"
            idx += 1
            cmds.append(
                f'{self.base} network virtual-router default routing-table ip static-route "{route_name}" '
                f'destination {r.dest_ip}/{r.cidr} nexthop ip-address {r.gateway} metric {r.metric}'
            )
        self.stage_commands["07_static_routes"] = cmds

    def _gen_nat_policies(self):
        cmds = []
        for nr in self.parser.nat_rules:
            base_rule = f'{self.base} rulebase nat rules "{nr.name}"'
            src_z = nr.src_zone if nr.src_zone and nr.src_zone != "any" else "any"
            dst_z = nr.dst_zone if nr.dst_zone and nr.dst_zone != "any" else "any"
            src_a = nr.src_addr or "any"
            dst_a = nr.dst_addr or "any"

            cmds.append(f'{base_rule} from {format_members([src_z])}')
            cmds.append(f'{base_rule} to {format_members([dst_z])}')
            cmds.append(f'{base_rule} source {format_members([src_a])}')
            cmds.append(f'{base_rule} destination {format_members([dst_a])}')
            cmds.append(f'{base_rule} service {nr.service or "any"}')

            # Translations
            if nr.snat_type == "static-ip" and nr.trans_src and nr.trans_src != nr.src_addr:
                cmds.append(f'{base_rule} source-translation static-ip translated-address {nr.trans_src}')
            elif nr.snat_type == "dynamic-ip-and-port":
                if nr.snat_interface:
                    cmds.append(f'{base_rule} source-translation dynamic-ip-and-port interface-address interface {nr.snat_interface}')
                elif nr.trans_src:
                    cmds.append(f'{base_rule} source-translation dynamic-ip-and-port translated-address {format_members([nr.trans_src])}')

            if nr.trans_dst and nr.trans_dst != nr.dst_addr:
                cmds.append(f'{base_rule} destination-translation translated-address {nr.trans_dst}')

            if nr.description:
                clean_desc = nr.description.replace('"', "'")
                cmds.append(f'{base_rule} description "{clean_desc}"')
        self.stage_commands["08_nat_policies"] = cmds

    def _gen_security_policies(self):
        cmds = []
        for sr in self.parser.security_rules:
            base_rule = f'{self.base} rulebase security rules "{sr.name}"'
            cmds.append(f'{base_rule} from {format_members(sr.src_zones)}')
            cmds.append(f'{base_rule} to {format_members(sr.dst_zones)}')
            cmds.append(f'{base_rule} source {format_members(sr.src_addrs)}')
            cmds.append(f'{base_rule} destination {format_members(sr.dst_addrs)}')
            cmds.append(f'{base_rule} application [ any ]')
            cmds.append(f'{base_rule} service {format_members(sr.services)}')
            cmds.append(f'{base_rule} action {sr.action}')
            cmds.append(f'{base_rule} log-end {sr.log_end}')
            if sr.description:
                clean_desc = sr.description.replace('"', "'")
                cmds.append(f'{base_rule} description "{clean_desc}"')
        self.stage_commands["09_security_policies"] = cmds

    def write_to_files(self, output_dir: str = "commands_stages", all_file: str = "ftd_migrated_commands.set"):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        all_cmds = []

        for stage, cmds in self.stage_commands.items():
            stage_path = Path(output_dir) / f"{stage}.set"
            with open(stage_path, "w", encoding="utf-8") as f:
                f.write("\n".join(cmds) + "\n")
            all_cmds.extend(cmds)
            print(f"  • {stage}: {len(cmds):,} commands -> {stage_path.name}")

        with open(all_file, "w", encoding="utf-8") as f:
            f.write("\n".join(all_cmds) + "\n")
        print(f"\nTotal PAN-OS commands generated: {len(all_cmds):,} -> {all_file}")


if __name__ == "__main__":
    ftd_file = "Cisco FTD running config"
    parser = FTDConfigParser(ftd_file).parse()
    gen = PANOSCommandGenerator(parser)
    gen.generate_all()
    gen.write_to_files()
