"""
Cisco FTD to Palo Alto Configuration Parser & Converter
Parses Cisco FTD (Firepower Threat Defense / ASA diagnostic-cli) running config
and generates complete, valid PAN-OS CLI configuration commands and structured Excel data.
"""

import ipaddress
import re
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional

# Helper: Netmask to CIDR
def mask_to_cidr(mask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return 32

def sanitize_name(name: str, max_len: int = 63) -> str:
    # Replace invalid chars with underscore
    clean = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name.strip())
    # Avoid consecutive underscores
    clean = re.sub(r'_+', '_', clean).strip('_')
    if not clean:
        clean = "obj_unnamed"
    return clean[:max_len]

# Known port service mapping
PORT_NAME_MAP = {
    "https": "443",
    "http": "80",
    "ssh": "22",
    "telnet": "23",
    "ftp": "21",
    "ftp-data": "20",
    "smtp": "25",
    "domain": "53",
    "dns": "53",
    "ntp": "123",
    "snmp": "161",
    "snmptrap": "162",
    "sqlnet": "1521",
    "ms-sql-s": "1433",
    "ms-sql-m": "1434",
    "radius": "1812",
    "radius-acct": "1813",
    "ldap": "389",
    "ldaps": "636",
    "syslog": "514",
    "tftp": "69",
    "netbios-ns": "137",
    "netbios-dgm": "138",
    "netbios-ssn": "139",
    "kerberos": "88",
    "bgp": "179",
    "tacacs": "49",
    "sunrpc": "111",
    "nfs": "2049",
    "h323": "1720",
    "sip": "5060",
    "sips": "5061",
    "pptp": "1723",
    "rtsp": "554",
    "pop3": "110",
    "pop3s": "995",
    "imap": "143",
    "imap4": "143",
    "imaps": "993",
    "echo": "7",
    "www": "80",
    "isakmp": "500",
    "bootps": "67",
    "bootpc": "68",
    "rsh": "514",
}

@dataclass
class FTDInterface:
    interface: str
    nameif: str
    ip: str = ""
    netmask: str = ""
    cidr: int = 32
    standby_ip: str = ""
    description: str = ""

@dataclass
class FTDAddressObject:
    name: str
    obj_type: str  # ip-netmask, ip-range, fqdn
    value: str
    description: str = ""

@dataclass
class FTDAddressGroup:
    name: str
    members: List[str] = field(default_factory=list)
    description: str = ""

@dataclass
class FTDServiceObject:
    name: str
    protocol: str  # tcp, udp, icmp
    port: str
    description: str = ""

@dataclass
class FTDServiceGroup:
    name: str
    members: List[str] = field(default_factory=list)
    description: str = ""

@dataclass
class FTDStaticRoute:
    interface: str
    dest_ip: str
    netmask: str
    cidr: int
    gateway: str
    metric: int = 1

@dataclass
class FTDNATRule:
    name: str
    src_zone: str
    dst_zone: str
    src_addr: str
    dst_addr: str
    trans_src: str = ""
    trans_dst: str = ""
    snat_type: str = "none" # dynamic-ip-and-port, static-ip, none
    snat_interface: str = ""
    service: str = "any"
    description: str = ""

@dataclass
class FTDSecurityRule:
    rule_id: str
    name: str
    action: str  # allow, deny
    src_zones: List[str] = field(default_factory=list)
    dst_zones: List[str] = field(default_factory=list)
    src_addrs: List[str] = field(default_factory=list)
    dst_addrs: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    description: str = ""
    log_end: str = "yes"

class FTDConfigParser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.interfaces: Dict[str, FTDInterface] = {}
        self.zones: Set[str] = set()
        self.address_objects: Dict[str, FTDAddressObject] = {}
        self.address_groups: Dict[str, FTDAddressGroup] = {}
        self.service_objects: Dict[str, FTDServiceObject] = {}
        self.service_groups: Dict[str, FTDServiceGroup] = {}
        self.static_routes: List[FTDStaticRoute] = []
        self.nat_rules: List[FTDNATRule] = []
        self.security_rules: List[FTDSecurityRule] = []

    def parse(self):
        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw_lines = f.readlines()
        stripped_lines = [l.strip() for l in raw_lines]

        self._parse_interfaces(stripped_lines)
        self._parse_network_objects(stripped_lines)
        self._parse_network_groups(stripped_lines)
        self._parse_service_groups(stripped_lines)
        self._parse_static_routes(stripped_lines)
        self._parse_nat_rules(raw_lines)
        self._parse_security_acls(stripped_lines)
        return self

    def _parse_interfaces(self, lines: List[str]):
        current_iface = None
        current_data = {}

        for line in lines:
            if line.startswith("interface "):
                if current_iface and "nameif" in current_data:
                    self._save_interface(current_iface, current_data)
                current_iface = line.split()[1]
                current_data = {}
            elif current_iface:
                if line.startswith("nameif "):
                    current_data["nameif"] = line.split()[1]
                    self.zones.add(current_data["nameif"])
                elif line.startswith("ip address "):
                    parts = line.split()
                    current_data["ip"] = parts[2]
                    current_data["netmask"] = parts[3]
                    if len(parts) >= 6 and parts[4] == "standby":
                        current_data["standby_ip"] = parts[5]
                elif line.startswith("description "):
                    current_data["description"] = line[12:].strip()

        if current_iface and "nameif" in current_data:
            self._save_interface(current_iface, current_data)

    def _save_interface(self, iface_name: str, data: dict):
        netmask = data.get("netmask", "255.255.255.255")
        cidr = mask_to_cidr(netmask) if netmask else 32
        self.interfaces[iface_name] = FTDInterface(
            interface=iface_name,
            nameif=data["nameif"],
            ip=data.get("ip", ""),
            netmask=netmask,
            cidr=cidr,
            standby_ip=data.get("standby_ip", ""),
            description=data.get("description", "")
        )

    def _parse_network_objects(self, lines: List[str]):
        current_obj = None
        current_desc = ""

        for line in lines:
            if line.startswith("object network "):
                current_obj = line.split()[2]
                current_desc = ""
            elif current_obj and (line.startswith("object ") or line.startswith("object-group ") or line.startswith("access-list ") or line.startswith("nat ")):
                current_obj = None
            elif current_obj:
                if line.startswith("description "):
                    current_desc = line[12:].strip()
                elif line.startswith("host "):
                    ip = line.split()[1]
                    self.address_objects[current_obj] = FTDAddressObject(
                        name=current_obj,
                        obj_type="ip-netmask",
                        value=f"{ip}/32",
                        description=current_desc
                    )
                elif line.startswith("subnet "):
                    parts = line.split()
                    ip = parts[1]
                    mask = parts[2]
                    cidr = mask_to_cidr(mask)
                    self.address_objects[current_obj] = FTDAddressObject(
                        name=current_obj,
                        obj_type="ip-netmask",
                        value=f"{ip}/{cidr}",
                        description=current_desc
                    )
                elif line.startswith("range "):
                    parts = line.split()
                    self.address_objects[current_obj] = FTDAddressObject(
                        name=current_obj,
                        obj_type="ip-range",
                        value=f"{parts[1]}-{parts[2]}",
                        description=current_desc
                    )
                elif line.startswith("fqdn "):
                    parts = line.split()
                    fqdn_val = parts[-1]
                    self.address_objects[current_obj] = FTDAddressObject(
                        name=current_obj,
                        obj_type="fqdn",
                        value=fqdn_val,
                        description=current_desc
                    )

    def _parse_network_groups(self, lines: List[str]):
        current_grp = None
        current_members = []
        current_desc = ""

        for line in lines:
            if line.startswith("object-group network "):
                if current_grp:
                    self.address_groups[current_grp] = FTDAddressGroup(
                        name=current_grp,
                        members=current_members,
                        description=current_desc
                    )
                current_grp = line.split()[2]
                current_members = []
                current_desc = ""
            elif current_grp and (line.startswith("object-group ") or line.startswith("object ") or line.startswith("access-list ") or line.startswith("nat ")):
                if current_grp:
                    self.address_groups[current_grp] = FTDAddressGroup(
                        name=current_grp,
                        members=current_members,
                        description=current_desc
                    )
                current_grp = None
            elif current_grp:
                if line.startswith("description "):
                    current_desc = line[12:].strip()
                elif line.startswith("network-object object "):
                    obj_name = line.split()[2]
                    current_members.append(obj_name)
                elif line.startswith("group-object "):
                    grp_name = line.split()[1]
                    current_members.append(grp_name)
                elif line.startswith("network-object host "):
                    ip = line.split()[2]
                    # Inline host: create an address object if not existing
                    host_obj_name = f"Host_{ip}"
                    if host_obj_name not in self.address_objects:
                        self.address_objects[host_obj_name] = FTDAddressObject(
                            name=host_obj_name,
                            obj_type="ip-netmask",
                            value=f"{ip}/32",
                            description=f"Auto-created from group {current_grp}"
                        )
                    current_members.append(host_obj_name)
                elif line.startswith("network-object "):
                    parts = line.split()
                    if len(parts) >= 3 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[1]):
                        ip = parts[1]
                        mask = parts[2]
                        cidr = mask_to_cidr(mask)
                        net_obj_name = f"Net_{ip}_{cidr}"
                        if net_obj_name not in self.address_objects:
                            self.address_objects[net_obj_name] = FTDAddressObject(
                                name=net_obj_name,
                                obj_type="ip-netmask",
                                value=f"{ip}/{cidr}",
                                description=f"Auto-created from group {current_grp}"
                            )
                        current_members.append(net_obj_name)

        if current_grp:
            self.address_groups[current_grp] = FTDAddressGroup(
                name=current_grp,
                members=current_members,
                description=current_desc
            )

    def _parse_service_groups(self, lines: List[str]):
        current_grp = None
        current_proto = "tcp"
        current_members = []
        current_desc = ""

        for line in lines:
            if line.startswith("object-group service "):
                if current_grp:
                    self.service_groups[current_grp] = FTDServiceGroup(
                        name=current_grp,
                        members=current_members,
                        description=current_desc
                    )
                parts = line.split()
                current_grp = parts[2]
                current_proto = parts[3] if len(parts) > 3 else "tcp"
                current_members = []
                current_desc = ""
            elif current_grp and (line.startswith("object-group ") or line.startswith("object ") or line.startswith("access-list ") or line.startswith("nat ")):
                if current_grp:
                    self.service_groups[current_grp] = FTDServiceGroup(
                        name=current_grp,
                        members=current_members,
                        description=current_desc
                    )
                current_grp = None
            elif current_grp:
                if line.startswith("description "):
                    current_desc = line[12:].strip()
                elif line.startswith("port-object eq "):
                    p = line.split()[2]
                    port_val = PORT_NAME_MAP.get(p.lower(), p)
                    svc_name = f"svc_{current_proto}_{port_val}"
                    if svc_name not in self.service_objects:
                        self.service_objects[svc_name] = FTDServiceObject(
                            name=svc_name,
                            protocol=current_proto,
                            port=port_val,
                            description=f"Port {port_val} {current_proto.upper()}"
                        )
                    current_members.append(svc_name)
                elif line.startswith("port-object range "):
                    parts = line.split()
                    p1 = PORT_NAME_MAP.get(parts[2].lower(), parts[2])
                    p2 = PORT_NAME_MAP.get(parts[3].lower(), parts[3])
                    port_val = f"{p1}-{p2}"
                    svc_name = f"svc_{current_proto}_{port_val}"
                    if svc_name not in self.service_objects:
                        self.service_objects[svc_name] = FTDServiceObject(
                            name=svc_name,
                            protocol=current_proto,
                            port=port_val,
                            description=f"Port range {port_val} {current_proto.upper()}"
                        )
                    current_members.append(svc_name)
                elif line.startswith("service-object "):
                    parts = line.split()
                    proto = parts[1]
                    if len(parts) >= 4 and parts[2] == "destination" and parts[3] == "eq":
                        p = parts[4]
                        port_val = PORT_NAME_MAP.get(p.lower(), p)
                        svc_name = f"svc_{proto}_{port_val}"
                        if svc_name not in self.service_objects:
                            self.service_objects[svc_name] = FTDServiceObject(
                                name=svc_name,
                                protocol=proto,
                                port=port_val,
                                description=f"Port {port_val} {proto.upper()}"
                            )
                        current_members.append(svc_name)
                    elif len(parts) >= 5 and parts[2] == "destination" and parts[3] == "range":
                        p1 = PORT_NAME_MAP.get(parts[4].lower(), parts[4])
                        p2 = PORT_NAME_MAP.get(parts[5].lower(), parts[5])
                        port_val = f"{p1}-{p2}"
                        svc_name = f"svc_{proto}_{port_val}"
                        if svc_name not in self.service_objects:
                            self.service_objects[svc_name] = FTDServiceObject(
                                name=svc_name,
                                protocol=proto,
                                port=port_val,
                                description=f"Port range {port_val} {proto.upper()}"
                            )
                        current_members.append(svc_name)
                    elif proto.lower() == "icmp":
                        icmp_type = parts[2] if len(parts) > 2 else "any"
                        # For ICMP in PAN-OS, application is typically ping/icmp or service any
                        current_members.append("application-default")
                elif line.startswith("group-object "):
                    current_members.append(line.split()[1])

        if current_grp:
            self.service_groups[current_grp] = FTDServiceGroup(
                name=current_grp,
                members=current_members,
                description=current_desc
            )

    def _parse_static_routes(self, lines: List[str]):
        route_re = re.compile(r'^route\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?')
        for line in lines:
            m = route_re.match(line)
            if m:
                iface, dest_ip, netmask, gateway, metric = m.groups()
                cidr = mask_to_cidr(netmask)
                self.static_routes.append(FTDStaticRoute(
                    interface=iface,
                    dest_ip=dest_ip,
                    netmask=netmask,
                    cidr=cidr,
                    gateway=gateway,
                    metric=int(metric) if metric else 1
                ))

    def _parse_nat_rules(self, lines: List[str]):
        # 1. Twice NAT
        # nat (INSIDE_ZONE,INTERNET_WAN) source static A B destination static C D description ...
        # nat (INSIDE_ZONE,INTERNET_WAN) source static A B description ...
        # nat (any,any) after-auto ...
        idx = 1
        for line in lines:
            if not line.startswith("nat ("):
                continue
            
            m_zones = re.match(r'^nat\s*\(([^,]+),([^)]+)\)\s*(.*)', line)
            if not m_zones:
                continue
            src_zone, dst_zone, rest = m_zones.groups()
            src_zone = src_zone.strip()
            dst_zone = dst_zone.strip()

            desc = ""
            if "description " in rest:
                rest_parts = rest.split("description ", 1)
                rest = rest_parts[0].strip()
                desc = rest_parts[1].strip()

            tokens = rest.split()
            # Default values
            src_addr = "any"
            trans_src = ""
            dst_addr = "any"
            trans_dst = ""
            snat_type = "none"

            t_idx = 0
            # skip after-auto if present
            if t_idx < len(tokens) and tokens[t_idx] == "after-auto":
                t_idx += 1

            snat_iface = ""
            if t_idx < len(tokens) and tokens[t_idx] == "source":
                t_idx += 1 # 'source'
                mode = tokens[t_idx] # static | dynamic
                t_idx += 1
                src_addr = tokens[t_idx]
                t_idx += 1
                if t_idx < len(tokens) and tokens[t_idx] == "pat-pool":
                    t_idx += 1
                trans_src = tokens[t_idx] if t_idx < len(tokens) else ""
                t_idx += 1
                snat_type = "static-ip" if mode == "static" else "dynamic-ip-and-port"
                if trans_src == "interface":
                    snat_type = "dynamic-ip-and-port"
                    snat_iface = "ethernet1/1"
                    trans_src = ""

            if t_idx < len(tokens) and tokens[t_idx] == "destination":
                t_idx += 1 # 'destination'
                mode = tokens[t_idx] # static
                t_idx += 1
                dst_addr = tokens[t_idx]
                t_idx += 1
                trans_dst = tokens[t_idx]
                t_idx += 1

            rule_name = f"NAT_Rule_{idx}"
            idx += 1
            if desc:
                clean_desc_name = sanitize_name(desc, 30)
                rule_name = f"NAT_{clean_desc_name}_{idx}"

            self.nat_rules.append(FTDNATRule(
                name=rule_name,
                src_zone=src_zone,
                dst_zone=dst_zone,
                src_addr=src_addr,
                dst_addr=dst_addr,
                trans_src=trans_src,
                trans_dst=trans_dst,
                snat_type=snat_type,
                snat_interface=snat_iface,
                description=desc
            ))

        # 2. Object NAT (Auto NAT)
        # object network <name> \n nat (INSIDE_ZONE,INTERNET_WAN) dynamic interface
        curr_obj = None
        for raw_line in lines:
            s_line = raw_line.strip()
            if s_line.startswith("object network "):
                curr_obj = s_line.split()[2]
            elif curr_obj and (raw_line.startswith(" ") or raw_line.startswith("\t")) and s_line.startswith("nat ("):
                m_obj_nat = re.match(r'nat\s*\(([^,]+),([^)]+)\)\s*(.*)', s_line)
                if m_obj_nat:
                    sz, dz, nat_spec = m_obj_nat.groups()
                    rule_name = f"ObjNAT_{curr_obj}"
                    snat_type = "none"
                    snat_iface = ""
                    if "dynamic interface" in nat_spec:
                        snat_type = "dynamic-ip-and-port"
                        snat_iface = "ethernet1/1" # egress interface for INTERNET_WAN
                    elif "static" in nat_spec:
                        snat_type = "static-ip"
                    
                    self.nat_rules.append(FTDNATRule(
                        name=rule_name,
                        src_zone=sz.strip(),
                        dst_zone=dz.strip(),
                        src_addr=curr_obj,
                        dst_addr="any",
                        snat_type=snat_type,
                        snat_interface=snat_iface,
                        description=f"Auto NAT for object {curr_obj}"
                    ))
            elif curr_obj and not (raw_line.startswith(" ") or raw_line.startswith("\t")):
                curr_obj = None

    def _parse_security_acls(self, lines: List[str]):
        # Extract rule-id to human-readable rule name mapping from remarks
        rule_names: Dict[str, str] = {}
        for line in lines:
            m = re.match(r'access-list CSM_FW_ACL_ remark rule-id (\d+): (?:L7 RULE|L4 RULE|RULE):\s*(.+)', line)
            if m:
                rule_names[m.group(1)] = m.group(2).strip()

        # Group ACE lines by rule-id
        ace_re = re.compile(r'access-list CSM_FW_ACL_ advanced (\S+)\s+(\S+)\s+(.*?)\s+rule-id (\d+)(.*)')

        rule_groups: Dict[str, List[Tuple[str, str, str]]] = {}
        for line in lines:
            if not line.startswith("access-list CSM_FW_ACL_ advanced "):
                continue
            m = ace_re.match(line)
            if not m:
                continue
            action, proto, middle, rule_id, _ = m.groups()
            if rule_id not in rule_groups:
                rule_groups[rule_id] = []
            rule_groups[rule_id].append((action, proto, middle))

        # Parse each group into a consolidated PAN-OS FTDSecurityRule
        rule_counter = 1
        for rule_id, aces in rule_groups.items():
            base_action = aces[0][0]
            action = "allow" if base_action in ("permit", "trust") else "deny"
            raw_name = rule_names.get(rule_id, f"Rule_{rule_id}")
            rule_name = sanitize_name(raw_name, 50)
            if not rule_name:
                rule_name = f"Rule_{rule_id}"
            rule_name = f"{rule_counter:03d}_{rule_name}"
            rule_counter += 1

            src_zones: Set[str] = set()
            dst_zones: Set[str] = set()
            src_addrs: Set[str] = set()
            dst_addrs: Set[str] = set()
            services: Set[str] = set()

            for act, proto, middle in aces:
                sz, sa, dz, da, svcs = self._parse_ace_middle(middle, proto)
                if sz != "any": src_zones.add(sz)
                if dz != "any": dst_zones.add(dz)
                for s in sa: src_addrs.add(s)
                for d in da: dst_addrs.add(d)
                for s in svcs: services.add(s)

            # Fallbacks if sets empty
            final_src_zones = list(src_zones) if src_zones else ["any"]
            final_dst_zones = list(dst_zones) if dst_zones else ["any"]
            final_src_addrs = list(src_addrs) if src_addrs else ["any"]
            final_dst_addrs = list(dst_addrs) if dst_addrs else ["any"]
            final_services = list(services) if services else ["any"]

            self.security_rules.append(FTDSecurityRule(
                rule_id=rule_id,
                name=rule_name,
                action=action,
                src_zones=final_src_zones,
                dst_zones=final_dst_zones,
                src_addrs=final_src_addrs,
                dst_addrs=final_dst_addrs,
                services=final_services,
                description=f"Migrated FTD rule {rule_id}: {raw_name}"[:255]
            ))

    def _parse_ace_middle(self, middle: str, proto: str) -> Tuple[str, List[str], str, List[str], List[str]]:
        tokens = middle.split()
        idx = 0
        service: List[str] = []

        # ICMP or leading service tokens
        if idx < len(tokens) and tokens[idx] not in ("ifc", "host", "object", "object-group", "any", "any4", "any6") and not re.match(r'^\d+\.\d+\.\d+\.\d+$', tokens[idx]):
            service.append(tokens[idx])
            idx += 1

        src_zone = "any"
        dst_zone = "any"

        # 1. Source zone
        if idx < len(tokens) and tokens[idx] == "ifc":
            src_zone = tokens[idx + 1]
            idx += 2

        # 2. Source address
        src_addr: List[str] = []
        if idx < len(tokens):
            if tokens[idx] == "host":
                ip = tokens[idx + 1]
                if ip in self.address_objects:
                    src_addr.append(ip)
                else:
                    host_name = f"Host_{ip}"
                    if host_name not in self.address_objects:
                        self.address_objects[host_name] = FTDAddressObject(
                            name=host_name,
                            obj_type="ip-netmask",
                            value=f"{ip}/32",
                            description="Auto-created from ACE inline host"
                        )
                    src_addr.append(host_name)
                idx += 2
            elif tokens[idx] in ("object", "object-group"):
                src_addr.append(tokens[idx + 1])
                idx += 2
            elif tokens[idx] in ("any", "any4", "any6"):
                src_addr.append("any")
                idx += 1
            elif re.match(r'^\d+\.\d+\.\d+\.\d+$', tokens[idx]):
                ip = tokens[idx]
                mask = tokens[idx + 1]
                cidr = mask_to_cidr(mask)
                net_name = f"Net_{ip}_{cidr}"
                if net_name not in self.address_objects:
                    self.address_objects[net_name] = FTDAddressObject(
                        name=net_name,
                        obj_type="ip-netmask",
                        value=f"{ip}/{cidr}",
                        description="Auto-created from ACE inline network"
                    )
                src_addr.append(net_name)
                idx += 2

        # Source port check (e.g. any eq 3544)
        if idx < len(tokens) and tokens[idx] == "eq":
            idx += 2
        elif idx < len(tokens) and tokens[idx] == "range":
            idx += 3

        # 3. Destination zone
        if idx < len(tokens) and tokens[idx] == "ifc":
            dst_zone = tokens[idx + 1]
            idx += 2

        # 4. Destination address
        dst_addr: List[str] = []
        if idx < len(tokens):
            if tokens[idx] == "host":
                ip = tokens[idx + 1]
                if ip in self.address_objects:
                    dst_addr.append(ip)
                else:
                    host_name = f"Host_{ip}"
                    if host_name not in self.address_objects:
                        self.address_objects[host_name] = FTDAddressObject(
                            name=host_name,
                            obj_type="ip-netmask",
                            value=f"{ip}/32",
                            description="Auto-created from ACE inline host"
                        )
                    dst_addr.append(host_name)
                idx += 2
            elif tokens[idx] in ("object", "object-group"):
                dst_addr.append(tokens[idx + 1])
                idx += 2
            elif tokens[idx] in ("any", "any4", "any6"):
                dst_addr.append("any")
                idx += 1
            elif re.match(r'^\d+\.\d+\.\d+\.\d+$', tokens[idx]):
                ip = tokens[idx]
                mask = tokens[idx + 1]
                cidr = mask_to_cidr(mask)
                net_name = f"Net_{ip}_{cidr}"
                if net_name not in self.address_objects:
                    self.address_objects[net_name] = FTDAddressObject(
                        name=net_name,
                        obj_type="ip-netmask",
                        value=f"{ip}/{cidr}",
                        description="Auto-created from ACE inline network"
                    )
                dst_addr.append(net_name)
                idx += 2

        # 5. Remaining destination service / port
        while idx < len(tokens):
            if tokens[idx] in ("object-group", "object"):
                service.append(tokens[idx + 1])
                idx += 2
            elif tokens[idx] == "eq":
                port = tokens[idx + 1]
                port_val = PORT_NAME_MAP.get(port.lower(), port)
                svc_name = f"svc_{proto}_{port_val}"
                if svc_name not in self.service_objects:
                    self.service_objects[svc_name] = FTDServiceObject(
                        name=svc_name,
                        protocol=proto,
                        port=port_val,
                        description=f"Port {port_val} {proto.upper()}"
                    )
                service.append(svc_name)
                idx += 2
            elif tokens[idx] == "range":
                p1 = PORT_NAME_MAP.get(tokens[idx + 1].lower(), tokens[idx + 1])
                p2 = PORT_NAME_MAP.get(tokens[idx + 2].lower(), tokens[idx + 2])
                port_val = f"{p1}-{p2}"
                svc_name = f"svc_{proto}_{port_val}"
                if svc_name not in self.service_objects:
                    self.service_objects[svc_name] = FTDServiceObject(
                        name=svc_name,
                        protocol=proto,
                        port=port_val,
                        description=f"Port range {port_val} {proto.upper()}"
                    )
                service.append(svc_name)
                idx += 3
            elif tokens[idx] in ("lt", "gt"):
                idx += 2
            else:
                service.append(tokens[idx])
                idx += 1

        return src_zone, src_addr, dst_zone, dst_addr, service


if __name__ == "__main__":
    ftd_file = "Cisco FTD running config"
    parser = FTDConfigParser(ftd_file)
    parser.parse()

    print("=" * 60)
    print("CISCO FTD CONFIGURATION PARSE RESULTS")
    print("=" * 60)
    print(f"Interfaces      : {len(parser.interfaces)}")
    print(f"Security Zones  : {len(parser.zones)}")
    for z in sorted(parser.zones):
        print(f"   • {z}")
    print(f"Address Objects : {len(parser.address_objects)}")
    print(f"Address Groups  : {len(parser.address_groups)}")
    print(f"Service Objects : {len(parser.service_objects)}")
    print(f"Service Groups  : {len(parser.service_groups)}")
    print(f"Static Routes   : {len(parser.static_routes)}")
    print(f"NAT Policies    : {len(parser.nat_rules)}")
    print(f"Security Rules  : {len(parser.security_rules)}")
    print("=" * 60)
