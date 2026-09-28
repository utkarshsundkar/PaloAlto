"""
PAN-OS CLI Command Builder
Converts structured policy data into PAN-OS CLI 'set' commands (configure mode).
All commands use the canonical PAN-OS set syntax.
"""

import config
from excel_reader import (
    AddressObject, ServiceObject, SecurityZone, NATPolicy, SecurityPolicy
)


def _members(value: str) -> str:
    """
    Convert a comma-separated string into PAN-OS member syntax.
    'A, B, C'  →  '[ A B C ]'
    'A'        →  'A'
    """
    items = [v.strip() for v in value.split(",") if v.strip()]
    if len(items) == 1:
        return items[0]
    return "[ " + " ".join(items) + " ]"


BASE = f"set vsys {config.VSYS}"


class CLIBuilder:
    """
    Generates PAN-OS configure-mode 'set' command lists.
    Each method returns list[str] — one string per CLI line.
    """

    # ──────────────────────────────────────────────
    #  Address Objects
    # ──────────────────────────────────────────────
    @staticmethod
    def address_object(obj: AddressObject) -> list[str]:
        base = f"{BASE} address \"{obj.name}\""
        t = obj.type   # ip-netmask | ip-range | fqdn | ip-wildcard

        cmds = [f"{base} {t} {obj.value}"]

        if obj.description:
            cmds.append(f"{base} description \"{obj.description}\"")
        if obj.tag:
            cmds.append(f"{base} tag {_members(obj.tag)}")

        return cmds

    # ──────────────────────────────────────────────
    #  Service Objects
    # ──────────────────────────────────────────────
    @staticmethod
    def service_object(svc: ServiceObject) -> list[str]:
        base  = f"{BASE} service \"{svc.name}\""
        proto = svc.protocol.lower()   # tcp | udp

        # Normalise tcp-udp → both protocols
        protos = []
        if proto == "tcp-udp":
            protos = ["tcp", "udp"]
        else:
            protos = [proto]

        cmds = []
        for p in protos:
            if svc.dst_port:
                cmds.append(f"{base} protocol {p} port {svc.dst_port}")
            if svc.src_port:
                cmds.append(f"{base} protocol {p} source-port {svc.src_port}")

        if svc.description:
            cmds.append(f"{base} description \"{svc.description}\"")
        if svc.tag:
            cmds.append(f"{base} tag {_members(svc.tag)}")

        return cmds

    # ──────────────────────────────────────────────
    #  Security Zones
    # ──────────────────────────────────────────────
    @staticmethod
    def security_zone(zone: SecurityZone) -> list[str]:
        base = f"{BASE} zone \"{zone.name}\""
        mode = zone.mode   # layer3 | layer2 | virtual-wire | tap | tunnel

        cmds = []
        # Bind each interface
        if zone.interfaces:
            for iface in [i.strip() for i in zone.interfaces.split(",") if i.strip()]:
                cmds.append(f"{base} network {mode} member {iface}")

        # User-ID
        if zone.enable_userid.lower() == "yes":
            cmds.append(f"{base} enable-user-identification yes")

        if zone.description:
            cmds.append(f"{base} description \"{zone.description}\"")

        return cmds

    # ──────────────────────────────────────────────
    #  NAT Policies
    # ──────────────────────────────────────────────
    @staticmethod
    def nat_policy(nat: NATPolicy) -> list[str]:
        base = f"{BASE} rulebase nat rules \"{nat.name}\""

        cmds = [
            f"{base} nat-type {nat.nat_type}",
            f"{base} from {_members(nat.srczone)}",
            f"{base} to {_members(nat.dstzone)}",
            f"{base} source {_members(nat.srcaddr)}",
            f"{base} destination {_members(nat.dstaddr)}",
            f"{base} service {nat.service}",
        ]

        # Source NAT
        snat = nat.snat_type.lower()
        if snat == "dynamic-ip-and-port":
            if nat.snat_interface:
                cmds.append(
                    f"{base} source-translation dynamic-ip-and-port interface-address "
                    f"interface {nat.snat_interface}"
                )
            elif nat.snat_ip:
                cmds.append(
                    f"{base} source-translation dynamic-ip-and-port translated-address "
                    f"{_members(nat.snat_ip)}"
                )
        elif snat == "dynamic-ip" and nat.snat_ip:
            cmds.append(
                f"{base} source-translation dynamic-ip translated-address "
                f"{_members(nat.snat_ip)}"
            )
        elif snat == "static-ip" and nat.snat_ip:
            cmds.append(
                f"{base} source-translation static-ip translated-address {nat.snat_ip}"
            )

        # Destination NAT
        if nat.dnat_address:
            cmds.append(
                f"{base} destination-translation translated-address {nat.dnat_address}"
            )
        if nat.dnat_port:
            cmds.append(
                f"{base} destination-translation translated-port {nat.dnat_port}"
            )

        if nat.description:
            cmds.append(f"{base} description \"{nat.description}\"")
        if nat.tag:
            cmds.append(f"{base} tag {_members(nat.tag)}")

        return cmds

    # ──────────────────────────────────────────────
    #  Security Policies
    # ──────────────────────────────────────────────
    @staticmethod
    def security_policy(pol: SecurityPolicy) -> list[str]:
        base = f"{BASE} rulebase security rules \"{pol.name}\""

        cmds = [
            f"{base} from {_members(pol.srczone)}",
            f"{base} to {_members(pol.dstzone)}",
            f"{base} source {_members(pol.srcaddr)}",
            f"{base} destination {_members(pol.dstaddr)}",
            f"{base} application {_members(pol.application)}",
            f"{base} service {_members(pol.service)}",
            f"{base} action {pol.action}",
            f"{base} log-start {pol.log_start}",
            f"{base} log-end {pol.log_end}",
        ]

        if pol.profile_group:
            cmds.append(f"{base} profile-setting group \"{pol.profile_group}\"")

        if pol.description:
            cmds.append(f"{base} description \"{pol.description}\"")
        if pol.tag:
            cmds.append(f"{base} tag {_members(pol.tag)}")
        if getattr(pol, "disabled", "no").lower() in ("yes", "true"):
            cmds.append(f"{base} disabled yes")

        return cmds
