"""
Policy Pusher
Orchestrates reading, building PAN-OS CLI commands, pushing via SSH,
and marking each item PUSHED or FAILED.

Push order (dependency-safe):
  1. Address Objects
  2. Service Objects
  3. Security Zones
  4. NAT Policies
  5. Security Policies
  6. Commit  (if AUTO_COMMIT = True)
"""

import re
import logging

import config
from ssh_client import PaloAltoSSHClient
from cli_builder import CLIBuilder
from excel_reader import PolicyWorkbook

log = logging.getLogger("paloalto.pusher")

# PAN-OS error keywords
_ERR_RE = re.compile(
    r"error|unknown|invalid|failed|warning|not found|syntax error",
    re.IGNORECASE,
)

# Lines to tolerate (not real errors)
_OK_RE = re.compile(
    r"^\+|^\-|configuration saved|value\s+'\S+' set|"
    r"Admin'|Commit\s+job|job enqueued",
    re.IGNORECASE,
)


def _has_error(output: str) -> tuple[bool, str]:
    """Return (True, first_error_line) if output contains an error."""
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip echoed CLI command lines or prompts
        if stripped.startswith("set ") or stripped.startswith("commit") or stripped.startswith("revert") or stripped.startswith("exit"):
            continue
        if stripped.startswith("admin@") or stripped.startswith("[edit]"):
            continue
        if _ERR_RE.search(stripped) and not _OK_RE.match(stripped):
            return True, stripped
    return False, ""


class PolicyPusher:
    def __init__(self, ssh: PaloAltoSSHClient | None, dry_run: bool = False):
        self.ssh     = ssh
        self.dry_run = dry_run
        self.builder = CLIBuilder()

    # ──────────────────────────────────────────────
    #  Public entry point
    # ──────────────────────────────────────────────
    def push_all(self, pwb: PolicyWorkbook) -> None:
        if not self.dry_run:
            self.ssh.configure()   # Enter configure mode once

        self._section("PHASE 1 — Address Objects")
        for obj in pwb.address_objects:
            self._push(obj, self.builder.address_object(obj))

        self._section("PHASE 2 — Service Objects")
        for svc in pwb.service_objects:
            self._push(svc, self.builder.service_object(svc))

        self._section("PHASE 3 — Security Zones")
        for zone in pwb.security_zones:
            self._push(zone, self.builder.security_zone(zone))

        self._section("PHASE 4 — NAT Policies")
        for nat in pwb.nat_policies:
            self._push(nat, self.builder.nat_policy(nat))

        self._section("PHASE 5 — Security Policies")
        for pol in pwb.security_policies:
            self._push(pol, self.builder.security_policy(pol))

        # Commit
        if not self.dry_run:
            if config.AUTO_COMMIT:
                out = self.ssh.commit(description=config.COMMIT_DESCRIPTION)
                log.info(f"Commit output:\n{out.strip()}")
            self.ssh.exit_configure()
        else:
            log.info("[DRY-RUN] Would commit here.")

    # ──────────────────────────────────────────────
    #  Internal
    # ──────────────────────────────────────────────
    def _push(self, item, cmds: list[str]) -> None:
        name = getattr(item, "name", "?")
        log.info(f"  → {name}")
        combined = ""
        try:
            for cmd in cmds:
                if self.dry_run:
                    log.info(f"    [DRY-RUN] {cmd}")
                    continue
                out = self.ssh.send_cfg_cmd(cmd)
                combined += out
                err, msg = _has_error(out)
                if err:
                    raise RuntimeError(f"CLI error: {msg}")

            item.status = "DRY-RUN" if self.dry_run else "PUSHED"
            log.info(f"  ✔ {name}")
        except Exception as exc:
            item.status    = "FAILED"
            item.error_msg = str(exc)[:300]
            log.error(f"  ✘ {name} — {exc}")

    @staticmethod
    def _section(title: str) -> None:
        log.info("═" * 60)
        log.info(title)
        log.info("═" * 60)
