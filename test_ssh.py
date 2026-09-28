"""
SSH Connectivity Test — Read-Only Check (Live CMD Window Version)
Connects to the Palo Alto, runs safe read-only commands and prints
EVERY step live. Nothing is changed on the device.
"""

import sys
import os
import re
import time

sys.path.insert(0, ".")
import config
from ssh_client import PaloAltoSSHClient

# ── Commands to run (all safe / read-only) ────────────────
CMDS = [
    "show system info",
    "show interface management",
    "show admins",
]

SEP  = "=" * 62
SEP2 = "-" * 62

# Strip ANSI escape codes and null bytes
_CLEAN_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]|\x00|\r")

def _clean(text: str) -> str:
    return _CLEAN_RE.sub("", text)

def banner(msg: str):
    print(f"\n{SEP}\n  {msg}\n{SEP}")

def step(n, total, msg):
    print(f"\n[Step {n}/{total}]  {msg}")

def ok(msg):    print(f"  [  OK  ]  {msg}")
def fail(msg):  print(f"  [ FAIL ]  {msg}")


def print_output(raw: str, skip_prompt_for: str = ""):
    """Print device output line by line, skipping echo and prompts."""
    lines = _clean(raw).splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Skip echo of the command we just sent
        if skip_prompt_for and skip_prompt_for.strip() in stripped:
            continue
        # Skip bare prompts like  admin@PA-220>  or  admin@PA-220#
        if re.match(r"^[\w@\-]+\s*[>#]\s*$", stripped):
            continue
        print(f"           {line}")


def main():
    banner("Palo Alto SSH Connectivity Test")
    print(f"  Target  : {config.PALOALTO_HOST}:{config.PALOALTO_PORT}")
    print(f"  Username: {config.PALOALTO_USERNAME}")
    print(f"  vsys    : {config.VSYS}")
    print(f"  Time    : {time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        # ── Step 1: Connect ────────────────────────────────
        step(1, 4, f"Opening SSH connection to {config.PALOALTO_HOST} ...")
        print(f"           Initiating TCP handshake on port {config.PALOALTO_PORT} ...")
        print(f"           Sending SSH banner + credentials ...")

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
        ok(f"SSH session established  (pager disabled)")

        # ── Step 2: Read-only operational commands ─────────
        step(2, 4, "Running read-only operational show commands ...")
        for cmd in CMDS:
            print(f"\n  >>> Sending:  {cmd}")
            print(SEP2)
            out = ssh.send_op_cmd(cmd)
            print_output(out, skip_prompt_for=cmd)
            time.sleep(0.3)

        # ── Step 3: Configure mode entry/exit ──────────────
        step(3, 4, "Testing configure mode entry and exit ...")
        print("           Sending:  configure")
        ssh.configure()
        ok("Entered configure mode  (prompt is now #)")

        print("           Sending:  exit")
        ssh.exit_configure()
        ok("Exited configure mode cleanly  (prompt back to >)")

        # ── Step 4: Disconnect ─────────────────────────────
        step(4, 4, "Closing SSH session ...")
        ssh.disconnect()
        ok("Disconnected cleanly")

        print(f"\n{SEP}")
        print("  RESULT :  *** SSH TEST PASSED ***")
        print("  The agent can connect to the Palo Alto and issue commands.")
        print(f"  You can now fill in policies.xlsx and run  RUN_AGENT.bat")
        print(SEP)
        return 0

    except KeyboardInterrupt:
        print("\n\n  Interrupted by user.")
        return 1
    except Exception as exc:
        print(f"\n{SEP}")
        fail(str(exc))
        print(f"\n  RESULT :  *** SSH TEST FAILED ***")
        print(f"  Checklist:")
        print(f"    - Is {config.PALOALTO_HOST} reachable? (try: ping {config.PALOALTO_HOST})")
        print(f"    - Is SSH enabled on the management interface?")
        print(f"    - Are credentials correct? (user: {config.PALOALTO_USERNAME})")
        print(SEP)
        return 1


if __name__ == "__main__":
    sys.exit(main())
