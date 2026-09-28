"""
Palo Alto SSH Client
Manages a persistent interactive SSH shell session to the PAN-OS CLI.
Handles both operational mode and configure mode automatically.
"""

import re
import time
import logging
import paramiko

log = logging.getLogger("paloalto.ssh")

# PAN-OS CLI prompt patterns
_OP_PROMPT_RE  = re.compile(r"[\w@\-]+>\s*$")          # admin@hostname>
_CFG_PROMPT_RE = re.compile(r"[\w@\-]+#\s*$")          # admin@hostname#
_ANY_PROMPT_RE = re.compile(r"[\w@\-]+[>#]\s*$")


class PaloAltoSSHClient:
    """
    Opens a persistent interactive shell to PAN-OS.
    Exposes:
      - send_op_cmd()   → runs commands in operational mode
      - send_cfg_cmd()  → runs commands inside configure mode
      - configure()     → enter configure mode
      - exit_configure()→ exit configure mode (back to op mode)
      - commit()        → commit the candidate config
    """

    def __init__(self, host: str, port: int, username: str, password: str,
                 timeout: int = 30, cmd_timeout: int = 20, banner_timeout: int = 60):
        self.host           = host
        self.port           = port
        self.username       = username
        self.password       = password
        self.timeout        = timeout
        self.cmd_timeout    = cmd_timeout
        self.banner_timeout = banner_timeout

        self._client: paramiko.SSHClient | None = None
        self._shell:  paramiko.Channel   | None = None
        self._in_configure = False

    # ──────────────────────────────────────────
    #  Lifecycle
    # ──────────────────────────────────────────
    def connect(self) -> None:
        log.info(f"Connecting to {self.host}:{self.port} …")
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            banner_timeout=self.banner_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        self._shell = self._client.invoke_shell(width=220, height=9999)
        self._shell.settimeout(self.cmd_timeout)
        # Consume banner/MOTD
        self._read_until_prompt(timeout=self.banner_timeout)
        # Disable the 'less' pager so output is never paginated
        self._send("set cli pager off")
        log.info("PAN-OS CLI ready (pager disabled, operational mode).")

    def disconnect(self) -> None:
        try:
            if self._in_configure:
                self.exit_configure()
        except Exception:
            pass
        if self._shell:
            try:
                self._shell.close()
            except Exception:
                pass
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
        log.info("SSH session closed.")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    # ──────────────────────────────────────────
    #  Mode management
    # ──────────────────────────────────────────
    def configure(self) -> str:
        """Enter configure mode."""
        out = self._send("configure")
        self._in_configure = True
        log.debug("Entered configure mode.")
        return out

    def exit_configure(self) -> str:
        """Exit configure mode (back to operational mode)."""
        out = self._send("exit")
        self._in_configure = False
        log.debug("Exited configure mode.")
        return out

    # ──────────────────────────────────────────
    #  Command execution
    # ──────────────────────────────────────────
    def send_op_cmd(self, command: str) -> str:
        """Send command in operational mode."""
        if self._in_configure:
            raise RuntimeError("Cannot run operational command while in configure mode.")
        return self._send(command)

    def send_cfg_cmd(self, command: str) -> str:
        """Send command in configure mode."""
        if not self._in_configure:
            self.configure()
        return self._send(command)

    def send_cfg_block(self, commands: list[str]) -> list[str]:
        """Send multiple configure-mode commands; returns each output."""
        if not self._in_configure:
            self.configure()
        return [self._send(cmd) for cmd in commands]

    def commit(self, description: str = "") -> str:
        """Commit the candidate configuration (must be in configure mode)."""
        log.info("Committing configuration …")
        if self._in_configure:
            self.exit_configure()
        cmd = f'commit description "{description}"' if description else "commit"
        # Commit can take a long time — use a longer timeout
        out = self._send(cmd, timeout=120)
        log.info("Commit complete.")
        return out

    # ──────────────────────────────────────────
    #  Internal
    # ──────────────────────────────────────────
    def _send(self, command: str, timeout: float | None = None) -> str:
        if not self._shell:
            raise RuntimeError("SSH shell is not open. Call connect() first.")
        log.debug(f"CMD → {command!r}")
        self._shell.send(command + "\n")
        time.sleep(0.4)
        out = self._read_until_prompt(timeout=timeout or self.cmd_timeout)
        log.debug(f"OUT ← {out!r}")
        return out

    def _read_until_prompt(self, timeout: float = 30) -> str:
        buf   = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._shell.recv_ready():
                buf += self._shell.recv(8192)
                text = buf.decode("utf-8", errors="replace")
                # Prompt detected on the last non-empty line
                last = text.rstrip().split("\n")[-1] if text.strip() else ""
                if _ANY_PROMPT_RE.search(last):
                    return text
            else:
                time.sleep(0.1)
        return buf.decode("utf-8", errors="replace")
