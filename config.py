"""
Palo Alto Policy Push Agent — Configuration
Edit this file to match your environment before running.
"""

# ─────────────────────────────────────────────
#  Palo Alto Device Settings
# ─────────────────────────────────────────────
PALOALTO_HOST     = "10.233.188.122"   # Firewall management IP
PALOALTO_PORT     = 22                  # SSH port (default 22)
PALOALTO_USERNAME = "admin"             # SSH username
PALOALTO_PASSWORD = "Admin@123"           # SSH password

# ─────────────────────────────────────────────
#  vsys  (leave "vsys1" for most deployments)
# ─────────────────────────────────────────────
VSYS = "vsys1"
# PA-VM / single-vsys: CLI is "set address ...", not "set vsys vsys1 address ..."
USE_VSYS_PREFIX = False

# ─────────────────────────────────────────────
#  Commit behaviour
# ─────────────────────────────────────────────
AUTO_COMMIT       = True     # Commit after all changes are pushed
COMMIT_DESCRIPTION = "Pushed by Palo Alto Policy Agent"

# ─────────────────────────────────────────────
#  Excel Sheet File
# ─────────────────────────────────────────────
EXCEL_FILE = "policies.xlsx"

# ─────────────────────────────────────────────
#  Sheet names inside the workbook
# ─────────────────────────────────────────────
SHEET_ADDRESS_OBJECTS  = "Address_Objects"
SHEET_SERVICE_OBJECTS  = "Service_Objects"
SHEET_SECURITY_ZONES   = "Security_Zones"
SHEET_NAT_POLICIES     = "NAT_Policies"
SHEET_SECURITY_POLICIES = "Security_Policies"
SHEET_HA_CONFIG         = "HA_Configuration"

# ─────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────
LOG_FILE  = "paloalto_push.log"
LOG_LEVEL = "INFO"           # DEBUG | INFO | WARNING | ERROR

# ─────────────────────────────────────────────
#  SSH Behaviour
# ─────────────────────────────────────────────
SSH_TIMEOUT    = 30    # seconds for initial TCP connection
CMD_TIMEOUT    = 20    # seconds per CLI command
BANNER_TIMEOUT = 60    # seconds for SSH banner handshake

# ─────────────────────────────────────────────
#  Dry-Run Mode
#  When True: commands are printed but NOT sent to the firewall
# ─────────────────────────────────────────────
DRY_RUN = False
