# Palo Alto

Automated policy deployment and management suite for **Palo Alto Networks** firewalls via SSH CLI.
Push firewall policies, security rules, NAT, zones, and address objects directly from Python or Excel (`policies.xlsx`) — zero manual interaction.

## Project Files

| File | Purpose |
|------|---------|
| `config.py` | 🔧 Device IP, credentials, vsys, timeouts, commit settings |
| `security_policies_list.py` | Predefined policy list, vHEADER schema definitions, and converter |
| `security_policy_agent.py` | Dedicated agent for security policy validation and deployment |
| `push_security_policies.py` | CLI entry point to push or dry-run security policies |
| `create_template.py` | Run once to generate the `policies.xlsx` template |
| `policies.xlsx` | Workbook containing all 5 policy sheets |
| `main.py` | Full multi-sheet deployment agent (Address, Service, Zone, NAT, Security) |
| `run_agent.bat` | Windows launcher for full deployment |
| `run_security_agent.bat` | Windows launcher for security policy agent |
| `TEST_SSH.bat` / `test_ssh.py` | Non-destructive SSH connectivity and permissions check |
| `ssh_client.py` | PAN-OS SSH session manager |
| `cli_builder.py` | Generates PAN-OS `set` commands |
| `excel_reader.py` | Reads all sheets from the Excel workbook |
| `excel_writer.py` | Writes PUSHED/FAILED status back to Excel |
| `policy_pusher.py` | Orchestrates the multi-stage push pipeline |

---

## Quick Start

### Step 1 — Configure the device
Edit **`config.py`** and set:
```python
PALOALTO_HOST     = "192.168.1.1"
PALOALTO_USERNAME = "admin"
PALOALTO_PASSWORD = "your_password"
VSYS              = "vsys1"
AUTO_COMMIT       = True
```

### Step 2 — Create the Excel template
```
python create_template.py
```
This generates `policies.xlsx` with all 5 sheets and example rows.

### Step 3 — Fill in your policies
Open `policies.xlsx` and fill in your data:

| Sheet | What goes here |
|-------|---------------|
| `Address_Objects` | IP subnets, ranges, FQDNs |
| `Service_Objects` | TCP/UDP port definitions |
| `Security_Zones` | Zone names + bound interfaces |
| `NAT_Policies` | Source NAT, Destination NAT rules |
| `Security_Policies` | Allow/deny security rules |

> **Tip:** Prefix a Name with `#` to skip that row (acts as a comment).

### Step 4 — Run the agent
```
python main.py
```
Or double-click **`run_agent.bat`** on Windows.

---

## Dry-Run Mode
Test without touching the firewall — set in `config.py`:
```python
DRY_RUN = True
```
Commands are printed to the console/log but never sent.

---

## Address Object Types

| Type | Value format |
|------|-------------|
| `ip-netmask` | `10.0.0.0/24` |
| `ip-range` | `10.0.0.1-10.0.0.254` |
| `fqdn` | `api.example.com` |
| `ip-wildcard` | `10.20.0.0/0.0.255.0` |

## SNAT Types (NAT Policies)

| SNAT Type | When to use |
|-----------|------------|
| `dynamic-ip-and-port` | Standard outbound NAT (DIPP) |
| `dynamic-ip` | Dynamic IP without port translation |
| `static-ip` | 1:1 NAT |
| `none` | Destination NAT only |

---

## Results
After each run, the `Status` column in every sheet is updated:

- 🟢 **PUSHED** — successfully applied
- 🔴 **FAILED** — error (see Error Detail column + log file)
- 🟡 **DRY-RUN** — would have been pushed
