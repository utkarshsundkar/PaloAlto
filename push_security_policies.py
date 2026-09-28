"""
Push Security Policies Script
Quick, direct script to push security policies to Palo Alto Networks firewall.

Usage:
    python push_security_policies.py              # Pushes according to config.py settings
    python push_security_policies.py --dry-run    # Simulates push without modifying device
    python push_security_policies.py --live       # Enforces live push to device
    python push_security_policies.py --excel      # Pushes security policies from policies.xlsx
"""

import sys
import argparse
from security_policy_agent import run_security_agent

def main():
    parser = argparse.ArgumentParser(description="Push Security Policies to Palo Alto Firewall")
    parser.add_argument("--dry-run", action="store_true", help="Run in dry-run mode (no firewall changes)")
    parser.add_argument("--live", action="store_true", help="Force live push to firewall")
    parser.add_argument("--excel", action="store_true", help="Load policies from policies.xlsx instead of policy list")
    parser.add_argument("--export-excel", action="store_true", help="Update policies.xlsx with current security policy list")
    parser.add_argument("--filter", type=str, default=None, help="Filter rule name by substring")
    
    args = parser.parse_args()
    
    dry_run = None
    if args.dry_run:
        dry_run = True
    elif args.live:
        dry_run = False

    source = "excel" if args.excel else "list"

    ret = run_security_agent(
        source=source,
        dry_run=dry_run,
        rule_filter=args.filter,
        export_to_excel=args.export_excel,
    )
    sys.exit(ret)

if __name__ == "__main__":
    main()
