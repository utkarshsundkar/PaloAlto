"""
Palo Alto & Cisco FTD Migration Agent - Local Web Server & API
Provides a REST API and serves the Agent UI dashboard.
Runs on http://localhost:8080
"""

import http.server
import socketserver
import json
import os
import sys
import subprocess
import threading
import time
import urllib.parse
import re
from pathlib import Path

PORT = 8080
BASE_DIR = Path(__file__).parent.resolve()
WEB_DIR = BASE_DIR / "web"
COMMANDS_DIR = BASE_DIR / "commands_stages"

# Task execution state
push_state = {
    "is_running": False,
    "current_stage": "",
    "log_output": [],
    "status": "idle", # idle, running, completed, error
    "exit_code": None
}

class AgentRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/config":
            self.get_config()
        elif path == "/api/status":
            self.get_status()
        elif path == "/api/stages":
            self.get_stages()
        elif path == "/api/policies":
            self.get_policies()
        elif path == "/api/push/log":
            self.get_push_log()
        else:
            # Serve static files from web directory
            if path == "/":
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        if path == "/api/config":
            self.update_config(data)
        elif path == "/api/parse":
            self.run_parse()
        elif path == "/api/fix-deny-rules":
            self.fix_deny_rules()
        elif path == "/api/test-ssh":
            self.test_ssh(data)
        elif path == "/api/push/start":
            self.start_push(data)
        elif path == "/api/git/push":
            self.git_push(data)
        else:
            self.send_json({"error": "Endpoint not found"}, status=404)

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def get_config(self):
        try:
            import config
            self.send_json({
                "host": config.PALOALTO_HOST,
                "port": config.PALOALTO_PORT,
                "username": config.PALOALTO_USERNAME,
                "vsys": getattr(config, "VSYS", "vsys1"),
                "excel_file": getattr(config, "EXCEL_FILE", "policies.xlsx"),
                "auto_commit": getattr(config, "AUTO_COMMIT", True),
                "dry_run": getattr(config, "DRY_RUN", False)
            })
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def update_config(self, data):
        try:
            config_file = BASE_DIR / "config.py"
            content = config_file.read_text(encoding="utf-8")

            if "host" in data:
                content = re.sub(r'PALOALTO_HOST\s*=\s*".*?"', f'PALOALTO_HOST = "{data["host"]}"', content)
            if "port" in data:
                content = re.sub(r'PALOALTO_PORT\s*=\s*\d+', f'PALOALTO_PORT = {int(data["port"])}', content)
            if "username" in data:
                content = re.sub(r'PALOALTO_USERNAME\s*=\s*".*?"', f'PALOALTO_USERNAME = "{data["username"]}"', content)
            if "password" in data and data["password"]:
                content = re.sub(r'PALOALTO_PASSWORD\s*=\s*".*?"', f'PALOALTO_PASSWORD = "{data["password"]}"', content)

            config_file.write_text(content, encoding="utf-8")
            self.send_json({"message": "Configuration updated successfully"})
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def get_status(self):
        ftd_file = BASE_DIR / "Cisco FTD running config"
        has_ftd = ftd_file.exists()
        stages_count = len(list(COMMANDS_DIR.glob("*.set"))) if COMMANDS_DIR.exists() else 0

        self.send_json({
            "ftd_config_exists": has_ftd,
            "ftd_size_mb": round(ftd_file.stat().st_size / (1024 * 1024), 2) if has_ftd else 0,
            "stages_count": stages_count,
            "push_status": push_state["status"]
        })

    def get_stages(self):
        stages = []
        if COMMANDS_DIR.exists():
            for f in sorted(COMMANDS_DIR.glob("*.set")):
                content = f.read_text(encoding="utf-8", errors="ignore").splitlines()
                cmd_count = len([l for l in content if l.strip() and not l.strip().startswith('#')])
                stages.append({
                    "filename": f.name,
                    "commands_count": cmd_count,
                    "size_bytes": f.stat().st_size,
                    "preview": content[:10]
                })
        self.send_json({"stages": stages})

    def get_policies(self):
        sec_file = COMMANDS_DIR / "09_security_policies.set"
        if not sec_file.exists():
            self.send_json({"rules": []})
            return

        lines = sec_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        rules_map = {}

        for l in lines:
            if not l.startswith('set rulebase security rules '):
                continue
            parts = l[len('set rulebase security rules '):].split(' ', 1)
            rule_name = parts[0].strip('"')
            rest = parts[1] if len(parts) > 1 else ""

            if rule_name not in rules_map:
                rules_map[rule_name] = {"name": rule_name, "action": "allow", "from": "", "to": "", "source": "", "destination": "", "description": ""}

            if rest.startswith("action "):
                rules_map[rule_name]["action"] = rest.split()[1]
            elif rest.startswith("from "):
                rules_map[rule_name]["from"] = rest[5:]
            elif rest.startswith("to "):
                rules_map[rule_name]["to"] = rest[3:]
            elif rest.startswith("source "):
                rules_map[rule_name]["source"] = rest[7:]
            elif rest.startswith("destination "):
                rules_map[rule_name]["destination"] = rest[12:]
            elif rest.startswith("description "):
                rules_map[rule_name]["description"] = rest[12:].strip('"')

        rules_list = list(rules_map.values())
        block_kw = ['block', 'deny', 'drop', 'reject', 'malicious']
        for r in rules_list:
            name_lower = r["name"].lower()
            desc_lower = r["description"].lower()
            r["is_block_suspect"] = any(kw in name_lower or kw in desc_lower for kw in block_kw) and r["action"] == "allow"

        self.send_json({"rules": rules_list, "total": len(rules_list)})

    def fix_deny_rules(self):
        try:
            sec_file = COMMANDS_DIR / "09_security_policies.set"
            if not sec_file.exists():
                self.send_json({"error": "Security policies stage file not found"}, status=404)
                return

            lines = sec_file.read_text(encoding="utf-8").splitlines()
            block_kw = ['block', 'deny', 'drop', 'reject', 'malicious']

            rules_to_fix = set()
            for l in lines:
                if ' description "' in l:
                    m = re.search(r'rules "([^"]+)" description "([^"]+)"', l)
                    if m:
                        rname, desc = m.groups()
                        if any(kw in rname.lower() or kw in desc.lower() for kw in block_kw):
                            rules_to_fix.add(rname)
                elif 'rules "' in l:
                    m = re.search(r'rules "([^"]+)"', l)
                    if m:
                        rname = m.group(1)
                        if any(kw in rname.lower() for kw in block_kw):
                            rules_to_fix.add(rname)

            updated_lines = []
            fixed_count = 0
            for l in lines:
                changed = False
                for rname in rules_to_fix:
                    if f'set rulebase security rules "{rname}" action allow' in l:
                        updated_lines.append(f'set rulebase security rules "{rname}" action deny')
                        fixed_count += 1
                        changed = True
                        break
                if not changed:
                    updated_lines.append(l)

            sec_file.write_text('\n'.join(updated_lines) + '\n', encoding="utf-8")
            self.send_json({"message": f"Successfully updated {fixed_count} block/deny rules to 'action deny'", "fixed_count": fixed_count})
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def test_ssh(self, data):
        try:
            import config
            from ssh_client import PaloAltoSSHClient

            host = data.get("host", config.PALOALTO_HOST)
            port = int(data.get("port", config.PALOALTO_PORT))
            user = data.get("username", config.PALOALTO_USERNAME)
            pwd = data.get("password", config.PALOALTO_PASSWORD)

            ssh = PaloAltoSSHClient(host, port, user, pwd, timeout=10, cmd_timeout=10, banner_timeout=15)
            ssh.connect()
            resp = ssh.send_cmd("show clock")
            ssh.disconnect()

            self.send_json({"success": True, "message": f"SSH connection successful! System clock: {resp.strip()}"})
        except Exception as e:
            self.send_json({"success": False, "error": str(e)}, status=400)

    def run_parse(self):
        def _parse_task():
            try:
                cmd = [sys.executable, "generate_panos_cli.py"]
                res = subprocess.run(cmd, cwd=str(BASE_DIR), capture_output=True, text=True)
                push_state["log_output"].append(res.stdout)
                if res.stderr:
                    push_state["log_output"].append(res.stderr)
            except Exception as e:
                push_state["log_output"].append(str(e))

        t = threading.Thread(target=_parse_task)
        t.start()
        self.send_json({"message": "Parsing Cisco FTD configuration started..."})

    def start_push(self, data):
        global push_state
        if push_state["is_running"]:
            self.send_json({"error": "Push task is already running"}, status=400)
            return

        dry_run = data.get("dry_run", False)
        auto_commit = data.get("auto_commit", True)
        chunk_size = data.get("chunk_size", 50)
        selected_stages = data.get("stages", [])

        push_state["is_running"] = True
        push_state["status"] = "running"
        push_state["log_output"] = ["Starting push agent...\n"]

        def _worker():
            try:
                cmd = [sys.executable, "push_ftd_to_paloalto.py", f"--chunk-size={chunk_size}"]
                if not dry_run:
                    cmd.append("--live")
                if auto_commit:
                    cmd.append("--commit")
                if selected_stages:
                    cmd.append(f"--stages={','.join(map(str, selected_stages))}")

                proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                
                for line in iter(proc.stdout.readline, ''):
                    if line:
                        push_state["log_output"].append(line)
                
                proc.stdout.close()
                proc.wait()
                push_state["exit_code"] = proc.returncode
                push_state["status"] = "completed" if proc.returncode == 0 else "error"
            except Exception as e:
                push_state["log_output"].append(f"\nError: {str(e)}\n")
                push_state["status"] = "error"
            finally:
                push_state["is_running"] = False

        t = threading.Thread(target=_worker)
        t.start()

        self.send_json({"message": "Push task started", "status": "running"})

    def get_push_log(self):
        self.send_json({
            "is_running": push_state["is_running"],
            "status": push_state["status"],
            "exit_code": push_state["exit_code"],
            "log": "".join(push_state["log_output"])
        })

    def git_push(self, data):
        commit_msg = data.get("message", "Update Palo Alto migration policies")
        try:
            res1 = subprocess.run(["git", "add", "."], cwd=str(BASE_DIR), capture_output=True, text=True)
            res2 = subprocess.run(["git", "commit", "-m", commit_msg], cwd=str(BASE_DIR), capture_output=True, text=True)
            res3 = subprocess.run(["git", "push", "origin", "main"], cwd=str(BASE_DIR), capture_output=True, text=True)

            out = f"{res1.stdout}\n{res2.stdout}\n{res3.stdout}"
            err = f"{res1.stderr}\n{res2.stderr}\n{res3.stderr}"

            self.send_json({"success": res3.returncode == 0, "output": out, "error": err})
        except Exception as e:
            self.send_json({"success": False, "error": str(e)}, status=500)

def main():
    WEB_DIR.mkdir(exist_ok=True)
    handler = AgentRequestHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Palo Alto Migration Agent Server running at http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")

if __name__ == "__main__":
    main()
