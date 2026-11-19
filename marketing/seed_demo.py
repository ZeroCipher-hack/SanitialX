"""Seed the running demo API (demo_server.py) with simulated incidents and endpoint agents."""
import json, os, tempfile, urllib.request
from pathlib import Path

API = f"http://localhost:{os.environ.get('DEMO_PORT', '8010')}/api/v1"
TOKEN = Path(tempfile.gettempdir(), "sanitialx-demo.token").read_text().strip()
ENROLL_KEY = "demo-api-key-" + "x" * 24


def post(path, body, headers):
    req = urllib.request.Request(API + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    return json.load(urllib.request.urlopen(req))


for scenario in ("WEB_APP_COMPROMISE", "SSH_BRUTE_FORCE", "DATA_EXFILTRATION"):
    post("/simulations/run", {"scenario_name": scenario}, {"Authorization": f"Bearer {TOKEN}"})

hosts = [("prod-web-01", "10.0.1.11", "Ubuntu 22.04"), ("prod-db-01", "10.0.1.21", "Ubuntu 22.04"),
         ("core-banking-01", "10.0.2.5", "RHEL 9"), ("corp-win-01", "10.0.3.14", "Windows Server 2022"),
         ("vpn-gw-01", "10.0.0.2", "Debian 12")]
for i, (name, ip, os_name) in enumerate(hosts, 1):
    agent_id = f"agent-{name}"
    token = post("/agents/enroll", {"agent_id": agent_id, "hostname": name, "ip_address": ip, "os": os_name,
                                    "agent_version": "0.2.0"}, {"X-Enrollment-Key": ENROLL_KEY})["agent_token"]
    post(f"/agents/{agent_id}/heartbeat", {"cpu_usage": 20 + i * 9.5, "memory_usage": 35 + i * 6.2,
                                           "agent_version": "0.2.0", "ip_address": ip}, {"X-Agent-Token": token})
print("seeded")
