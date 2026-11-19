"""Visit every page logged in as the demo admin; report console errors, HTTP >=400 and visible error text."""
import json, shutil, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
from websockets.sync.client import connect

BASE = "http://localhost:3101"; API = "http://localhost:8010/api/v1"
creds = Path(tempfile.gettempdir(), "sanitialx-demo-credentials.txt").read_text().splitlines()
user, password = [x.strip() for x in creds[0].split("(")[0:1]][0], creds[0].split(": ", 1)[1]
req = urllib.request.Request(API + "/auth/token", data=json.dumps({"username": user, "password": password}).encode(),
                             headers={"Content-Type": "application/json"}, method="POST")
token = json.load(urllib.request.urlopen(req))["access_token"]
inc = json.load(urllib.request.urlopen(urllib.request.Request(API + "/incidents", headers={"Authorization": f"Bearer {token}"})))[0]["incident_id"]
agents = json.load(urllib.request.urlopen(urllib.request.Request(API + "/agents", headers={"Authorization": f"Bearer {token}"})))
agent = agents[0]["agent_id"]
PAGES = ["/", "/pricing", "/dashboard", "/events", "/incidents", f"/incidents?id={inc}", "/logs", "/rules", "/techniques",
         "/vulnerabilities", "/agents", f"/agents/{agent}", "/assets", "/honeypots", "/simulations",
         f"/attack-graph?incident_id={inc}", "/ai-analysis", "/reports", "/threats", "/guide", "/support", "/news", "/license"]
if len(sys.argv) > 1:
    PAGES = sys.argv[1:]

prof = tempfile.mkdtemp()
proc = subprocess.Popen([shutil.which("chromium"), "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                         "--remote-debugging-port=9777", f"--user-data-dir={prof}", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try:
            tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9777/json"))
            ws = connect(next(t["webSocketDebuggerUrl"] for t in tabs if t["type"] == "page"), max_size=64 * 1024 * 1024); break
        except Exception:
            time.sleep(.25)
    n = 0; events = []
    def call(m, **k):
        global n; n += 1; ws.send(json.dumps({"id": n, "method": m, "params": k}))
        while True:
            r = json.loads(ws.recv())
            if "method" in r: events.append(r)
            if r.get("id") == n: return r.get("result")
    for d in ("Network", "Runtime", "Log"): call(f"{d}.enable")
    call("Emulation.setDeviceMetricsOverride", width=1440, height=900, deviceScaleFactor=1, mobile=False)
    call("Page.navigate", url=BASE + "/login"); time.sleep(2)
    call("Runtime.evaluate", expression=f"localStorage.setItem('access_token','{token}')")
    bad = 0
    for path in PAGES:
        events.clear()
        call("Page.navigate", url=BASE + path); time.sleep(5)
        text = call("Runtime.evaluate", expression="document.body.innerText", returnByValue=True)["result"].get("value", "")
        urls = {}
        problems = []
        for e in events:
            m, p = e["method"], e["params"]
            if m == "Network.requestWillBeSent": urls[p["requestId"]] = p["request"]["url"]
            if m == "Network.responseReceived" and p["response"]["status"] >= 400:
                problems.append(f"HTTP {p['response']['status']} {p['response']['url'].replace(API,'')}")
            if m == "Network.loadingFailed" and not p.get("canceled"):
                problems.append(f"FAILED {urls.get(p['requestId'],'?').replace(API,'')} {p.get('errorText')}")
            if m == "Runtime.exceptionThrown":
                problems.append("EXC " + p["exceptionDetails"].get("exception", {}).get("description", p["exceptionDetails"]["text"])[:140])
            if m == "Runtime.consoleAPICalled" and p["type"] == "error":
                problems.append("console.error " + " ".join(str(a.get("value", a.get("description", ""))) for a in p["args"])[:140])
        lowered = text.lower()
        for word in ("failed to fetch", "api error", "graph error", "unauthorized", "application error", "something went wrong"):
            if word in lowered: problems.append(f"page text: '{word}'")
        status = "OK " if not problems else "BAD"
        bad += bool(problems)
        print(f"{status} {path}  ({len(text)} chars)")
        for pr in dict.fromkeys(problems): print("     -", pr)
    print(f"\n{len(PAGES)-bad}/{len(PAGES)} pages clean")
finally:
    proc.terminate(); shutil.rmtree(prof, ignore_errors=True)
