"""Capture real product screens from the demo stack (demo_server.py + next dev on :3101)."""
import base64, json, shutil, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
from websockets.sync.client import connect

here = Path(__file__).parent
shots = here / "shots"
shots.mkdir(exist_ok=True)
BASE = "http://localhost:3101"
token = Path(tempfile.gettempdir(), "sanitialx-demo.token").read_text().strip()
req = urllib.request.Request("http://localhost:8010/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
incidents = json.load(urllib.request.urlopen(req))
inc = next((i for i in incidents if i["severity"] == "CRITICAL"), incidents[0])["incident_id"]

PAGES = [("dashboard", "/dashboard"), ("incidents", "/incidents"), ("incident", f"/incidents?id={inc}"),
         ("graph", f"/attack-graph?incident_id={inc}"), ("agents", "/agents"), ("simulations", "/simulations"),
         ("rules", "/rules"), ("reports", "/reports")]
only = set(sys.argv[1:])

chrome = shutil.which("chromium") or shutil.which("google-chrome")
profile = tempfile.mkdtemp(prefix="cap-chrome-")
port = 9444
proc = subprocess.Popen([chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                         f"--remote-debugging-port={port}", f"--user-data-dir={profile}", "about:blank"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try:
            tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
            ws = connect(next(t["webSocketDebuggerUrl"] for t in tabs if t["type"] == "page"), max_size=64 * 1024 * 1024)
            break
        except Exception:
            time.sleep(0.25)
    seq = 0

    def call(method, **params):
        global seq
        seq += 1
        ws.send(json.dumps({"id": seq, "method": method, "params": params}))
        while True:
            msg = json.loads(ws.recv())
            if msg.get("id") == seq:
                if "error" in msg:
                    raise RuntimeError(msg["error"])
                return msg["result"]

    call("Emulation.setDeviceMetricsOverride", width=1440, height=900, deviceScaleFactor=1, mobile=False)
    call("Page.navigate", url=BASE + "/login")
    time.sleep(3)
    call("Runtime.evaluate", expression=f"localStorage.setItem('access_token','{token}')")
    for name, path in PAGES:
        if only and name not in only:
            continue
        call("Page.navigate", url=BASE + path)
        time.sleep(6)
        data = call("Page.captureScreenshot", format="png")["data"]
        (shots / f"{name}.png").write_bytes(base64.b64decode(data))
        print("saved", name)
finally:
    proc.terminate()
    shutil.rmtree(profile, ignore_errors=True)
