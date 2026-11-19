"""Debug helper: check from inside headless Chrome whether the demo API is reachable."""
import json, shutil, subprocess, tempfile, time, urllib.request
from pathlib import Path
from websockets.sync.client import connect

token = Path(tempfile.gettempdir(), "sanitialx-demo.token").read_text().strip()
prof = tempfile.mkdtemp()
p = subprocess.Popen([shutil.which("chromium"), "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-web-security", "--remote-debugging-port=9555",
                      f"--user-data-dir={prof}", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try:
            tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9555/json"))
            ws = connect(next(t["webSocketDebuggerUrl"] for t in tabs if t["type"] == "page")); break
        except Exception:
            time.sleep(.25)
    n = 0
    ev = []
    def call(m, **k):
        global n; n += 1; ws.send(json.dumps({"id": n, "method": m, "params": k}))
        while True:
            r = json.loads(ws.recv())
            if "method" in r: ev.append(r)
            if r.get("id") == n: return r
    call("Network.enable")
    call("Page.navigate", url="http://localhost:3101/login"); time.sleep(3)
    tests = ["fetch('/login').then(r=>'same-origin '+r.status).catch(e=>'same-origin ERR '+e.message)",
             "fetch('http://localhost:8011/api/v1/health').then(r=>'8010 '+r.status).catch(e=>'8010 ERR '+e.message)",
             "fetch('http://[::1]:8010/api/v1/health').then(r=>'[::1]:8010 '+r.status).catch(e=>'[::1]:8010 ERR '+e.message)",
             "fetch('http://localhost:3101/login',{mode:'no-cors'}).then(r=>'3101 '+r.type).catch(e=>'3101 ERR '+e.message)",
             "location.href+' online='+navigator.onLine"]
    for js in tests:
        print(call("Runtime.evaluate", expression=js, awaitPromise=True, returnByValue=True)["result"]["result"].get("value"))
    call("Page.navigate", url="http://localhost:8011/api/v1/health"); time.sleep(2)
    print("NAV 8011:", call("Runtime.evaluate", expression="document.body.innerText.slice(0,80)", returnByValue=True)["result"]["result"].get("value"))
    call("Page.navigate", url="http://localhost:8010/api/v1/health"); time.sleep(2)
    print("NAV 8010:", call("Runtime.evaluate", expression="document.body.innerText.slice(0,80)", returnByValue=True)["result"]["result"].get("value"))
    for e in ev:
        if e["method"] == "Network.loadingFailed":
            print("FAILED:", e["params"].get("errorText"), e["params"].get("blockedReason"), e["params"].get("corsErrorStatus"))
finally:
    p.terminate()
