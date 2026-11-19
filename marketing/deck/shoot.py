"""Screenshot deck slides: python shoot.py 1 4 12  -> out/slide-N.png (1920x1080)."""
import base64, json, shutil, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
from websockets.sync.client import connect

here = Path(__file__).parent
out = here / "out"; out.mkdir(exist_ok=True)
nums = [int(a) for a in sys.argv[1:]] or list(range(1, 15))
prof = tempfile.mkdtemp()
proc = subprocess.Popen([shutil.which("chromium"), "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                         "--remote-debugging-port=9666", f"--user-data-dir={prof}", "about:blank"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try:
            tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9666/json"))
            ws = connect(next(t["webSocketDebuggerUrl"] for t in tabs if t["type"] == "page"), max_size=64 * 1024 * 1024); break
        except Exception:
            time.sleep(.25)
    n = 0
    def call(m, **k):
        global n; n += 1; ws.send(json.dumps({"id": n, "method": m, "params": k}))
        while True:
            r = json.loads(ws.recv())
            if r.get("id") == n: return r.get("result")
    call("Emulation.setDeviceMetricsOverride", width=1920, height=1080, deviceScaleFactor=1, mobile=False)
    call("Page.navigate", url=(here / "index.html").as_uri()); time.sleep(2)
    for i in nums:
        call("Runtime.evaluate", expression=f"go({i-1})"); time.sleep(3.2)
        (out / f"slide-{i}.png").write_bytes(base64.b64decode(call("Page.captureScreenshot", format="png")["data"]))
        print("slide", i)
finally:
    proc.terminate(); shutil.rmtree(prof, ignore_errors=True)
