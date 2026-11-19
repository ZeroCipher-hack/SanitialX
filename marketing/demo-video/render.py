"""Render the reel to MP4 with headless Chromium (DevTools protocol) and ffmpeg.

  python render.py [fps] [--stills t1,t2,...]   (needs: websockets, chromium or chrome, ffmpeg)
"""
import base64, json, shutil, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
from websockets.sync.client import connect

here = Path(__file__).parent
argv = sys.argv[1:]
stills = None
if "--stills" in argv:
    i = argv.index("--stills")
    stills = [float(x) for x in argv[i + 1].split(",")]
    del argv[i:i + 2]
fps = int(argv[0]) if argv else 30

chrome = shutil.which("chromium") or shutil.which("google-chrome")
port = 9333
profile = tempfile.mkdtemp(prefix="reel-chrome-")
proc = subprocess.Popen([chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                         f"--remote-debugging-port={port}", f"--user-data-dir={profile}",
                         "--window-size=1080,1920", (here / "index.html").as_uri()],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    ws_url = None
    for _ in range(60):
        try:
            tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
            ws_url = next(t["webSocketDebuggerUrl"] for t in tabs if t["type"] == "page")
            break
        except Exception:
            time.sleep(0.25)
    ws = connect(ws_url, max_size=64 * 1024 * 1024)
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

    call("Emulation.setDeviceMetricsOverride", width=1080, height=1920, deviceScaleFactor=1, mobile=False)
    time.sleep(0.8)

    def frame(t, quality=92):
        call("Runtime.evaluate", expression=f"window.render({t})")
        data = call("Page.captureScreenshot", format="jpeg", quality=quality)["data"]
        return base64.b64decode(data)

    if stills:
        out = here / "out"; out.mkdir(exist_ok=True)
        for t in stills:
            (out / f"still_{t}.jpg").write_bytes(frame(t))
        print("stills in", out)
    else:
        duration = call("Runtime.evaluate", expression="window.DURATION", returnByValue=True)["result"]["value"]
        frames = Path(tempfile.mkdtemp(prefix="reel-frames-"))
        total = int(duration * fps)
        for i in range(total):
            (frames / f"f{i:05d}.jpg").write_bytes(frame(i / fps))
        out = here / "out"; out.mkdir(exist_ok=True)
        mp4 = out / "sanitialx-demo.mp4"
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(fps), "-i", str(frames / "f%05d.jpg"),
                        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18", "-movflags", "+faststart", str(mp4)], check=True)
        shutil.rmtree(frames)
        print(mp4)
finally:
    proc.terminate()
    shutil.rmtree(profile, ignore_errors=True)
