"""The upgrade path, end to end: does the port survive a code-change handover?

    PYTHONPATH=src python3 tools/upgrade_probe.py

Reproduces what happened on two live machines the day it was learned. A daemon
notices its own code changed and replaces itself — and the port must stay on
the SAME number throughout, because every live session had that number baked
into HTTPS_PROXY at exec and never re-reads it.

MEASURED, this script, incident-era code vs now:

    incident-era   PORT 45451 -> 39799   refused=134268
    now            PORT 39507 -> 39507   refused=0   ok=78685

To reproduce the failure (a control, so a green run means something):
  1. `if held_by_a_holder():` -> `if False:` in the code-change watchdog
  2. put the holder back behind `if listen_fd is None:` in `_spawn_daemon`
Both together are what was deployed at 12:57 and 13:03.

A README saying "upgrade carefully" was the first answer to this and it is not
one: a deploy is not a procedure someone follows, it is whatever the running
code does.
"""
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, "src")
from cswap_pin import proxy as pp  # noqa: E402

certdir = pathlib.Path(tempfile.mkdtemp())
pp.ensure_ca(certdir, "api.anthropic.com")

port = pp._spawn_daemon("1", "a@example.com", certdir)
if not port:
    sys.exit("daemon did not come up")
time.sleep(1.5)
state = certdir / "proxy.json"
before = json.loads(state.read_text())["pid"]
print(f"serving {port}, daemon {before}")

counts = {"ok": 0, "refused": 0, "reset": 0, "other": 0}
stop = threading.Event()


def hammer():
    while not stop.is_set():
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.sendall(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                      b"Host: api.anthropic.com:443\r\n\r\n")
            if s.recv(200):
                counts["ok"] += 1
            s.close()
        except ConnectionRefusedError:
            counts["refused"] += 1
        except ConnectionResetError:
            counts["reset"] += 1
        except OSError:
            counts["other"] += 1


threads = [threading.Thread(target=hammer, daemon=True) for _ in range(3)]
for t in threads:
    t.start()
time.sleep(1)

# THE UPGRADE: change the code on disk, exactly as `pip install` does.
src = pathlib.Path(pp.__file__)
original = src.read_text()
src.write_text(original + "\n# upgrade marker\n")
print("code changed on disk; waiting for the handover...")

deadline = time.time() + 120
while time.time() < deadline:
    time.sleep(1)
    try:
        if json.loads(state.read_text())["pid"] != before:
            break
    except Exception:
        pass
time.sleep(3)
stop.set()
for t in threads:
    t.join(timeout=3)
src.write_text(original)

after = json.loads(state.read_text())
print(f"daemon {before} -> {after['pid']}")
print(f"PORT {port} -> {after['port']}   {'OK' if after['port'] == port else 'MOVED — sessions stranded'}")
print("traffic across the upgrade:", counts)

# Is the successor under a holder?
import subprocess  # noqa: E402
out = subprocess.run(["ps", "-eo", "pid=,ppid=,command="],
                     capture_output=True, text=True).stdout
mine = [l for l in out.splitlines()
        if " -m cswap_pin.proxy" in l and str(certdir) in l]
print("processes:", len(mine))
for line in mine:
    print("  ", line.strip()[:120])

for line in mine:                       # parents first
    if "--hold-port" in line:
        try:
            os.kill(int(line.split()[0]), 15)
        except OSError:
            pass
