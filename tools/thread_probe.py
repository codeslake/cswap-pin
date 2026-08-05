"""Does a connection cost a thread? Measure the daemon FROM OUTSIDE.

    PYTHONPATH=src python3 tools/thread_probe.py

WHY THIS EXISTS AS A SCRIPT rather than a test. The property it measures —
"a connection is not a thread" — is the one the host-a outage turned on: the
pin served 27,491 threads / 44,121 FDs in 40 minutes when its upstream hop
died, load reached 16,483 on a 48-core box, and the mechanism was one OS
thread per accepted connection. Measured here before the fix:

    idle          4 threads
     50 conns ->  54 threads
    150 conns -> 154 threads
    300 conns -> 304 threads     exactly 1:1

and after:

     50 conns ->   5 threads
    150 conns ->   5 threads
    300 conns ->   5 threads

The pytest case (`case_connections_do_not_become_threads`) cannot tell those
two apart — reverting the fix leaves it green while this reports 305 against
5. Until that is understood, THIS is the instrument and the test is a smoke
check. Run it after any change to the pump, the accept path, or the tunnel
handlers.

Two traps it exists to avoid, both measured:
  - counting IN-PROCESS is useless: `threading.active_count()` also counts
    the load generator's own opener threads, the same order of magnitude as
    the thing being measured. It reported grew=0 while every connection had
    a thread.
  - pointing the tunnel at a real host (github.com) measures DNS and WAN
    latency instead of the pump, and most connections never reach the steady
    state at all.
"""
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

# The tunnel's far end: accepts and HOLDS, which is a real upstream mid-session.
far = socket.socket()
far.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
far.bind(("127.0.0.1", 0))
far.listen(512)
far_port = far.getsockname()[1]


def _accept_forever():
    kept = []
    while True:
        try:
            conn, _ = far.accept()
            kept.append(conn)          # hold, or the tunnel closes at once
        except OSError:
            return


threading.Thread(target=_accept_forever, daemon=True).start()

port = pp._spawn_daemon("1", "a@example.com", certdir)
if not port:
    sys.exit("the daemon did not come up")
time.sleep(1)
pid = int(pp.read_daemon_state(certdir)["pid"])


def threads_of(p: int) -> int:
    try:
        with open(f"/proc/{p}/status") as fh:
            for line in fh:
                if line.startswith("Threads:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return -1


print(f"daemon port {port}, far end {far_port}")
print("idle:", threads_of(pid), "threads")

held, lock = [], threading.Lock()


def hold():
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(f"CONNECT 127.0.0.1:{far_port} HTTP/1.1\r\n"
                  f"Host: 127.0.0.1:{far_port}\r\n\r\n".encode())
        if b"200" not in s.recv(200):
            return
        with lock:
            held.append(s)
        s.recv(65536)          # park on an OPEN tunnel: the steady state
    except OSError:
        pass


for target in (50, 150, 300):
    deadline = time.time() + 20
    while time.time() < deadline and len(held) < target:
        for t in [threading.Thread(target=hold, daemon=True)
                  for _ in range(target - len(held))]:
            t.start()
        for _ in range(40):
            if len(held) >= target:
                break
            time.sleep(0.05)
    time.sleep(0.7)
    print(f"{len(held):4d} open tunnels -> {threads_of(pid):4d} threads")

for s in held:
    try:
        s.close()
    except OSError:
        pass
time.sleep(2)
print("after close:", threads_of(pid), "threads")

try:
    os.kill(pid, 15)
except OSError:
    pass
far.close()
