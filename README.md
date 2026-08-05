# cswap-pin

Keep Claude Code's **Remote Control** and **Artifacts** on one account while
inference keeps following [`cswap`](https://github.com/realiti4/claude-swap)'s
account swap.

## The problem

cswap swaps the on-disk credential, so *everything* follows the swap —
including two things that are not inference and that you usually want to stay
put:

- **Remote Control** — a session's owner is fixed at creation by whichever
  bearer created it. Swap accounts and the phone/web loses the session; stale
  "ghost" sessions pile up on the old account.
- **Artifacts** — owned by the publishing bearer. After a swap a republish
  403s and the artifact "disappears" from the account you are logged into.

Claude Code resolves all of these through one credential accessor and has no
per-operation token selector, so splitting auth *per operation inside one
session* means intercepting the requests.

## How it works

A local MITM forward proxy that swaps the `Authorization` bearer on exactly
the routes whose server-side ownership is decided by it, and passes everything
else — `/v1/messages` above all — through untouched.

```
claude session
  HTTPS_PROXY ─► cswap pin proxy ──► (whatever HTTPS_PROXY was already set) ──► api.anthropic.com
                   swaps bearer on: /v1/code/sessions*, /v1/sessions/*,
                                    /api/frame/*, /v1/ultrareview/*
                   passes through:  /v1/messages, /api/oauth/usage, everything else
                   NEVER swapped:   .../worker/*, .../client/presence
```

Inference keeps billing whichever account cswap has swapped onto. Only the
claude.ai-side assets are pinned.

Two exceptions inside the pinned prefix are worth naming, because both were
learned by breaking them:

- **`/worker/*`** carries the session's own channel credential, not an OAuth
  bearer. Swapping it makes the server reject every worker call and leaves
  Remote Control in a reconnect loop.
- **`/client/presence`** is *registration*, not ownership: it tells the server
  which process is attached and should receive events. Swapped, the server
  registers the pinned account while the process actually listening belongs to
  the active one — so inbound has nobody to reach. It returns `200` either way,
  which is what made it hard to find.

### A wrong guess cannot cost you a session

Route classification used to be a single point of *permanent* failure. Claude
Code treats `401/403/404` as terminal — its SSE transport sets `state="closed"`
and never reconnects — so one misrouted swap ended that session's Remote
Control for the life of the process (measured: 26 such responses severed four
sessions that were still running hours later).

Since 0.1.1 the proxy holds the response before any byte reaches the client,
and when the *swap* is what was refused it re-sends the request exactly as it
arrived. "Wrong about this route" degrades to "this request went out unpinned",
which is the failure mode everything else here is already built to tolerate.

## Install

```bash
uv tool install 'claude-swap[pin]'      # or: pipx install 'claude-swap[pin]'
```

The pin is an optional extra of claude-swap, not a standalone tool: it reads
cswap's account store and rewrites the config cswap already manages. Installing
`cswap-pin` on its own does nothing useful.

### Upgrading a machine that is already serving

**The upgrade itself runs the OLD code.** A daemon notices its own code
changed on disk and recycles — using the handover its own version implements,
not the one you are installing. So a fix to that path cannot fix the handover
that installs it, and each machine has exactly one unsafe transition.

Measured on two machines the day this was learned: the outgoing daemon handed
its listening socket to a successor, the successor's holder found the port
still held and served on a fresh one instead, and `.claude.json` followed it
there. Every session that had the old number baked in at exec got
`ConnectionRefused` until a human noticed.

So do it deliberately rather than letting the watchdog do it:

```bash
uv pip install --python <tool-python> --upgrade cswap-pin   # 1. install
cswap pin --get_port                                        # 2. note the port
# 3. retire the running holder (its daemon goes with it)
kill -TERM "$(pgrep -f 'cswap_pin.proxy --hold-port' | head -1)"
# 4. put the NEW code on the port the config names
python -m cswap_pin.proxy --hold-port <port> <account> <email> <certdir> &
```

Then check that port answers before touching the next machine. `cswap pin
--ensure` repairs the wiring if the window left it empty.

## Use

```bash
cswap pin 2          # RC / artifacts / ultrareview → account 2
cswap pin            # show the current pin
cswap pin --clear    # remove it
```

The pinned account is re-read per request, so `cswap pin <other>` takes effect
under a live daemon — no session restart. The one thing a re-pin cannot move is
a Remote Control session that is **already open**: the server fixed its owner
when it was created, so reconnecting inside it is what mints a new one under
the new pin.

## The port

Nothing is hardcoded. The first daemon binds port `0` — the OS picks — and
records what it got in `<cswap-backup>/pin-proxy/proxy.json`. Later starts try
to reclaim that number and fall back to another ephemeral port if anything else
already holds it, so a port you are using is never taken from you.

Reclaiming matters because a running session's `HTTPS_PROXY` is fixed when it
execs: coming back on a different port would leave that session dialling an
address nothing answers, and its requests would then go out *unpinned* rather
than fail loudly.

### The port outlives the daemon

The socket is bound by a **holder** — a process that never serves a request.
It binds, starts the daemon, and waits. The daemon accepts on that inherited
descriptor, so there is no relay and no extra hop: the connection the client
makes is the connection the daemon serves.

That is what makes a crash survivable. A planned restart already keeps the
port (the outgoing daemon hands its socket down), but a `kill -9`, an OOM
kill or a segfault skips every cooperative step — and an unowned port is
permanent for a live session, whose `HTTPS_PROXY` was fixed at exec.
Measured: three `kill -9`s of the daemon while hammering the port, `refused=0`
and a new pid on the same port each time.

The holder reads the daemon's exit rather than guessing:

| exit | meaning | what the holder does |
| :-- | :-- | :-- |
| `0` | idle teardown — it meant to go | release the port, do not respawn |
| `75` | `SIGTERM` under a holder: a redeploy | restart at once, same socket |
| other | killed or crashed | restart on a 0.25s → 5s ladder |

`CSWAP_PIN_SELF_HEAL=off` turns the restart off, for when you are debugging
the daemon and a respawner fighting you is worse than a dead port.

A redeploy is the same story from the other side. Under a holder the daemon
does not hand its socket to a successor — it exits `75` and lets the holder
put the new code on the socket it already owns. Handing the port out of the
holder is what left this machine's pin unwired for 76 minutes while every
component reported healthy.

## A connection is not a thread

An upstream that accepts and never answers used to cost one OS thread per
connection, and a client that retries forever opens them faster than they
drain. Measured on a 48-core box: **27,491 threads / 44,121 FDs in 40
minutes**, load 16,483, rescued by hand.

Connections are multiplexed on one selector instead. Measured with
`tools/thread_probe.py`, idle CONNECT tunnels against a local upstream:

| open tunnels | before | after |
| --: | --: | --: |
| 50 | 55 threads | 5 |
| 150 | 155 threads | 5 |
| 300 | 305 threads | 5 |

A ceiling was tried first and removed: it turns the 257th retry into a
refused connection and leaves the coupling in place.

### Asking for a specific port

```bash
cswap pin --get_port          # what it is serving right now (for scripts)
cswap pin --set_port 41234    # serve there from the next daemon start
cswap pin --set_port 0        # back to dynamic: the kernel picks
```

A port you set outranks the reclaim above — it is a standing instruction,
where the reclaim is only about keeping live sessions attached. It takes
effect on the next daemon start, not immediately: moving the port under a
running session would strand it, since its `HTTPS_PROXY` was fixed at exec.

If the port you asked for is taken, the pin serves on another one rather than
refusing to start, and says so in `pin-proxy/daemon.log`.

**`CSWAP_PIN_PORT` is not a setting.** The pin writes it into `.claude.json`
as its own marker and Claude Code applies that block at boot, so inside a
pinned session it already holds the running daemon's port. Exporting it
changes nothing; use `--set_port`.

## Requirements

- Python 3.10+
- [`claude-swap`](https://github.com/realiti4/claude-swap) — a peer, not a
  dependency: this package is loaded *by* it (see `src/cswap_pin/_host.py` for
  the exact surface it borrows)
- `cryptography` (installed automatically) for the MITM CA

## Running the tests

```bash
uv sync --group dev                 # pytest, pytest-xdist, and the host
S="$(mktemp -d)" && HOME="$S" XDG_DATA_HOME="$S/.local/share" \
  uv run python -m pytest tests -q
```

**Redirect `HOME` and `XDG_DATA_HOME`.** The suite drives real cert dirs,
daemon state and config wiring; a run against your own `HOME` will rewrite
`~/.claude.json`, publish a test CA into `~/.claude/ca-trust.d/`, and touch
the account store. `tests/conftest.py` redirects all of it per test, but the
env vars are the belt to that suspenders — they are what the child processes
the suite spawns obey.

**`pytest-xdist` is required, not optional.** `addopts = "-n 4"` in
`pyproject.toml` runs the suite on 4 workers (12.2s → ~5.0s, measured; more
workers do not help — the floor is the single longest test). A pytest without
xdist refuses the flag rather than ignoring it, so the suite will not start.

For a serial repro of a failure, add `-n 0`: xdist gives no live output and
truncates tracebacks it cannot attribute to a worker.

One pytest test runs many `case_*` methods (`run_cases` in `conftest.py`), so
60 collected tests carry 321 cases. A failure names both: `Class::case_name`.

## Why a separate package

Upstream did not want a MITM proxy shipped inside claude-swap itself and asked
for a companion distribution exposed through an optional extra. See
[realiti4/claude-swap#198](https://github.com/realiti4/claude-swap/issues/198).

## Trust

The proxy generates its own CA to re-sign `api.anthropic.com` and names it in
`NODE_EXTRA_CA_CERTS`. Node accepts exactly one file there, so an existing CA
(a corporate MITM, another local proxy) is **merged**, never replaced —
otherwise the session silently loses trust in every host the other proxy
re-signs.

**The proxy does not authenticate its callers, deliberately.** It listens on
`127.0.0.1` only, so the population it could turn away is other processes
running *as you* — and an earlier version did exactly that, with a secret file
in the cert dir. That defended against nobody: any process able to reach the
port could also read a `0600` file in your own home. What it did cost was real,
because a session's `HTTPS_PROXY` is fixed when it execs and cannot be updated
in place: arming the credential instantly `407`'d every session that had
started before it existed.

So the honest boundary is the loopback interface plus your user account, not a
credential. If you share a machine with logins you do not trust, do not run
this — the pinned account's token is reachable by anything that can reach the
port.

## License

MIT
