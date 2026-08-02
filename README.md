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

## Requirements

- Python 3.10+
- [`claude-swap`](https://github.com/realiti4/claude-swap) — a peer, not a
  dependency: this package is loaded *by* it (see `src/cswap_pin/_host.py` for
  the exact surface it borrows)
- `cryptography` (installed automatically) for the MITM CA

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
