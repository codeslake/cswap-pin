# cswap-pin

Keep Claude Code's **Remote Control** and **Artifacts** on one account while
inference keeps following [`cswap`](https://github.com/realiti4/claude-swap)'s
account swap.

## Quick start

1. Install (the commit is tagged `pin-install-85764e7`). This command is the
   one place the verified pair of versions is stated: the host commit and the
   `cswap-pin` release it was checked with.

   ```bash
   uv tool install --force --python 3.12 \
     "claude-swap[pin] @ git+https://github.com/codeslake/claude-swap@85764e77dc63c02f35caffdf64ddcc5cc61ea0dd" \
     --with cswap-pin==0.1.338
   ```

2. Log in with `claude`, then add that account to cswap with `cswap add`.
   `cswap list` shows the number N it was given.
3. `cswap pin N`, from a plain shell, never from inside a pinned Claude Code
   session (that shell already carries the pin as its `HTTPS_PROXY`, and the
   pin would record itself as its own upstream). If you reach the internet
   through a proxy, pin with it exported:
   `HTTPS_PROXY=http://127.0.0.1:<port> cswap pin N`.
4. Run `cswap pin --ensure >/dev/null 2>&1 &` on every `claude` launch: as this
   one line in `~/.bashrc` or `~/.zshrc` for hand launches, and in your
   `CLAUDE_CODE_PROCESS_WRAPPER` script too if you use one.

   ```bash
   claude() { (cswap pin --ensure >/dev/null 2>&1 &); command claude "$@"; }
   ```

If it breaks: `cswap pin --clear`. Everything below is reference.

## Before you start, and if it breaks

Pinning rewrites files Claude Code reads at startup (every one is listed under
[What the pin writes](#what-the-pin-writes)). This is the full way back.

**`cswap pin --clear` is the undo**, and it works even when the `cswap-pin`
package is broken or gone. It:

- removes the `env` keys the pin added to `.claude.json` (`HTTPS_PROXY`,
  `https_proxy`, `ALL_PROXY`, `all_proxy`, `NODE_EXTRA_CA_CERTS`, `CSWAP_PIN_PORT`) and puts
  back any value they replaced, so a proxy you had set before comes back;
- points `oauthAccount` in the same file back at the account you are logged in
  as;
- drops the pin record from cswap's `settings.json`, unless that file is
  shared across machines (below).

It prints `Unpinned the cloud account` (or `No cloud account pinned`) and exits
0. When Claude Code is holding the config lock it says `re-run once it frees
up` and exits 1; run it again.

**A settings file shared across machines.** When `<data>/settings.json` is a
symlink (for example into a dotfiles repo that several machines link), the pin
record in it belongs to all of them, so `--clear` unpins THIS machine only. It
unwires `.claude.json`, leaves the shared record alone and writes
`<data>/pin-cleared`; the other machines keep their pin, and so does the shared
file you commit. `cswap pin <account>` removes `pin-cleared` and pins this
machine again. With no pin recorded there is nothing to keep, so `--clear`
writes no `pin-cleared` and a pin recorded later from another machine reaches
this one. `cswap pin --clear --everywhere` drops the shared record, for
every machine that links it. A `cswap pin <account>` that fails puts the shared
record, and this machine's `pin-cleared`, back as they were. This needs a claude-swap that has the matching
support; with an older one `--clear` drops the record from the shared file as
before.

What it does not undo:

- `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` are deleted from
  that `env` block whenever the pin wires it, and no copy is kept, because each
  of them replaces a trust store instead of adding to it. Set them again
  yourself if you had them.
- The proxy keeps running. A session that is already open had the pin's port
  fixed in its environment when it started, so it keeps going through the
  proxy, now unpinned, and stopping the proxy would cut it. So stop the proxy
  (below) once the last pinned session has closed.

**By hand, when `cswap` itself will not run.** `<data>` below is cswap's data
directory: `~/.local/share/claude-swap` on Linux (`$XDG_DATA_HOME/claude-swap`
when that is set), `~/.claude-swap-backup` on macOS.

1. Find the receipt for your config: `<data>/pin-wiring/<key>.json`, where
   `<key>` is the first 16 hex digits of the SHA-256 of the config's absolute
   path.

   ```bash
   printf %s "$HOME/.claude.json" | sha256sum | cut -c1-16    # macOS: shasum -a 256
   ```

2. In `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json` if you use that),
   delete from `env` every key the receipt lists under `_cswapPinWiredKeys`,
   then add back every key and value under `_cswapPinWiredKeysSaved`. An older
   cswap-pin kept those two keys at the top level of `.claude.json` instead;
   if they are there, use them and then delete them.
3. Delete the receipt.
4. Only now, delete `pinnedEmail` and `pinnedOrganizationUuid` under
   `remoteControl` in `<data>/settings.json`. The order matters: while the
   wiring is still there, the next `cswap pin --ensure` rebuilds a missing
   record from it.
5. If `oauthAccount` in `.claude.json` still names the pinned account, switch
   to (or log in as) the account you want; that rewrites it.

**Stopping the proxy**, once no session started under the pin is still open
(each one would lose its connection):

```bash
pkill -HUP  -f 'cswap_pin.proxy --standby'     # the standby ignores TERM and INT
pkill -TERM -f 'cswap_pin.proxy --hold-port'   # the holder stops its daemon, then frees the port
pgrep -f cswap_pin.proxy                       # should print nothing
```

The standby goes first because a standby whose holder is gone puts a new holder
back on the port (see [When the holder and its daemon die
together](#when-the-holder-and-its-daemon-die-together)). A pid still listed
afterwards is a daemon running without a holder; `kill` it.

**Removing it completely.** `--clear` undoes the pin; these also remove what
you and the pin added around it:

1. Take out the `cswap pin --ensure` line (the rc `claude()` function, a
   launcher or `CLAUDE_CODE_PROCESS_WRAPPER` script), and the
   `CLAUDE_CODE_SHELL_PREFIX` setting or rc line from [Keeping the programs
   Claude Code starts off the pin](#keeping-the-programs-claude-code-starts-off-the-pin)
   if you added one.
2. Run `cswap pin --clear`. With `CLAUDE_CONFIG_DIR` set there are two
   configs, `~/.claude.json` and `$CLAUDE_CONFIG_DIR/.claude.json`, each with
   its own receipt; `--clear` clears both when `CLAUDE_CONFIG_DIR` is exported
   in its own environment, and only `~/.claude.json` from a shell without it.
3. Stop the proxy as above, once the last pinned session has closed.
4. Delete `ca-trust.d/cswap-pin.pem` under `~/.claude` (and under
   `$CLAUDE_CONFIG_DIR`) if it is there, and `<data>/pin-proxy/`. The pin's CA
   is a full CA (`CA:TRUE`, no name constraints) and its private key stays in
   `pin-proxy/ca.key` until you delete it.

**Back to upstream claude-swap.** Run `cswap pin --clear` first, while this
build is still installed: upstream has no `cswap pin` and nothing that removes
a wiring. Then reinstall from PyPI, naming the release you want:

```bash
uv tool install --force --python 3.12 claude-swap==<version>    # e.g. 0.26.0
```

## Prerequisites

- **macOS or Linux.** The pin needs POSIX file locks and FIFOs; on Windows
  `cswap pin` refuses.
- **Not root, unless inside a container.** As root outside one, `cswap pin`
  refuses to run, and `cswap pin --ensure` exits 0 having done nothing.
- **[uv](https://docs.astral.sh/uv/)**, and **git** for uv to fetch the host
  from GitHub. `pipx` should take the same arguments, but this was verified
  with `uv` only.
- **Python 3.12 or newer** for the tool. That is claude-swap's floor;
  `cswap-pin` on its own accepts 3.10, but it never runs on its own. uv can
  supply one (see [Install](#install)).
- **Claude Code, logged in with a claude.ai (OAuth) account that cswap
  manages**: `cswap list` has to show it. An API-key account cannot be pinned,
  because Remote Control and Artifacts need an OAuth bearer.
- **If you reach the internet through a proxy**: its URL, exported as
  `HTTPS_PROXY` in the shell where you run `cswap pin N`. See
  [Proxy chains](#proxy-chains).
- **If anything on that path re-signs TLS** (a local caching or inspecting
  proxy, a corporate TLS inspector): its CA certificate as a PEM file,
  exported as `NODE_EXTRA_CA_CERTS` in the same shell.

## Install

The pin is an optional extra of claude-swap, not a standalone tool: it reads
cswap's account store, rewrites the config cswap already manages, and the
`cswap pin` command itself lives in the host. Installing `cswap-pin` on its own
does nothing useful.

**The extra is not on PyPI.** `claude-swap` 0.26.0 publishes only the
`menubar` extra, so `uv tool install 'claude-swap[pin]'` installs a host with
no pin in it and exits 0 with a warning. Install the host from the fork that
carries the extra, at a fixed commit, with this package beside it: the
command in [Quick start](#quick-start) step 1, which is the one place the
verified versions are stated.

```console
$ cswap --version
cswap 0.27.0b1
$ cswap pin
No cloud account pinned
```

- **A commit, not a branch.** The fork's `integration` branch is force-pushed,
  so a branch name installs whatever it points at that day. The commit above
  is tagged `pin-install-85764e7`, so it stays fetchable after `integration`
  is force-pushed; the URL keeps the full SHA because a tag can move. When you
  upgrade, change the commit and the `cswap-pin` version together; the pair in
  Quick start is the one this README was checked against, and the next
  verified pair is announced there.
- **`--python 3.12`**, because claude-swap needs 3.12 or newer and without the
  flag uv takes whichever interpreter it finds first. Under a narrowed `PATH`
  that was a 3.11, and the install failed. With the flag uv uses a 3.12 it
  finds, or downloads one (under `env -i` it downloaded 3.12.14 and the line
  above installed cleanly). Any 3.12+ works: `--python 3.13`, or a path to an
  interpreter.
- **Already have claude-swap as a uv tool?** If its interpreter is 3.12 or
  newer, reuse it, so whatever already runs `cswap` keeps the same runtime:

  ```bash
  grep -E '^(home|version_info)' "$(uv tool dir)/claude-swap/pyvenv.cfg"
  ```

  and pass `--python <home>/python3`.
- **`cryptography`** (for the pin's CA) is installed into the tool's own
  environment as a dependency of `cswap-pin`. A uv tool never uses the system
  Python or its packages, so there is nothing to install there.
- **`--force`** replaces an existing `claude-swap` tool, whatever it was
  installed from.

**Do not run a plain `uv tool install 'claude-swap[pin]'` over this**,
including the one `cswap pin` prints when it cannot import `cswap-pin`. With
`--force` it replaces the fork with PyPI's 0.26.0, which has no pin (measured:
`cswap 0.26.0`, and a warning that there is no extra named `pin`). Without
`--force` it keeps the installed fork but rewrites the tool's record of where
it came from to PyPI, so a later upgrade comes from there. `cswap upgrade` on
its own is safe: it runs `uv tool upgrade claude-swap`, which keeps the pinned
commit (measured: `Nothing to upgrade`).

**Do not run a plain `uv tool install claude-swap` over it either**, the line
a bootstrap script usually carries. Measured with uv 0.12.18 over the install
line in Quick start: it exits 0, keeps the fork's code (`cswap 0.27.0b1`),
rewrites the tool's record to PyPI's `claude-swap`, and uninstalls `cswap-pin` and
`cryptography` from the tool. The pin can then no longer respawn its daemon,
and the first `cswap pin --ensure` that finds the daemon dead removes the
wiring. Re-install only with the `git+...@<sha>` line, and make a bootstrap
script install claude-swap only when it is missing:

```sh
[ -d "$(uv --color never tool dir)/claude-swap" ] || uv tool install -q claude-swap
```

`--color never` because uv colours even piped output when `FORCE_COLOR` is set,
and Claude Code sessions export it; the path then carries escape codes and the
test never matches.

**On a machine running claude-swap from a checkout, keep it editable.** Any
`uv tool install --force` replaces the tool, extras included, so pointing one
at an editable install swaps your checkout out, and a line without the `pin`
extra also drops `cswap_pin` from the tool env. The daemon already running
survives (its code is in memory) but every successor it spawns dies with
`ModuleNotFoundError`, which is invisible until something tries to restart it:

```bash
uv tool install --force --python 3.12 --editable '.[pin]'     # from the checkout
```

### Upgrading a machine that is already serving

Nothing to do beyond the Quick start install line with the new commit and
version; the running daemon notices its own code changed and replaces itself,
on the same port, without dropping anything.
Measured across a real code change on a live daemon: **68,168 requests, 0
refused, 0 reset, 0 unanswered**, same port, new pid.

**`refused=0` on its own is not that claim**, and it is worth saying because
this package spent several releases believing it was. The port is held by a
process that outlives the daemon, so during a handover it stays bound and
every arrival queues in the backlog: a probe that only counts
`ConnectionRefusedError` is structurally incapable of failing, however long
nobody is behind the socket. One machine drained for 30 seconds that way —
`refused=0` the whole time, and 30 requests died on a 3s timeout with no
reply. The numbers above count a request that connects and is never answered
as a failure, which is what it is to a session.

This used to need a procedure, and a procedure is not an answer — a deploy is
not something someone follows, it is whatever the running code does. Two
machines taught that: both moved their port mid-upgrade (53749 → 54264,
36301 → 45357) and stranded every session that had the old number baked in at
exec, because the successor came up with no holder above it. Every spawn now
lands under one.

## Proxy chains

The pin is one more hop in front of whatever your machine already uses to
reach `api.anthropic.com`:

```
claude ──► pin (127.0.0.1:<port>) ──► first hop ──► next hop ──► api.anthropic.com
```

It learns the chain from the environment of the command that pins, `cswap pin
N` (and `cswap run`). Run that command from a plain shell, never from inside a
pinned Claude Code session: the shell there already carries the pin as its
`HTTPS_PROXY`, and the pin would record itself as its own upstream. Export these
in that plain shell:

- `HTTPS_PROXY` (or `https_proxy`): the **first** hop, as a URL. `http://`,
  `https://` and `http://user:password@host:port` all work.
- `NODE_EXTRA_CA_CERTS`: the CA certificate (a PEM file) of a hop that
  re-signs TLS.

What it learned goes into `upstream.json`, in the directory `cswap pin
--get_certdir` prints (the first successful pin creates it):

| key | holds | learned from |
| :-- | :-- | :-- |
| `proxy` | the first hop | `HTTPS_PROXY` / `https_proxy` when you pinned |
| `ca` | that hop's CA | `NODE_EXTRA_CA_CERTS` when you pinned |
| `next` | the hop behind the first one | the first hop's own `GET /health`, asked when you pin and again later by the running daemon. Only a loopback `http://` hop is asked, and only a JSON answer naming its `https_proxy` counts |
| `cache` | the first hop's `host:port`, when it answered `/health` with JSON | the same `GET /health`. Absent otherwise. Read only by the [opt-in shell prefix](#keeping-the-programs-claude-code-starts-off-the-pin), which then hands over `next` (or nothing), never the first hop |

The daemon re-reads this file on every connection, so an edit takes effect
without a restart. The `ca` is merged with the pin's own CA into
`ca-bundle.pem`, and that bundle is the `NODE_EXTRA_CA_CERTS` the pin hands
Claude Code, so a session trusts both.

**An unset variable never clears the record.** `cswap pin` usually runs in a
plain shell that cannot see the proxy a launcher gives Claude Code, so a
missing `HTTPS_PROXY` keeps what an earlier pin recorded. To take a hop out,
edit `upstream.json` and set `proxy` (and `next`) to `""`.

Ports below are examples (8118 is privoxy's default):

| your chain | export before `cswap pin N` | `upstream.json` then holds | when a hop dies |
| :-- | :-- | :-- | :-- |
| none: direct to the internet | nothing (`unset HTTPS_PROXY https_proxy`) | an empty `proxy` | nothing to fall through; the pin dials direct |
| privoxy, or any plain forwarding proxy | `HTTPS_PROXY=http://127.0.0.1:8118` | `proxy`; no `next`, since privoxy answers `/health` with a 400 | `503` until it is back; set `CSWAP_PIN_ALLOW_DIRECT=1` only when direct internet works, to dial direct instead |
| a local TLS-intercepting proxy that dials out itself | `HTTPS_PROXY=http://127.0.0.1:<its port>` and `NODE_EXTRA_CA_CERTS=<its CA>` | `proxy`, `ca` | `503` until it is back; set `CSWAP_PIN_ALLOW_DIRECT=1` only when direct internet works, to dial direct instead |
| a local intercepting proxy that reports its upstream on `/health`, in front of privoxy | the same two, for the intercepting proxy: the first hop, not privoxy | `proxy`, `ca`, and `next` (privoxy) once the intercepting proxy's `/health` names it | falls through to privoxy; `503` only while both are down |
| any other TLS-intercepting hop: a corporate inspector, a remote proxy | `HTTPS_PROXY=<its URL>`, and `NODE_EXTRA_CA_CERTS=<its root CA>` unless your system trust store already has it | `proxy`, `ca`; no `next`, because only loopback hops are asked | `503` until it is back |

**`next` is learned only from the first hop's `/health`.** It is recorded
only when that hop's `GET /health` returns JSON naming its `https_proxy`. A
generic intercepting proxy has no such endpoint, so in front of privoxy it
leaves no `next`, and a dead first hop gives `503` instead of falling through.
Then set `next` in `upstream.json` by hand (e.g.
`"next": "http://127.0.0.1:8118"`); it survives re-pins, because a pin that
learns no `next` keeps the recorded one.

**A dead hop is never bypassed silently.** The pin tries `proxy`, then `next`,
for 2.5 s, then answers Claude Code `503 Service Unavailable` with
`Retry-After: 2`, and Claude Code retries. While any hop is recorded it does
not fall back to a direct dial: where only the proxy may reach the internet, a
direct dial fails, and on the network this was measured on it answered 403,
which Claude Code shows as "Please run /login". If a direct dial from your
machine does reach the internet, `CSWAP_PIN_ALLOW_DIRECT=1` in the daemon's
environment restores the direct fallback (see [The port](#the-port)). With no
hop recorded at all, direct is simply the route. [Falling through a dead
hop](#falling-through-a-dead-hop) says why `next` is asked while the first hop
still answers.

**A chain recorded outer-first is fixed by a re-pin.** If the first pin ran
from a shell exporting the outer egress proxy, `upstream.json` holds it as
`proxy` and the cache proxy in front of it is skipped. Re-pin with `cswap pin
N` from the shell that exports the inner cache proxy: when that hop reports
its own upstream as `https_proxy` on `GET /health`, and the recorded hop
answers that request with a 4xx, the pin re-records the chain inner first.
Only a re-pin, or a `cswap run`, from that shell does this; `--ensure` and
`heal` never re-stamp a non-empty record, and fill an empty one (T2753).

**Which certificates the pin itself checks.** Through a loopback hop the pin
does not verify `api.anthropic.com`'s certificate: it trusts the local hop, the
same way Claude Code trusts that hop's CA. Through a remote hop, or direct, it
verifies against the system trust store plus the `NODE_EXTRA_CA_CERTS` in its
own environment, which it inherits from whatever started it: `cswap pin N`,
`cswap run`, or `cswap pin --ensure`. So for a remote intercepting hop whose CA
is not in the system store, export `NODE_EXTRA_CA_CERTS` in all three places,
the launch hooks in [Launching `claude`](#launching-claude) included.

### Using cswap-pin and cache-fix together

1. Run cache-fix in forward-proxy mode as a service:
   `CACHE_FIX_FORWARD_PROXY=on cache-fix-proxy install-service`. It listens on
   `127.0.0.1:9801` unless `CACHE_FIX_PROXY_PORT` says otherwise.
2. From a plain shell, not from inside a pinned session (there the shell
   already carries the pin as `HTTPS_PROXY` and the pin would record itself as
   its own upstream), pin through it:
   `HTTPS_PROXY=http://127.0.0.1:9801 NODE_EXTRA_CA_CERTS=<a file holding cache-fix's ca.pem and, behind a TLS-inspecting proxy, your corporate root> cswap pin <N>`.
3. Add only the pin's `claude()` line to your shell rc (the one in [Launching
   `claude`](#interactive-shells)). The pin writes its proxy and CA into the
   `env` block of `~/.claude.json`, which overrides cache-fix's client recipe
   for those keys, so do not also add cache-fix's client recipe or use
   `--remote-control`.
4. To keep the programs Claude Code starts (hooks, MCP servers, Bash commands)
   off the pin, see [Keeping the programs Claude Code starts off the
   pin](#keeping-the-programs-claude-code-starts-off-the-pin).

## Use

**An account has to exist first.** The pin points at one of cswap's managed
accounts by number, so on a machine that has none, the first command in this
section is the one that fails:

```console
$ cswap pin 2
Error: Account-2 does not exist
$ cswap list
No accounts are managed yet.
No active Claude account found. Please log in first.
```

Log in with `claude`, add that account with `cswap add` (`cswap list` shows
the numbers), then, in a plain shell (never inside a pinned Claude Code
session) that exports your chain (see [Proxy chains](#proxy-chains)):

```bash
cswap pin 2          # RC / artifacts / ultrareview → account 2
cswap pin            # show the current pin
cswap pin --state    # OK / NOT-OK / UNKNOWN on stdout, the detail on stderr, exit 0
cswap pin --clear    # remove it
```

The pinned account is re-read per request, so `cswap pin <other>` takes effect
under a live daemon — no session restart. The one thing a re-pin cannot move is
a Remote Control session that is **already open**: the server fixed its owner
when it was created, so reconnecting inside it is what mints a new one under
the new pin.

## Launching `claude`

`cswap pin N` writes the pin into `.claude.json`, which Claude Code applies at
startup, so every `claude` started afterwards goes through the pin with no
wrapper. What can go stale is the daemon behind that address: a crash, a
reboot, an upgrade that lost a dependency. `cswap pin --ensure` repairs it
before a launch. It restarts a dead daemon on the same port or, if it cannot,
removes the wiring so the session starts unpinned instead of dialling a port
nothing answers. It prints nothing, always exits 0, and does nothing when no
pin is set.

**The trigger is every `claude` launch**, in whatever every launch passes
through: a shell function for hand launches, and the script
`CLAUDE_CODE_PROCESS_WRAPPER` names, so the daemon and background sessions
Claude Code spawns itself are covered too.

**Run it in the background, never in front of the launch.** It returns in
about 70 ms when nothing is pinned (measured; that is interpreter start-up) and
is cheap on a healthy pin (a state read and one loopback connect). With a dead
daemon it can take tens of seconds: up to 10 s waiting for the spawn lock, up
to 10 s for a new daemon to come up, then up to three 1 s probes of the old
port before it unwires. A launch that starts before it finishes uses whatever
wiring was there; a daemon that comes back comes back on the same port, so
that session picks it up.

`cswap run N` needs none of this: it repairs the pin itself before it execs
Claude Code.

### Interactive shells

The same line works in `~/.zshrc` and in `~/.bashrc`:

```bash
claude() { (cswap pin --ensure >/dev/null 2>&1 &); command claude "$@"; }
```

The subshell keeps the background job out of your shell's job table, so there
are no `[1] Done` lines.

### Unattended launchers

A bot, a daemon, a systemd unit, a cron job or a `CLAUDE_CODE_PROCESS_WRAPPER`
script reads no rc file, so put the line in the launcher, before it execs
Claude Code:

```sh
#!/bin/sh
cswap pin --ensure >/dev/null 2>&1 &
exec "$@"        # or: exec claude ...
```

A daemon that `--ensure` starts inherits this launcher's environment. It needs
`cswap` on the launcher's `PATH` (`uv tool dir --bin` prints where uv put it)
and, if your chain needs them, the same `NODE_EXTRA_CA_CERTS` and
`CSWAP_PIN_ALLOW_DIRECT` you pin with.

**Not from a systemd service's `ExecStart`.** A daemon that `--ensure` starts
there joins that unit's cgroup, and with the default `KillMode=control-group`
it dies when the unit stops, freeing the port every pinned session is wired
to. Run the line from a launcher that is not a service's `ExecStart`, and
after the first pin check where the holder runs:

```bash
pgrep -f '[c]swap_pin.proxy --hold-port'    # the holder's pid
cat /proc/<pid>/cgroup                    # a last component ending in .service is that unit's
```

### A settings `env` overrides the pin

Claude Code applies the `env` block of `.claude.json` first and then the `env`
of every settings file on top of it: user, project, local and managed (read in
Claude Code 2.1.287). So an `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY` or
`NODE_EXTRA_CA_CERTS` in any `settings.json` replaces the pin's value, and
nothing says so: requests skip the pin, or the session stops trusting the
pin's CA and every pinned request fails TLS. Keep proxy and CA variables out of
settings files. Export them where you pin instead; the pin chains through the
proxy and merges the CA for you.

## Keeping the programs Claude Code starts off the pin

**What the pin wires, and who inherits it.** `cswap pin N` writes
`HTTPS_PROXY`, `https_proxy`, `ALL_PROXY`, `all_proxy`, `NODE_EXTRA_CA_CERTS`
and `CSWAP_PIN_PORT` into the `env` block of `~/.claude.json`. Claude Code puts that
block into its own environment at start, and every program it starts inherits
its environment: the Bash tool's shells, command hooks, stdio MCP servers, the
status line, and everything those run (`aws`, `git`, `curl`). Their HTTPS then
goes through the pin, which tunnels every host except `api.anthropic.com`
unopened. If you want those programs off the pin (say one of them fails through
it), and Claude Code itself still on it, this section is the way. It is opt-in:
the pin never sets `CLAUDE_CODE_SHELL_PREFIX` for you.

**What it is.** Claude Code runs the Bash tool, every command hook, every stdio
MCP server and the status line through the executable that
`CLAUDE_CODE_SHELL_PREFIX` names, handing it the whole command as one argument
(measured on Claude Code 2.1.296). The pin ships such an executable that
sets the six proxy variables (`HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`,
`http_proxy`, `ALL_PROXY`, `all_proxy`) to the proxy you had before the pin wired
itself in, or unsets them when you had none, and then runs the command.
`NO_PROXY` and `no_proxy` are left alone. `NODE_EXTRA_CA_CERTS` and
`CSWAP_PIN_PORT` stay, so a Node child still trusts the pin's CA (see
[Trust](#trust)).

Before it rewrites them, the script records the route the session was started
with in `CSWAP_PIN_SESSION_ROUTE`: `name=value` for each of `https_proxy`,
`HTTPS_PROXY`, `all_proxy` and `ALL_PROXY` that was set, in that order, separated
by spaces; empty when none was. It is taken once per Claude Code process
(`CSWAP_PIN_SESSION_ROUTE_PID` is the `CLAUDE_PID` it was taken for), so a prefix
of your own that chains back into the script does not record the rewritten
values, and a Claude Code started from a Bash command records its own route. The
status line reads it, because by the time it runs the variables no longer say.

**1. Write it.** If `cswap pin --help` lists `--print-shell-prefix-path`, run

```bash
cswap pin --print-shell-prefix-path
```

and otherwise run the same thing with the Python that `cswap` runs in (for a uv
tool install, `$(uv --color never tool dir)/claude-swap/bin/python`):

```bash
"$(uv --color never tool dir)/claude-swap/bin/python" -m cswap_pin print-shell-prefix-path
```

Either prints one absolute path and nothing else: `<data>/pin-proxy/shell-prefix`,
where `<data>` is cswap's data directory (see [Before you
start](#before-you-start-and-if-it-breaks)). By default that is
`~/.local/share/claude-swap/pin-proxy/shell-prefix` on Linux and
`~/.claude-swap-backup/pin-proxy/shell-prefix` on macOS, printed with your home
directory spelled out; on Linux `$XDG_DATA_HOME`, when set, moves it to
`$XDG_DATA_HOME/claude-swap/pin-proxy/shell-prefix`. Running the command again
changes nothing while the file is current. The file is mode 755 and holds
exactly this:

```sh
#!/bin/sh
# the proxy the user had before the pin wired itself in: the pin writes it next to this file, or leaves it empty
p=${0%/*}/shell-prefix.proxy; CSWAP_PIN_CHILD_PROXY=; [ -r "$p" ] && IFS= read -r CSWAP_PIN_CHILD_PROXY < "$p"; export CSWAP_PIN_CHILD_PROXY
# the route this Claude was started with, taken once per Claude before the rewrite below (a chain that comes back here, or a Claude inside a Bash command, is told by CLAUDE_PID); the status line reads it
[ "${CSWAP_PIN_SESSION_ROUTE_PID-?}" = "${CLAUDE_PID-}" ] || export CSWAP_PIN_SESSION_ROUTE="$(r=; for k in https_proxy HTTPS_PROXY all_proxy ALL_PROXY; do eval "v=\${$k-}"; [ -z "$v" ] || r="$r $k=$v"; done; printf %s "${r# }")" CSWAP_PIN_SESSION_ROUTE_PID="${CLAUDE_PID-}"
u='for k in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy; do if [ -n "$CSWAP_PIN_CHILD_PROXY" ]; then export "$k=$CSWAP_PIN_CHILD_PROXY"; else unset "$k"; fi; done; unset k'; eval "$u"
# Bash tool (Claude puts no CLAUDE_PROJECT_DIR there): remember which Claude this is
[ -z "${CLAUDE_PROJECT_DIR+x}" ] && export SHELL_PREFIX_CLAUDE_PID="${CLAUDE_PID-}"
# the shells below run $u again after their startup files, and take the holder with them
u="$u; unset CSWAP_PIN_CHILD_PROXY"
# the user's own earlier prefix gets the command exactly as Claude gave it; the variable is
# dropped first, so a chain that comes back to this file ends here; a missing file or a relative name is skipped
p=${CSWAP_PIN_PREV_SHELL_PREFIX-}; unset CSWAP_PIN_PREV_SHELL_PREFIX
case $p in /*) [ -f "$p" ] && [ -x "$p" ] && { unset CSWAP_PIN_CHILD_PROXY; exec "$p" "$1"; } ;; esac
# Bash tool: the shell Claude chose (it sets SHELL); set again after its startup files
[ -z "${CLAUDE_PROJECT_DIR+x}" ] && exec "${SHELL:-/bin/sh}" -c "$u; $1"
# hook or statusLine: Claude stamped its own pid on it; run it under /bin/sh, as without a prefix
[ -n "${CLAUDE_PID+x}" ] && [ "$CLAUDE_PID" != "${SHELL_PREFIX_CLAUDE_PID-}" ] && exec /bin/sh -c "$u; $1"
# stdio MCP server: one quoted command; become it, so Claude's signals reach the server
unset CSWAP_PIN_CHILD_PROXY; eval "exec $1"
```

**Which proxy.** The one you had before the pin wired itself in, so a program
that needs a proxy to reach the network keeps its way out. The pin records it
next to the script, in `<data>/pin-proxy/shell-prefix.proxy`, when a session
starts and when it refreshes the script or you run the command above: one line,
a URL as you gave it (a credential in it stays; the file is as readable as
`upstream.json` beside it), or empty. The script reads that file, from its own directory, for every command
and parses nothing; so `CLAUDE_CODE_SHELL_PREFIX` has to be the absolute path
(see step 2): a relative name looks for the file in the wrong directory, and the
six are then unset. The one value goes into all six, also those you had not set.
It is chosen by the first hop in `upstream.json` (`proxy`):

- No proxy recorded: none. The six are unset.
- A first hop that is not on this machine (only a local hop is asked what it
  chains to, so a `next` behind any other is one an earlier hop left): that
  proxy, as you exported it.
- A local first hop that answered `/health` (a cache proxy, `cache` is set): the
  proxy it chains to, never its own address; none when it chains to nothing.
- A local first hop that answered `/health` with an error, or has no `next`
  recorded yet: that proxy.
- A local first hop with a `next` recorded and nothing known about it yet: none,
  since it may be a cache proxy; unless the file already holds that hop, which
  the daemon, having asked it, wrote, and a session start does not undo.

Whatever the rule gives is dropped when it is the pin itself, by any port the
pin has (`--set_port`, `proxy.json`, `port.hint`, the global config).

The pin learns what a local hop is by asking its `/health`, at a session start
or on the daemon's half-minute timer, which rewrites the file as it learns. Until
then a cache proxy that chains to something passes none, and one that chains to
nothing passes its own address.

A `cswap pin` you run from such a program (a Bash command) has the hop behind
the recorded one in its environment. While the recorded local hop is down, the
pin does not take it for the hop in front: the record keeps its first hop.
While that hop serves, it is preferred anyway, so a record written the wrong
way round (the outer proxy first) is still put right from the shell that
exports the inner one.

**2. Set it**, in one of two places.

- In `settings.json` (`~/.claude/settings.json`), with the path the command
  printed (the Linux default, here):

  ```json
  { "env": { "CLAUDE_CODE_SHELL_PREFIX": "/home/you/.local/share/claude-swap/pin-proxy/shell-prefix" } }
  ```

  Claude Code expands no `~`, `$HOME` or `${HOME}` in this value (measured on
  2.1.296), so a `settings.json` needs the absolute path.
- Or as a line in your shell rc, which expands the `~` for you. Use this when
  one `settings.json` is shared by machines whose home directories differ. Take
  the printed path and write your home directory as `~`:
  `/home/you/.local/share/claude-swap/pin-proxy/shell-prefix` becomes

  ```bash
  export CLAUDE_CODE_SHELL_PREFIX=~/.local/share/claude-swap/pin-proxy/shell-prefix
  ```

  and on macOS `/Users/you/.claude-swap-backup/pin-proxy/shell-prefix` becomes
  `~/.claude-swap-backup/pin-proxy/shell-prefix`. A path outside your home
  directory (an `XDG_DATA_HOME` elsewhere) has no `~` form: use it as printed.
  The Linux line on a Mac names a missing file, and every Bash command then
  fails with exit 127 (see "If it breaks" below).

Set it in one place. It applies to Claude Code sessions started afterwards;
sessions already open keep what they started with.

**What it runs under.** The Bash tool: the shell Claude Code chose, with the six
set again after that shell's startup files, so a `.zshenv` that exports a
proxy does not undo it. Hooks and the status line: `/bin/sh`, as without a
prefix. A stdio MCP server: the server itself, started in place of the script,
so Claude Code's signals reach it.

**Check it.** Start a new session and ask Claude to run this with the Bash tool:

```bash
echo "shell=$0"; env | grep -iE '^(https?|all)_proxy=' | sed 's|//[^@/]*@|//|'
```

It should print your shell and then the six variables, each with the proxy you
had before the pin (the sed hides a credential), or nothing after the shell when
you had none. A line with the pin's port (`cswap pin --get_port`) means the
prefix is not applied. Then ask Claude to show that Claude itself is still on
the pin:

```bash
lsof -a -p "$CLAUDE_PID" -iTCP -n -P
```

Its connections should land on the pin's port (`cswap pin --get_port`).

**What it does not cover.** The prefix does not reach these:

- exec-form hooks (a hook written as `command` plus an `args` list is run
  without a shell, so without the prefix; it keeps the pin's proxy variables);
- Claude Code's own `git` and `gh`, its helpers and LSP servers, which it
  starts without a shell, and WebFetch. They stay on the pin, which passes
  everything except `api.anthropic.com` through as an unopened tunnel;
- Claude Code's Bash sandbox mode. Its sandbox has its own proxy variables,
  and the unset would remove them and leave a sandboxed command no way out. This
  is read from the code, not measured.

A program the prefix reaches gets the proxy you had before the pin, or none when
you had none (see "Which proxy"). A program that needs a different proxy gets it
from you: in an MCP server's own `env` block, in the hook's command, or in the
Bash command.

**You already have a prefix.** Claude Code runs one prefix. Move yours to
`CSWAP_PIN_PREV_SHELL_PREFIX`, as an absolute path to an executable file with
no arguments, in the same place you would set the other (`settings.json` `env`
or an rc `export`), and set `CLAUDE_CODE_SHELL_PREFIX` to the pin's file. The
pin's script sets the proxies as above and then hands your prefix the command
exactly as Claude Code gave it. A relative name, a missing file or one that is not
executable is skipped and the command still runs. With a prefix chained, hooks
run under that prefix's shell instead of `/bin/sh`, and a `.zshenv` that
re-exports a proxy wins, as it does with your prefix alone.

**With cache-fix too.** cache-fix ships its own script of this kind, with its own
variable for a previous prefix. Set one of them as `CLAUDE_CODE_SHELL_PREFIX`.
Chaining one product's script through the other gains nothing.

**Turning it off.** Remove the setting (and the rc line). New sessions only. The
file stays until you delete `<data>/pin-proxy/shell-prefix`; `cswap pin --clear`
does not touch it, since the pin never wrote the setting.

**If it breaks.** Everything below means `CLAUDE_CODE_SHELL_PREFIX` names a file
that is missing or not executable (a wrong path, a deleted `<data>/pin-proxy/`):

| where | what you see |
| :-- | :-- |
| Bash tool | every command fails, `no such file or directory: <path>` with exit 127, or `permission denied: <path>` with exit 126 |
| a hook | `hook error`, `not found` or `Permission denied` |
| a stdio MCP server | status `failed`, `ENOENT` or `EACCES` in Claude Code's debug log |
| the status line | blank |

`No module named cswap_pin.__main__` from the write command means the installed
cswap-pin predates it (0.1.339 and earlier have no such command). Install a newer
one: the Quick start line with `--with cswap-pin` in place of `--with
cswap-pin==<version>` takes the latest.

Run the write command again, which recreates the file at mode 755, or remove the
setting. After an upgrade of the pin, `cswap pin --ensure` rewrites the file by
itself when it exists and differs, but only while a pin is wired; it never
creates one you did not ask for. The file is the pin's: a symlink you put at
that path is replaced by a regular file, so keep your own script or symlink at
another path and name that one in the setting. If
the Bash tool prints `shell=/bin/sh`, Claude Code itself was most likely started
with `CLAUDE_PROJECT_DIR` already in its environment (from a hook or another
tool): start it without.

## What the pin writes

`<data>` is cswap's data directory (see [Before you
start](#before-you-start-and-if-it-breaks)); `cswap pin --get_certdir` prints
`<data>/pin-proxy`.

| where | what | after `cswap pin --clear` |
| :-- | :-- | :-- |
| `~/.claude.json` `env` (`$CLAUDE_CONFIG_DIR/.claude.json` when that is set) | sets `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY` and `all_proxy` to the pin's loopback address, `NODE_EXTRA_CA_CERTS` to the pin's CA (or to `ca-bundle.pem` when a hop's CA is merged in) and `CSWAP_PIN_PORT` to its port; deletes `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` | the six removed and whatever they replaced restored; the three deleted stay deleted |
| `~/.claude.json` `oauthAccount` | the pinned account's identity, re-asserted by every `--ensure` | the account you are logged in as |
| `<data>/pin-wiring/<key>.json` | the receipt: `_cswapPinWiredKeys` (what was set), `_cswapPinWiredKeysSaved` (what that replaced), `writtenBy` | emptied |
| `<data>/settings.json`, `remoteControl` | `pinnedEmail`, `pinnedOrganizationUuid` (a `debugSlowMs` you add there is yours and is left alone) | the two pin keys dropped; when the file is a symlink (shared across machines) they are left alone unless you add `--everywhere` |
| `<data>/pin-cleared` | written only by a `--clear` on a symlinked `settings.json` that records a pin: this machine reads the shared record as "nothing pinned" while it exists. Needs the matching claude-swap | removed by `cswap pin <account>` and by `--clear --everywhere` |
| `<data>/pin-proxy/` | the CA and its keys, `ca-bundle.pem`, `upstream.json`, `shell-prefix.proxy` (the proxy the opt-in shell prefix hands the programs Claude Code starts), `proxy.json` (port and pid), `port.hint`, `settings.json` (from `--set_port`), `daemon.log`, locks and a FIFO, and `shell-prefix` only if you ran the command that writes it | left in place |
| `~/.claude/ca-trust.d/cswap-pin.pem` (under `$CLAUDE_CONFIG_DIR` when that is set) | a copy of the pin's CA, for a launcher that builds one trust bundle from that directory. That is a launcher convention, not Claude Code's: with no such launcher nothing reads it | left in place |
| `~/.claude/jobs/<id>/state.json`, and a transcript's `bridge-session` record | the account in the bridge pointer of a session that is not running, restamped (see [Keeping a session's bridge when the account rotates](#keeping-a-sessions-bridge-when-the-account-rotates)) | not touched |

## The problem

cswap swaps the on-disk credential, so *everything* follows the swap —
including two things that are not inference and that you usually want to stay
put:

- **Remote Control** — a session's owner is fixed at creation by whichever
  bearer created it. Swap accounts and the phone/web loses the session; stale
  "ghost" sessions pile up on the old account.
- **Artifacts** — owned by the publishing bearer. After a swap a republish
  403s and the artifact "disappears" from the account you are logged into.
- **Claude in Chrome** — the extension pairs with Claude Code through a relay
  that checks the token Claude Code sends against the account the extension
  is signed in to. After a swap the relay answers `User mismatch` and the
  browser tools report "Browser extension is not connected".

Claude Code resolves all of these through one credential accessor and has no
per-operation token selector, so splitting auth *per operation inside one
session* means intercepting the requests.

## How it works

A local MITM forward proxy that swaps the `Authorization` bearer on exactly
the routes whose server-side ownership is decided by it, and passes everything
else — `/v1/messages` above all — through untouched (unless cswap's
cache-aware strategy is on, which it is not by default: see Session affinity
below).

```
claude session
  HTTPS_PROXY ─► cswap pin proxy ──► (whatever HTTPS_PROXY was already set) ──► api.anthropic.com
                   swaps bearer on: /v1/code/sessions*, /v1/sessions/*,
                                    /v1/environments, /v1/environments/bridge*,
                                    /v1/environments/<env>/bridge/reconnect,
                                    /api/frame/*, /v1/ultrareview/*
                   passes through:  /v1/messages, /api/oauth/usage, everything else
                   NEVER swapped:   .../worker/*, .../client/presence,
                                    /v1/environments/<env>/work/*, ?beta=true
```

Inference keeps billing whichever account cswap has swapped onto. Only the
claude.ai-side assets are pinned.

**Claude in Chrome** goes to a second host, `bridge.claudeusercontent.com`, and
puts its bearer in the first WebSocket message (`{"type":"connect",
"oauth_token": ...}`) rather than a header. The pin MITMs that host too, so it
terminates TLS for the whole host, but rewrites only the connect frame of a
`GET /chrome/...` WebSocket upgrade: `oauth_token` becomes the pinned account's
token. Everything else on the host (Claude Code's `/devices/mcp`, over https
and wss) is relayed byte for byte. On the `/chrome/` socket the handshake and
every later frame pass through unchanged, and compression is left
unnegotiated there so the message stays readable. When there is nothing to swap
(the pin is the active account, or no pinned token can be minted) the host is
tunnelled blind, as before. The MITM leaf carries both names, so an existing
install gets a new leaf under the same CA on its next start.

### Remote Control has two front doors, and they own sessions differently

| you run | it creates | ownership route |
|---|---|---|
| `/remote-control` in the REPL | a bridge on the current session | `POST /v1/code/sessions/<id>/bridge` |
| `claude remote-control` | an ENVIRONMENT this machine offers | `POST /v1/environments/bridge` |

The second family is easy to miss, because `remote-control` is the
subcommand's name while the ownership it creates travels on a path that does
not contain it. Pin only the first and `claude remote-control` registers every
machine on whichever account is currently active — with nothing reporting a
fault, because nothing is failing. The machine is simply absent from the
pinned account's browser.

**A pinned route is only swapped on a path that reads the bearer, and there
are two.** The MITM terminates a `CONNECT` and inspects each request inside
it; the other forwards absolute-form requests (`POST https://host/path`),
which is plain-proxy form. Remote Control's bridge client speaks the second,
so adding its routes to the table changes nothing until that path swaps too.
Both now take the same decision from the same predicate, and both write a line
saying what they decided — an untraced path leaves exactly the evidence a
feature that is not running leaves.

A swap the upstream REFUSES (401/403/404) is taken back and the request goes
again with the bearer it arrived with. That is what lets an environment
registered before the pin knew this route keep working instead of dying on its
next poll.

Three exceptions inside the pinned prefixes are worth naming, because all
three were learned by breaking them:

- **`/worker/*`** carries the session's own channel credential, not an OAuth
  bearer. Swapping it makes the server reject every worker call and leaves
  Remote Control in a reconnect loop.
- **`/client/presence`** is *registration*, not ownership: it tells the server
  which process is attached and should receive events. Swapped, the server
  registers the pinned account while the process actually listening belongs to
  the active one — so inbound has nobody to reach. It returns `200` either way,
  which is what made it hard to find.
- **`/v1/environments/<env>/work/*`** is the same shape as `/worker/*`, one
  path over. In the bridge client every OAuth call goes through one wrapper
  that reads the account's access token — register, deregister,
  `bridge/reconnect`, archive — while `poll`, `ack`, `stop` and `heartbeat`
  each take a token as an *argument* and send whatever the caller hands them.
  Measured against an environment this proxy had just registered: the register
  answered fine swapped, and the very next `work/poll` on that same
  environment answered `401` swapped and `200` unswapped. Ownership is still
  the pin's, because the register is; the work queue is simply not an
  ownership route.

`?beta=true` under `/v1/environments` is excluded for a different reason: it
is a second product (the managed-agents SDK) sharing the path space with a
credential this proxy has never looked at. Swapping an `Authorization` nobody
has read is the mistake `/worker` already measured.

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

### Keeping a session's bridge when the account rotates

Swapping the bearer is only half of it. Claude Code also writes a *pointer* —
naming the bridge, the sequence to resume at, and the account it believes it is
— and on the next launch compares that recorded account against
`~/.claude.json`'s `oauthAccount`. A mismatch is a veto:

```
reattach vetoed: the credential store account changed since this conversation's
pointer was persisted — minting fresh, history channels suppressed
```

The comparison is against the account cswap currently has **active**, never
against the pin. And Claude Code stamps the pointer with its own login, not
with the bearer this proxy swapped in — so under a perfectly working pin the
bridge belongs to the pinned account while the pointer names whichever account
happened to be active. Rotate once between two runs and the veto strands a
bridge that was reattachable the whole time. Measured on one machine: **14 of
14** live sessions held a pointer that disagreed with the login. What follows
from that — veto, fresh mint, history suppressed — is Claude Code's code path
as read at 2.1.233, not a second measurement and not documentation: none of
this is documented anywhere, it is decompiled. Nobody relaunched all fourteen
to watch it happen.

So since 0.1.81 the pin restamps the pointer of sessions that are **not
running** with the account that is live right now, and the pointer then agrees
with the login by construction. Two hooks, because neither covers the other's
sessions:

| hook | reached by | timing |
| --- | --- | --- |
| `heal` | `cswap pin --ensure`, the rc hook before every hand-launched `claude` | backgrounded by the rc file, so it can lose the race against the launch it precedes |
| `ensure_proxy` | `cswap run`, and a hand-typed `cswap pin <n>` | synchronous, before `execvpe` — but it runs with the DEFAULT profile's environment, so on `cswap run <account>` it sweeps that profile, not the isolated one it is about to launch |

Losing that race costs the current launch and nothing else: the pointer a pass
misses is restamped by the next launch on the machine, and a session that gets
vetoed once still ends up with a working bridge — just a new one.

**Restamped, not blanked.** Removing the owner also clears the veto, and it is
the more obvious move, but the same branch decides something else:

```js
if (!He) { He = Qe.id, Oe = Qe.seq;
           if (!Ir || !hzs()) Ke = true;      // Ir = owner matches the login
           … `${Ke ? "reattach-or-fail" : "fresh-mint fallback"}` }
```

No owner means no match means **reattach-or-fail, with the fresh-mint fallback
switched off** — so a pointer naming a bridge that has since been deleted (by
another machine's sweep, by `/cleanup-rc`, from claude.ai) leaves that session
with no Remote Control at all. A *matching* owner keeps the fallback, which
makes a wrong guess cost exactly what it costs today: a new bridge. That is why
nothing here has to prove which account owns a bridge, and why there is no
cache to go stale.

The `hzs()` in that condition is a server-side feature gate whose `true` is a
client default, so the fallback is Anthropic's to keep rather than something
this package can guarantee. Removing the owner loses it unconditionally;
matching loses it only if that gate is ever turned off.

**Two stores, and the live one is not the obvious one.** The pointer lives in
`~/.claude/jobs/<jobId>/state.json` when `CLAUDE_JOB_DIR` is set and in the
transcript's last `bridge-session` record otherwise. A session that has been
both keeps a stale transcript record forever — 12 of 13 live sessions here are
background jobs whose transcript record disagrees with their job record.

**What it restores is the bridge, not the backfill.** `noHistoryBackfill` is
copied through, and `if (Qe.noHistoryBackfill) le = true` runs on the reattach
branch too, so a pointer carrying it reattaches with history channels still
suppressed — 12 of 12 job records here carry it, and Claude Code ORs it forward
so it never clears. The session keeps the same conversation and the same
sequence position instead of starting over on a new bridge.

That `le` also skips Claude Code's own title derivation (the block is
`else if (!le)`), so the name does not come back from CC either — it comes from
this package: the daemon's sweep puts each session's local name on its bridge
whenever the server has invented one, which is what `titles_to_restore` is for
and what 0.1.80 shipped. Restamping and title restore are two halves of the
same outcome, and neither replaces the other.

Nothing here clears the flag. Doing that would push transcript history to the
server, which is not this proxy's call to make — and a draft that wrote the
flag ON, to preserve a suppression on a branch that turns out to be unreachable
at launch, would have cost every ownerless pointer its messages and its name,
permanently. It was removed.

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
Measured: **twelve `kill -9`s** of the daemon while four clients hammered the
port — **6,388 requests, 0 refused**, same port throughout, a new pid each
time. The 41 resets in that run are the killed daemon's own in-flight
requests, which a crash must cost; a *planned* restart costs none.

The reason it is zero rather than small is that the holder never releases the
socket between children. It binds once and keeps it; each daemon accepts on
the inherited descriptor. So there is no re-acquire to lose, and a connection
arriving mid-crash waits in the kernel's backlog instead of being refused. A
supervisor that closes and rebinds has a window there by construction, however
narrow — a peer measured 1 refusal in 40 requests on that shape.

The holder reads the daemon's exit rather than guessing:

| exit | meaning | what the holder does |
| :-- | :-- | :-- |
| `0` | idle teardown — it meant to go | release the port, do not respawn |
| `75` | `SIGTERM` under a holder: a redeploy | restart at once, same socket |
| other | killed or crashed | restart on a 0.25s → 5s ladder |

`CSWAP_PIN_SELF_HEAL=off` turns every automatic replacement off — the holder's
restart above and the self-upgrade below — for when you are debugging the
daemon and a respawner fighting you is worse than a dead port. `cswap pin
--heal` and a launch still repair, because those are you asking.

`CSWAP_PIN_ALLOW_DIRECT=1` restores the old fall-through to a DIRECT dial when
every configured hop is unusable. Off by default since 0.1.251: on the network
it was measured on, the direct route is a corporate TLS-inspecting proxy,
which answers 403 "Access restricted by network policy" to API and Remote
Control requests, and Claude Code renders that as "Please run /login" (measured
2026-09-07, 49 direct dials in 22 minutes, one fleet-wide login wave). That is
one network's behaviour: set the opt-in only when a direct dial from your
machine reaches the internet. Without
the opt-in the pin answers `503 Service Unavailable` with `Retry-After: 2` and
logs `egress REFUSED` once per outage; the client retries, nothing is asked to
log in. A host with no chain configured is unaffected and dials direct as
before. The daemon reads the opt-in from ITS OWN environment, fixed at exec,
so a running daemon never sees a later export: set it in the shell that starts
the next daemon (`export CSWAP_PIN_ALLOW_DIRECT=1; cswap pin --heal`).

`CSWAP_PIN_EXIT_WITH_PARENT=1` makes the holder die when the process that
started it dies. **Do not set this.** A holder is meant to outlive its
launcher — `cswap pin` spawns it and exits, a shell backgrounds it and the
shell exits — so with this on, a normal launch loses the port within a couple
of seconds and every session wired to it is stranded. It exists for a test
runner: a `SIGKILL`ed pytest otherwise leaves holders behind (151 of them,
9.17 GiB, measured), and the suite sets it for the one case that asserts that
cleanup.

`CSWAP_PIN_CODE_WATCH_S=<seconds>` sets how often the daemon checks whether
the code on disk changed, from 1 to 30 seconds; the default is 30, and any
other value is the default. **Do not set this on a fleet.** Only the throwaway
pin of the Rule 0 sandbox sets it, to shorten its rehearsal of a deploy. The
daemon reads it once, at start, and writes a `code watch ticks every` line to
`daemon.log` when it is not 30.

Two opt-in traces, both off unless you name a file:

```bash
CSWAP_PIN_DEBUG=/tmp/pin.log     # one line per request
CSWAP_PIN_SHAPE=/tmp/shape.log   # the message-array shape of each request body
```

And an opt-in slow-request report, off unless you name a threshold in
milliseconds. It writes to `daemon.log`, so it stays silent until asked —
always-on it produced about 38 lines an hour on one fleet, which is noise in
the file people read to find out why a daemon died.

It goes in the section `cswap pin <email>` already writes in cswap's own
`settings.json` (`~/.local/share/claude-swap/settings.json` on Linux,
`~/.claude-swap-backup/settings.json` on macOS), so there is no new path to
remember:

```json
"remoteControl": { "pinnedEmail": "you@example.com", "debugSlowMs": 1500 }
```

Edit it while the daemon serves; it is re-read within seconds. Restarting the
daemon is the one act guaranteed to hide an intermittent stall, so a switch
that needed a restart would be useless for this. `CSWAP_PIN_SLOW_MS` wins for
a deployment that would rather set it in the environment.

Each line splits the round trip three ways — inside the pin, waiting for the
server, and getting the request out through the chain — because the total
alone cannot say whose problem a stall is. The route is logged without its
query string or session id.

**Session affinity (off by default).** When cswap switches the live account,
Claude Code's next request goes out on the new account's token and the prompt
cache the session built on the old one is lost. With session affinity armed, a session (`x-claude-code-session-id`)
whose last `/v1/messages` was within `autoswitch.cacheTtlSeconds` keeps the
account it was on: the pin sends that request with the kept slot's *stored*
access token. It sends it only while that token has an `expiresAt` and is
unexpired (it never refreshes one and never spends a grant), the slot is not
walled or disabled and every window reads under `autoswitch.threshold` (or
under the slot's own switch threshold, when that is lower), and the client's
token and the kept one both belong to a slot in your roster and to different
ones. A new or cold session, a Console API key or an expired one is forwarded
exactly as without it. A reply that shows a kept slot at or over its own
limit takes the slot out at once, without waiting for the next snapshot. If the kept account answers 401, 403 or
429, the pin takes that answer back before the client sees any of it, rests
the account (until the 429's reset, else 60 s) and resends on the client's own
token, so the client only ever hears from the live account. A 404 is the server
saying the thread a held send names is not on that account, and a resend on the
live account answered 404 again every time it was measured, so it is relayed to
the client, which replays the conversation in full and is routed to the kept
slot again; the session stays on it, the account is not rested, and the kept
body is forgotten. Each take-back
writes a line to `daemon.log` (the slot, the status code, the rest in
seconds, at most one a minute per slot and code; the take-backs it folded into
"; N more" are written by the next snapshot rebuild once the minute is up), the
account's usage headers on that reply always reach cswap's usage store (a 429
is never held back by the 30 s throttle), and a request sent on a kept token
shows `kept=<slot>` in the `trace-to` log.

A request never waits on the store or the Keychain for any of this. A
snapshot of the roster (which slot stores which token, which slots have
headroom) is rebuilt on a thread of its own, at most every 30 s and one at a
time, by whichever armed request finds it that old, or by a thread of the pin
while a session is inside the cache time (or carried in from a predecessor),
since with none nothing would read it; the request only reads it. With no
snapshot yet, one older than two minutes (a rebuild that failed or is stuck: `daemon.log` names
the exception class, and `/health` `cache_aware.snapshot` has `age_s`,
`last_rebuild_ms` and `failures`), or a client token the snapshot has not seen
yet (a token that rotated: the first request with it starts a rebuild at
once), the request goes out on the client's own token and the session keeps its account: it is not rebound to that token,
and its clock is not renewed, so the cache time still ends it. So with a stale
snapshot a session can go A, then B for the requests that find it stale, then A
again, and thinking blocks made on B are later sent to A. A rebuild that has
not returned after two minutes is abandoned, a `daemon.log` line says so, a new
one starts, and the abandoned one's late answer is thrown away. At most three
abandoned ones are left waiting: a store stuck for good costs four threads
(the three and the rebuild now running), and once the third is abandoned
`daemon.log` says affinity stays off until one of them returns or the daemon
restarts.

Real scope: under the `dynamic` strategy the proactive and at-limit moves
leave an account at its own bar (97% unless the slot has its own switch
threshold), so a session on a slot under that bar stays, and one at or over it
moves. In practice it stops *alternation* and *manual* switches from moving
warm sessions, and little else.

It is armed by cswap, not by a file here: `autoswitch.strategy` is `dynamic`
and `autoswitch.cacheAware` is true (the `c` key of the auto-switch screen in
`cswap tui`), re-read within seconds, so turning it off takes effect without a
restart. A cswap without the `cacheAware` setting never arms it. The old
switches, `remoteControl.sessionAffinity` in `settings.json` and the
`session-affinity` file in `<data>/pin-proxy/`, no longer arm anything. The
state is in memory and bounded. A daemon handover carries the bindings
(session, slot, email, time of its last request: never a token, never a
conversation) in `affinity-carry.json` beside `proxy.json`, written by the
running daemon at most every 5 s while armed, and the successor lands them with
its first snapshot, so a session inside the cache time keeps its account across
the handover; the first release to carry them hands over cold, since the
predecessor writes none.

A snapshot older than two minutes is still used for a slot it read at least 10
points under its bar (the slot's own switch threshold, else the engine's), for
up to an hour (cswap's own trust limit for a reading); a reply from the kept
account updates that reading. A slot whose stored token reads expired is not
kept this way: that expiry is as old as the snapshot, and cswap may have
refreshed the token since, so the session is left alone as for any old
snapshot. A fresh reading that lacks a window which has just
rolled (its last reading's `resets_at` has passed) counts that window as 0%
and scores the slot on the rest; one never measured is still no reading.

**Keep-alive.** While armed, the pin keeps each session's last main-thread
`/v1/messages` body that asks for the 1 h cache tier (in memory only, never
logged, bounded in count and bytes, dropped with the session's entry or when
the switch goes off; a subagent's request never replaces it). A main-thread
request that writes another cache drops it: a final breakpoint on the 5 minute
tier, a body too big to keep, or a `message-threads-` turn with no breakpoint
(it advances the history the server holds). A main-thread request with no
`cache_control` at all (a title or hook-evaluation call) writes no cache and
is ignored: the API's 1 h entry is still there. The body also records the
bearer its request went out on; when that is on another account than the
session is bound to (a stale snapshot sends the client's own token and leaves
the binding), the cache is not on the bound slot and the sender drops the body
(`sent on another account`) rather than write it there. A thread of its own
looks once a minute for a session whose body is about 55 minutes old (the
body's own clock: a subagent's request does not reset it, a 2xx ping does) and
whose slot the pin would keep, and it ends when the switch goes off or the
process hands its listener to a successor. It sends that body once more with `max_tokens` 0 and
`stream` false, on the kept slot's stored token, so the API's cache is renewed
before it expires: at most two per real request, and none for a prefix under
20,000 tokens (a held body's is unknown, so its first ping goes out and the
reply measures it; cswap's `autoswitch.keepalive_due` has the rule; the pin has
a copy for a cswap without it). A body is `held` when it carries a `thread`
(a `message-threads-` request whose history the server holds) and `full`
otherwise, whatever the beta header says. A full body is replayed as it was. A
held body is never replayed: the server refuses a `continue` it has already
served (400 while its ~300 s thread lives, 404 after), so the pin rebuilds the
conversation as it relays it (the last `create`, then each reply, rebuilt from
the SSE it relayed with its thinking signatures and tool input, and each later
`continue`'s messages) and pings that as a `create`, the form `rebuilt`: the one
message breakpoint (`1h`) on its last block, the create's `system` and `tools`
as they were. It reads 30864 of 30866 tokens at 56 minutes idle with the
thread gone. The rebuild lives in memory beside the body, under the same
bounds, and is dropped, counted by reason, when it cannot be the conversation
the cache holds: a 404 (the thread is gone), a `continue` that does not name
the last reply, a rebuild over the body cap, a tee that failed. A `continue`
the API answered with a 429, a 5xx or a 400, or whose stream ended in an
`error` event, made no message, moved no thread and renewed no cache: the
rebuild gives it back, with the session's idle clock from before it, and its
retry carries on from the turn before. (A 429 on a request the pin sent on a
kept slot is another outcome: that slot refused it, the retry goes out on the
client's account where the cache is not, and the session's entry is dropped,
counted `taken back`.) A reply cut short (Esc, a dropped stream) leaves the
rebuild pingable, since the cache holds the request's messages, but no
`continue` chains to it. A held body with no rebuild is refused (`a held
thread with no rebuild`), as is a headless session's. To read the replies the
pin asks the upstream for an uncompressed one to an armed held request. It never refreshes,
consumes or probes a token: an expired stored token is refused. Any answer but
a 2xx, a 429 or a 401 included, is counted and ends that session's pings until
its next real request; it never reaches the wall, take-back, rest or switch
paths. A form no sandbox run has measured is refused (`form not measured`).
Each ping writes one line to `daemon.log`: the slot, the form, the status,
`cache_read` and `cache_creation`, whether it was a hit, and the reply's
`utilization` headers. A ping the API refuses writes `error.type`,
`error.details.error_code`, `error.message` (120 characters, control
characters and backticks made spaces) and the `request-id` header instead,
never the body as received.

`/health` carries a `cache_aware` key (additive): `armed`; per slot, `warm`
sessions, how many of them `kept`, `prefix_est` (tokens, summed; a held body
counts 0 until a ping measures it) and `ttl_left_min_s` (the kept body's own
clock where there is one, else the binding's); `pings` (`sent`, `hit`,
`refused` by reason, each reason counted once per request; a session not idle
long enough yet is the normal state and is not counted; `cost`, the `input`,
`cache_read`, `cache_creation` and `output` tokens the answered pings used; and
`forms`, the same four per ping form, `full` and `rebuilt`: `hit` over `sent`
of `rebuilt` is what a held session's keep-alive achieves); `rebuilds` (`kept`,
the held requests a rebuild took in, and `dropped` by reason);
`snapshot` (`age_s`, `last_rebuild_ms`, `failures`); `captures` (`kept`,
and `dropped` by reason, for main-thread requests; a subagent's, and one with
no `cache_control` at all, are neither); and `since`, when this process started
counting. Never a session id or a byte of a
conversation.

`CSWAP_PIN_LISTEN_FD` and `CSWAP_PIN_LISTEN_FROM` also appear in a daemon's
environment. They are how a process hands its listening socket to the next
one, written by the parent at spawn — not settings, and setting them by hand
makes a daemon adopt a descriptor that is not the one it was given.

A redeploy is the same story from the other side. Under a holder the daemon
does not hand its socket to a successor — it exits `75` and lets the holder
put the new code on the socket it already owns. Handing the port out of the
holder is what left one machine's pin unwired for 76 minutes while every
component reported healthy.

A daemon that is NOT under a holder still hands its socket down, and the
successor it starts gets a holder that **adopts** that socket rather than
binding a fresh one. There is no race to lose: the descriptor is already bound
and listening. That is what makes the first upgrade onto this version safe as
well as every one after it.

### A daemon that outlives its holder gets a new one

A holder can die without taking its daemon with it, and nothing looks wrong
afterwards: the daemon already holds the socket, so the port keeps answering.
What is gone is the property above — every spawn lands under a holder — so the
*next* death takes the port down for good.

The daemon notices by asking a question it was already able to answer. Its
`CSWAP_PIN_HELD_BY` names the holder that started it, and an orphan is
reparented to init, so the marker and `getppid()` disagree the moment the
holder dies. Nothing signal-specific: a `SIGHUP`, a `SIGQUIT`, a segfault and a
targeted kill all land the same way. It then hands over exactly as a code
change would, and the successor's holder adopts the socket.

Measured, under load across the whole orphaning: **110,188 requests, 0 refused,
0 reset**, same port, one holder afterwards.

### When the holder and its daemon die together

The two rows above both leave *something* alive that can put the port back. The
row neither covers is both going at once — `cswap` fully off, an OOM kill that
takes the process group, a machine being torn down. The descriptor is closed by
the kernel with the last process holding it, and a session's `HTTPS_PROXY` was
fixed at exec, so it has no way to learn the address moved. Measured with both
gone: **198 of 199 ConnectionRefused**, permanently.

**On Linux, killing the holder alone is already this row.** The daemon is
spawned to exit with its parent (`PR_SET_PDEATHSIG`, and see
`CSWAP_PIN_EXIT_WITH_PARENT`), so the kernel takes it down with the holder and
the descriptor closes with them both. macOS has no equivalent primitive, so
there the daemon outlives its holder still holding the socket and its own
watchdog puts a fresh holder back. Same command, same lineage shape, measured
the same day: **147 probes / 0 unanswered on a Mac, 232 of 241 refused on
Linux**. Anything reasoning about "the holder dies but the daemon survives" is
reasoning about Darwin.

The signal matters as much as the target, and in the same direction:
`SIGTERM` leaves the holder able to run its teardown — drain the daemon, hand
the socket down — while `SIGKILL` denies it exactly that. The handler *is* the
handover.

So a third process holds the same descriptor and does nothing with it. It is
spawned detached (its own session, so a `ctrl-C` or a group-delivered `TERM`
aimed at the holder misses it) and it **never accepts** — CPython only accepts
when you call `accept()`, so a listening socket can be held in silence. That is
what makes this a dormant holder rather than a relay: it forwards no bytes, so
none of the byte-shuffling failures a relay has to get right exist here.

`CSWAP_PIN_STANDBY_FROM` carries the pid it was born under. It acts only when
**both** are true:

- `getppid()` no longer reads that pid — *not* `== 1`, which never happens on a
  subreaper host (`systemd --user`); a standby that never arms while still
  holding the descriptor makes the address accept-and-hang, strictly worse than
  refusing.
- the daemon `proxy.json` names is gone — `kill(pid, 0)`, microseconds and no
  socket — **and** one 250ms probe to the port gets **no byte back**. The
  recorded pid is asked first because it is the cheapest and most direct
  evidence there is: silence is only a *proxy* for "nothing accepts", and a
  loaded daemon can stay silent longer than any window worth waiting. Any byte
  counts and the status is ignored — a live daemon answers `407` and a peer's
  carrying relay answers `503`, and both mean "somebody is behind this socket".

Either condition alone is wrong: while the holder lives it is already respawning
its own daemon, and a silent port during an ordinary daemon crash is a gap the
holder closes by itself (measured: 407 of 408 requests served across a daemon
`SIGKILL`, max time-to-first-byte 6.3ms).

When it does act it does not serve traffic — it puts a holder back on the
descriptor it was already holding, and requests that arrived meanwhile are
waiting in the backlog of a socket that never stopped listening.

**What it cannot preserve is the connections the dead daemon had already
accepted.** Those bytes are in a process that no longer exists and no successor
can produce them. Measured with a peer's instrument — sampling a real session's
ESTABLISHED connections every 200ms across the kill — the session's connections
drop to zero and are re-made about 851ms later. What survives is the *address*,
which is the part a session cannot relearn, and that is the whole point:
`HTTPS_PROXY` was fixed at exec, so a client that retries finds a listener
instead of the 198-of-199 ConnectionRefused above.

So **"zero requests lost" is a claim about a retrying client, not about
connection continuity**, and elapsed time cannot tell the two apart — a reset
that is re-made in under a second looks identical to no reset at all. The
upgrade path above is the stronger one: there the socket is handed on, so
connections are never reset in the first place.

**Only `SIGHUP` releases it.** `SIGTERM` and `SIGINT` are ignored outright:
`TERM` is what a supervisor, a `systemctl stop` or a stray `pkill` sends, and
that is exactly when the sessions still need the address. A peer on this design
measured their graceful path as *more destructive than `kill -9`* for want of
that distinction. `PortHolder.stop()` — a deliberate release — sends the
`SIGHUP` itself, so releasing the port really releases it.

### A daemon the macOS Keychain refuses is moved into the caller's session

On macOS a process outside the login session (one started over `ssh`, say) is
refused Claude Code's OAuth Keychain item (`security` rc=36), and every daemon
it spawns inherits that, successors included: every successor is born of the
holder. Such a daemon still serves and can report `can_pin` true, but its 429
wall cannot switch slots. Killing the trio to start another cuts the held
tunnels, so the **socket** moves instead.

- The daemon reads its own refusal once, at start, and `/health` says
  `"keychain_denied": true`. The key is absent for a daemon that is not
  refused, and off macOS.
- Exactly these commands trigger it: `cswap pin --ensure` (what the rc hook
  runs on every launch) and `cswap pin --heal`, through `heal`'s
  serving arm (`--ensure` reaches `heal`, never `ensure_proxy`), and `cswap
  run`, a hand-typed `cswap pin <n>` and the TUI's repair, through
  `ensure_proxy`. Each finds such a daemon, and when the caller is **not**
  itself refused and sees the daemon's pid (host and container share `$HOME`,
  not pids), starts a **detached helper** (`python -m cswap_pin.proxy
  --relocate <certdir> <account> <email>`, stderr to `daemon.log`) and returns
  the current port **at once**: the old daemon keeps serving, its record stays
  valid (the helper's spawn does not mark it as handed over), and no launch
  waits on the move or on the helper's lock. The helper is the caller's own
  child, so it shares the caller's macOS audit session. The launch's own
  checks are reads, and its Keychain check is one read, never the two a second
  apart the helper makes. Only one runs at a time: a caller that finds the
  spawn lock held starts none. The helper takes the spawn lock, binds
  `pin-proxy/.successor-<pid>.sock` and waits 60 s; a daemon acts only on a
  rendezvous younger than 50 s, so it never connects to a socket nobody
  accepts on. The daemon's next watchdog tick (at most 30 s) sees it, whatever
  else that tick wanted (stale code, a blind mint), and asks its holder, which
  answers the daemon's own ask by sending the helper the live listening socket
  over that rendezvous instead of spawning (the holder's own replace of a
  wedged daemon never hands off). The helper runs `_spawn_daemon(listen_fd=)`
  itself, so the new holder is its child and `CSWAP_PIN_LISTEN_FROM` its pid,
  and the old daemon runs the ordinary gapless sequence: wait for the
  successor's record, stop accepting, drain **uncapped**, exit 0. The helper
  exits once the new daemon has published.
- **The old holder stands down on every exit of its draining daemon.** Once
  `proxy.json` names another live daemon, an exit 0 (the drain ended), 75 (a
  TERM during the drain) or a crash (an OOM kill) respawns nothing, the old
  lineage's standby is released while the drain still runs, and the socket is
  closed only after its daemon is gone.
- **One move per lineage.** The helper stamps `CSWAP_PIN_RELOCATED=1` into the
  lineage it starts, and a daemon that carries it is never moved again.
- **Off macOS nothing changes**: the refusal does not exist there, so a launch
  asks the daemon nothing extra (not even `/health`) and a daemon starts no
  thread to read it.
- **Opt-in: pull a daemon from another pid namespace.** A caller that sets
  `CSWAP_PIN_RELOCATE=1` (an env var, because host and container read one
  `$HOME`) and cannot see the recorded daemon's pid asks for its socket on
  `/health`'s word instead of the ps and `/proc` clauses (which read "not
  mine" across namespaces): the same successor-first move, on any platform.
  It is **directional**: only the side with the knob pulls, and only a pid it
  cannot see. One `/health` field, `"relocated"`, decides. It is published
  only by a daemon whose own holder runs this code (the holder marks the
  daemons it starts with its pid in `CSWAP_PIN_HOLDER_HANDS_ACROSS`, an
  internal mark and not a setting, and a daemon under an older holder carries
  no mark), so ABSENT refuses (the holder cannot hand across namespaces),
  `true` refuses (this lineage was already moved, the ping-pong backstop) and
  `false` allows the pull. A daemon outside the helper's namespace cannot
  see its pid either, so it finds the rendezvous by a connect instead of
  `kill 0` (the helper accepts until a descriptor arrives, under one
  deadline), and the old holder reads the successor from the port's `/health`
  when its pid reads dead, so it stands down instead of respawning beside it.
- **Nothing is cut and nothing is stranded if it fails.** If the helper dies
  or the successor never publishes, the old daemon keeps serving past its
  bound (no capped drain, no exit 75) and its holder keeps its respawn duty.
  The bound is `_RELOCATE_WAIT_S` (180 s), not the 10 s `_SPAWN_WAIT_S`: a
  helper-spawned successor measured 0.54 s to serve on a quiet box and 9 s with
  16 busy loops sharing its CPU, and 56-85 s on a loaded Mac (T1935).
- Not verified on a Mac: that a lineage spawned from the login session is read
  as not refused. The new daemon's own `/health` is the measurement, and a
  lineage that is read as refused anyway stays where it is (one move).

### `/health`'s `pin_identity_mismatch` is a verdict of one generation

An object means the bearer in the pinned slot answers as another account than
the pin (`{"pinned": ..., "bearer": ...}`). `false` means this daemon checked
its own bearer and it is the pinned account. `null` means no conclusive verdict
from this generation, for one of three causes:

- a fresh process or a handover successor before its first check;
- a check that ran and could not decide: the profile read raised, timed out or
  returned a non-dict, or there was no email to compare. It is retried after one
  backoff (`_IDENTITY_PROBE_BACKOFF_S`) and stays `null` while the profile read
  keeps failing;
- a pin that is the live login, where there is no spliced bearer to evaluate:
  the field stays as last evaluated (`null` on a fresh generation) once the pin
  becomes the live login, and nothing resets it.

A reader treats `null` as unknown, never as clean and never as foreign. The
verdict is not inherited across a handover: a verdict on the predecessor's
bearer does not vouch for the one the successor serves, so an upgrade through a
handover reads `null` again until the successor's first check. That check runs
within seconds of the successor's warm mint, so a `null` that persists well
past a handover points at the second or third cause, not at "not checked yet".

## Hosts that bring their own login (Claude Desktop)

Everything above assumes inference already follows cswap, and for the `claude`
CLI it does: it reads the Keychain cswap swaps. **Claude Desktop's Code tab
does not.** It spawns its bundled CLI with the app's own login in
`CLAUDE_CODE_OAUTH_TOKEN`, and under a desktop entrypoint Claude Code ignores
any settings `env` entry naming a variable the host set at spawn, so no
configuration reaches it. Desktop bills the account the app is signed into,
and after a rotation it is the one client left on "Weekly limit reached".

Its traffic still comes through this proxy, and its User-Agent names the
entrypoint (`claude-cli/<ver> (external, claude-desktop)`). So, opt-in, the
proxy can re-bill it: turn on cswap's `pin.desktopFollows` setting (a bool,
default `false`). Any of the three flips it:

```bash
cswap config set pin.desktopFollows true      # or false
cswap pin --desktop on                        # or off
# or press `d` in the Auto view
```

The setting is re-read every 2 seconds, so it reaches a daemon that is already
serving, with no restart. `CSWAP_PIN_INFERENCE_FOLLOWS=claude-desktop`
(comma-separated) wins over the setting, like `CSWAP_PIN_DEBUG` over
`trace-to`; an empty value forces it off. It is off by default, and while it
is off no request changes.

What it does, for a followed entrypoint only:

- `/v1/messages` gets the active account's bearer. Unlike the proposal this
  was adapted from (#60), `/v1/messages/count_tokens` does not: the wall and
  access-grant conversions match `/v1/messages` exactly, so a refusal on
  `count_tokens` could never be converted. Nothing else moves: ownership
  routes keep the pin, and `/api/oauth/*`, usage and profile calls keep the
  host's own login.
- The active credential is read by a thread of its own, never by a request:
  every 10 seconds while an entrypoint is followed, and at once after a switch
  the wall or the access-grant check converted into a 401. A request that
  finds no token yet, an unreadable one, one no read has landed in for a
  minute (a reader that hangs), or one within a minute of expiry goes out as
  the host sent it, and the proxy never refreshes one (refresh tokens are
  single-use; the CLI keeps the Keychain copy fresh). A request that carries
  an `x-api-key` unlike its bearer is the client's own pair and is left alone.
- Session affinity (above) still applies, and an affinity entry wins. The
  follow swap runs first, so affinity sees the followed bearer: a warm Desktop
  session stays on the account its prompt cache is on after a switch, and a
  session with no warm entry follows the move.
- A followed request the account refuses with a 401 or 403 is resent on the
  host's own bearer, the same fail-open the pinned routes use, and the token is
  read again. A 404 is relayed as it came. A 403 that is the access-grant
  refusal is checked first: when the switch converts it, the client gets the
  401 the wall and access-grant conversions send and nothing is resent;
  otherwise it is taken back like any 403.

`/health` carries an `inference_follow` key (additive): `entrypoints`;
`swapped`, the requests whose bearer became the active account's (a warm
session's affinity entry may still send one on its kept slot); `taken_back` by
status code; `passthrough` by reason (`no-token`, `stale`, `expiring`,
`same-token`); `snapshot` (`age_s`, `failures`); and `since`, when this process
started counting. Counts only, and nothing is written to a file. `daemon.log`
records a refusal (at most one line per status code a minute).

## Falling through a dead hop

The pin dials through whatever egress proxy the machine already has, and that
proxy usually has one behind it. When a hop dies the request has to reach the
hop *behind* it — falling through to a direct dial is not "no proxy" on a
machine whose direct route is a TLS-inspecting corporate proxy, it is a `403`.

So the pin asks each hop what it chains through, **while that hop is still
answering** — the only moment the answer can be trusted, and the only moment it
is free. Measured on one machine: the record named a single hop for a day while
that hop's own `/health` had been naming the next one the entire time, because
the question was only ever asked at launch. When the inner hop died, a chain
that could have stepped one hop out went direct instead.

## IPv6 that resolves but does not route

Every upstream dial (direct, through a hop, and the blind tunnel) races the
resolved addresses the way RFC 8305 describes: IPv6 and IPv4 interleaved, the
next attempt started 250 ms after the previous one or at once when one fails,
the first to connect kept. A plain `socket.create_connection` gives each
address the whole 15 s in turn. On a machine whose IPv6 stops carrying traffic
while it keeps a global address (measured on a cellular modem), AAAA still
resolves first, so every pinned request hung while Claude Code's own direct
dials, which race the same way, kept working.

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

Tunnels to hosts that are not Anthropic's (the same population as the ceiling
below) run on a second selector thread of their own. Every command Claude Code
runs inherits `HTTPS_PROXY`, so one bulk `aws s3 sync` shared the bridges'
selector and deafened 12 of 17 Remote Control bridges. The cost is one flat
thread: `thread_probe.py` reads 6 threads idle and 7 from 50 tunnels up to 256.

One ceiling is back, for a different resource. A fan-out of tunnels to hosts
that are not Anthropic's (an agent's 48 parallel bulk transfers, measured at
~500 tunnels) used every fd the egress hop had, and Claude's own `/v1/messages`
CONNECTs through the same hop got `502`. So at most 256 blind tunnels to other
hosts are open at once; the 257th waits 2 s for a slot, then gets the same
`503` with `Retry-After: 2` as a dead hop, and nothing else is counted:
`anthropic.com`, `claude.ai`, `claude.com` and `claudeusercontent.com` (and
their subdomains) are never capped. It bounds the hop's fds, not threads, so
the coupling above stays gone. `thread_probe.py` tunnels to `127.0.0.1`, so its
300 row now tops out at 256.

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

See [Prerequisites](#prerequisites). [`claude-swap`](https://github.com/realiti4/claude-swap)
is a peer, not a dependency: this package is loaded *by* it (see
`src/cswap_pin/_host.py` for the exact surface it borrows), which is why
`cswap-pin` itself declares Python 3.10+ while the pair needs 3.12+.
`cryptography` (installed automatically) is for the MITM CA.

## Running the tests

Against the **released** host, which is what CI gates on:

```bash
S="$(mktemp -d)" && HOME="$S" XDG_DATA_HOME="$S/.local/share" \
  uv run --with pytest --with pytest-xdist --with cryptography \
         --with claude-swap \
         python -m pytest tests -q -m "not needs_host_seam"
```

Against your **claude-swap checkout**, which also runs the seam tests:

```bash
S="$(mktemp -d)" && HOME="$S" XDG_DATA_HOME="$S/.local/share" \
  uv run --with pytest --with pytest-xdist --with cryptography \
         --with-editable /path/to/claude-swap \
         python -m pytest tests -q
```

Measured, both: 114 passed / 6 skipped for the first, 115 / 6 for the second.
The extra one is `TestAutoViewPinBadge` — it reads a seam that only exists in a
host new enough to have it, so it is `@pytest.mark.needs_host_seam` and CI
excludes it by marker rather than skipping it silently.

**`--with claude-swap` (or `--with-editable`) is not optional.** Five test
files import the HOST, and `claude-swap` is deliberately absent from
`[dependency-groups] dev` — listing it there made `uv run` unresolvable and
took the publish workflow down with it (the reason sits beside the group in
`pyproject.toml`). So the host arrives on the command line or not at all.
Without it the suite does not fail, it **errors**: 14 collection errors,
`ModuleNotFoundError: No module named 'claude_swap'`.

`--with pytest-xdist` is not optional either: `addopts` carries `-n 4`, and a
pytest without xdist refuses the flag rather than ignoring it.

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

**Do not split a heavy test class to parallelise it.** It looks like free
speed — splitting the 24-case port class halved its 12.7s — and it crashes a
worker instead, 3 runs of 3, reported as `received keyboard-interrupt`. The
cause is in xdist's own shutdown, not in this suite: `execnet`'s
`_terminate_execution` gives a worker's execution pool **5 seconds** to drain
and then runs `os.kill(os.getpid(), 2)  # send ourselves a SIGINT`
(`gateway_base.py:1245`, measured with `sigwaitinfo` — `si_pid` is the worker
itself and `si_code` is `SI_USER`). Two spawn-heavy classes on one worker
exceed that budget, so the worker interrupts itself mid-run and the class
never reports at all — it does not even appear in `--durations`.

The 5s is hardcoded, so nothing here can raise it. Both halves pass in
isolation (7.60s and 5.74s); together on one worker they do not.

One pytest test runs many `case_*` methods (`run_cases` in `conftest.py`), so
113 collected tests carry 350 cases. A failure names both: `Class::case_name`.

## Why a separate package

Upstream did not want a MITM proxy shipped inside claude-swap itself and asked
for a companion distribution exposed through an optional extra. See
[realiti4/claude-swap#198](https://github.com/realiti4/claude-swap/issues/198).

## Trust

The proxy generates its own CA to re-sign `api.anthropic.com` (and
`bridge.claudeusercontent.com`, for Claude in Chrome) and names it in
`NODE_EXTRA_CA_CERTS`. Node accepts exactly one file there, so an existing CA
(a corporate MITM, another local proxy) is **merged**, never replaced —
otherwise the session silently loses trust in every host the other proxy
re-signs.

**A remote proxy that intercepts TLS needs its CA.** When the pin chains
through a proxy, `cswap pin N` makes one CONNECT to `api.anthropic.com` through
it with the trust the daemon uses. If that proxy re-signs with a CA the pin was
never given, it prints a line starting `PINNED REQUESTS WILL FAIL` with the fix:
export the proxy's CA in `NODE_EXTRA_CA_CERTS` and re-run `cswap pin N`. The pin
is set either way, and the daemon already serving picks the CA up on its next
connection. A proxy that does not answer is reported, not fatal. A loopback
proxy's certificate is not checked, because the daemon does not verify the
origin through one.

**Replace-class CA variables are handed back.** `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` each replace a trust store, so the pin
never writes them and removes them from the `env` block of `.claude.json` while
it is wired. The values it removed are kept in the wiring receipt, and
`cswap pin --clear` puts them back.

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

**Every shell a session starts inherits the pin.** Claude Code applies the
`env` block of `.claude.json` to its own process, so every child it starts,
Bash-tool shells included, inherits `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY`,
`all_proxy`, `NODE_EXTRA_CA_CERTS` and `CSWAP_PIN_PORT`. The child's HTTPS then goes through
the proxy, which re-signs only `api.anthropic.com` and tunnels every other host
untouched. The trust it hands the child is wider than that: the CA is a full CA
(`CA:TRUE`) with no name constraints, so a Node child reading
`NODE_EXTRA_CA_CERTS` accepts a certificate that CA signs for any host. A
settings file's `env` is applied after that block and wins over it; see [A
settings `env` overrides the pin](#a-settings-env-overrides-the-pin).

To take those programs off the pin, see [Keeping the programs Claude Code starts
off the pin](#keeping-the-programs-claude-code-starts-off-the-pin).

**Accept Claude Code's trust dialog in your home directory by hand.** Trust
accepted in your home directory does not persist (Claude Code keeps it per
session by design), so a process started there, such as Claude Code's
background daemon or a background session, evaluates Remote Control as an
anonymous user and `/remote-control` can disappear. Set
`projects["<your home directory>"].hasTrustDialogAccepted` to `true` in
`~/.claude.json` yourself. This is Claude Code's behaviour, not the pin's.

## License

MIT
