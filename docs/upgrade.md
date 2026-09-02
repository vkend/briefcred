# Upgrading the daemon without downtime

`briefcred daemon restart` is a restart: the daemon closes its sockets, exits,
and is started again. Anything in flight dies with it, and for the moment
between the two a client that connects is told there is nothing there.

`briefcred daemon upgrade` is not a restart. It starts the new binary, hands it
the *same* listening sockets and every open session, and only then lets the old
process stand down — and even then only once whatever it was already serving
has finished. No socket closes, no port moves, no session ends, and no stream
is cut.

```console
$ briefcred daemon upgrade
upgrading pid 4102 to /opt/briefcred/bin/briefcred-daemon
daemon upgraded: pid 4102 handed 3 session(s) to pid 4188
the sockets never closed; pid 4102 is draining what it had in flight
```

`--binary <path>` names a daemon somewhere else. The default is the
`briefcred-daemon` next to the `briefcred` you ran, which is the one a package
upgrade has just replaced.

## What happens, in order

1. **The CLI starts the new daemon** with `--takeover <socket>`, where
   `<socket>` is a fresh path under the `0700` state directory. The new daemon
   binds that socket, generates an ephemeral X25519 key pair, and waits. It has
   bound nothing else and is serving nothing.
2. **The CLI asks the running daemon to hand over.** The old daemon connects to
   the takeover socket and reads the new daemon's hello, which carries the
   ephemeral public key.
3. **The old daemon sends one message**, carrying two things at once:
   - its **listening descriptors** — the IPC socket, the metrics port, the HTTP
     proxy port and the Postgres proxy port — over `SCM_RIGHTS`. The Unix
     socket travels as a descriptor rather than being unlinked and rebound, so
     a client connecting during the swap is never told "no such file".
   - a **signed session-state blob**: every open session with its identifier,
     its profile, its age, its mints, its quota position, its HTTP counters,
     its session key, and its master credentials — each master encrypted to the
     new daemon's ephemeral key.
4. **The new daemon verifies, rebuilds and adopts.** It checks the signature
   against the machine's token-signer key, checks that the blob names *this*
   daemon's ephemeral key and was issued within the last two minutes, decrypts
   the masters, rebuilds the sessions, restores the proxy's revocation set,
   adopts the descriptors and starts accepting. Then, and only then, it answers
   `ready`.
5. **The old daemon stands down.** It stops accepting, drains the requests and
   streams it was already serving (bounded by `handoff_drain_secs`, thirty
   seconds by default), writes its audit rows, wipes its masters, and exits 0.

Between steps 4 and 5 both processes hold the same listening sockets, so there
is no instant in which nobody is accepting. That overlap is the design.

## The window, and why new work is refused in it

From step 2 to step 5 the old daemon is still accepting on the IPC socket. A
session opened in there would reach no blob and be adopted by nobody, so a
credential minted against it would be one that *neither* daemon holds a revoke
for — the worst outcome an upgrade could produce.

So for the length of the handoff the old daemon refuses `open_session`, `exec`
and MCP tool calls that mint, with:

```
the daemon is handing off to a new one; retry, and the new daemon will answer
```

The retry lands on the new daemon, because by the time the client sees the
refusal the sockets are already changing hands. If the handoff fails the
refusal is lifted and the old daemon carries on as before.

Belt and braces: on the way out, the old daemon retires — that is, queues
revokes for — any session it is still holding that the blob did *not* carry, and
releases without revoking only the ones that actually moved. A mint that somehow
reached the window is caught by that rather than lost.

Two `briefcred daemon upgrade` runs at once are not a race. The claim is taken
with a compare-exchange, so exactly one proceeds and the other is told `a
handoff is already in progress on this daemon`.

## What is guaranteed, and what is not

**Guaranteed.** A request that was in flight is answered by the daemon that
accepted it. A request that arrives during the swap is answered by one of the
two. A server-sent event stream or a WebSocket that was open before the upgrade
runs to its natural end on the old daemon, byte for byte. A session handle a
client already holds keeps working, against the new process. The addresses in
`briefcred daemon status` do not change.

**Not guaranteed.** A stream that never ends is cut when `handoff_drain_secs`
expires; the old daemon says so on its log before it exits. A session whose
profile the new daemon cannot load — because the file was deleted or edited to
a different name between the two — is dropped rather than adopted, and its
client is told the session is gone, which is the same answer an idle eviction
gives.

## If it fails

Nothing about the running daemon changes until the new one has confirmed it is
serving, so **every failure before that point leaves the machine exactly as it
was**: same process, same sockets, same sessions. The command exits non-zero
and says what went wrong, the half-started replacement is killed, and the
takeover socket is removed.

That is why the new daemon verifies the blob's signature before it adopts
anything, and why it answers `refused` rather than `ready` when it cannot: a
handoff that half happened would be two daemons each believing they own the
socket, which is worse than an upgrade that did not happen.

The blob also names the daemon it was built for — the recipient's ephemeral
public key is echoed back inside the signature — and carries the second it was
issued, which is refused if it is more than two minutes from the receiver's own
clock. Neither is what keeps the masters secret; the key agreement already does
that. What they buy is that a blob captured off a socket cannot be presented to
a *later* daemon as though it were current.

## The service manager still owns the *installed* daemon

`briefcred daemon upgrade` replaces the running process. It does not rewrite
the launchd or systemd unit, and the replacement is a child of the `briefcred`
command rather than of the service manager.

The practical consequences:

- On macOS, launchd's `KeepAlive` may start the old label again when the daemon
  it was watching exits. That copy finds a live socket, refuses to start a
  second daemon, and exits — which is the guard working, not a fault.
- The upgrade lasts until the next login or reboot, when the service manager
  starts whatever binary its unit names. To make it permanent, put the new
  binary at the path the unit already points at — which is what a package
  upgrade does — or run `briefcred install` again.

## Socket activation, on Linux

`briefcred install` on Linux writes a `briefcred.socket` unit alongside the
service unit. With it enabled, **systemd** holds the four listeners and passes
them to the daemon as `LISTEN_FDS`, so even an ordinary restart queues a
connecting client rather than refusing it.

```ini
[Socket]
ListenStream=%h/.local/share/briefcred/sock
ListenStream=127.0.0.1:9317
ListenStream=127.0.0.1:9318
ListenStream=127.0.0.1:9319
SocketMode=0600
Service=briefcred.service
```

The order of those lines is not cosmetic. systemd says only *how many*
descriptors it passed, so the unit's order and the daemon's are one fact
written in two places: IPC, metrics, HTTP proxy, Postgres proxy. The daemon
honours `LISTEN_FDS` only when `LISTEN_PID` names its own process, so an
inherited environment cannot make it adopt descriptors meant for something
else.

macOS has no equivalent this daemon uses, so there the LaunchAgent binds
nothing and `briefcred daemon upgrade` is the seamless path.

## What it records

| where | what |
| --- | --- |
| audit | `daemon_handoff` with `from_pid`, `to_pid`, `sessions`, and `outcome` — written by **both** daemons, so the log shows which process was serving at any moment |
| audit | `session_close` with reason `handoff` on the outgoing daemon: the session moved rather than ended, and its mints are deliberately **not** revoked |
| metrics | `briefcred_handoffs_total{outcome}`, with `handed_over`, `adopted` and `failed` all seeded at zero |

A rising `failed` is somebody whose upgrades are silently not taking, which
otherwise looks exactly like nobody upgrading.

## The one configuration key

| Key | Default | Meaning |
| --- | --- | --- |
| `handoff_drain_secs` | `30` | Seconds the outgoing daemon gives its in-flight requests and streams |

Long enough that an ordinary event stream is never cut, and bounded, because a
stream that never ends must not keep a replaced daemon resident for the rest of
the login.
