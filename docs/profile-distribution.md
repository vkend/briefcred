# Distributing profiles

A profile is not configuration. It names the hosts a subprocess may reach, the
credentials briefcred will mint on its behalf, and the Cedar policy that
decides what the proxy forwards. A profile you did not write is an instruction
from whoever wrote it — and, if it arrived unsigned over the network, from
whoever last had write access to the server it came from.

So briefcred keeps two kinds of profile apart and holds them to different
standards.

| | Where | Signature | Who chose it |
| --- | --- | --- | --- |
| Local | `profiles/*.yaml` | not required | you |
| Registry | `profiles/registry/<name>/*.yaml` | **required** | the publisher |

A local profile needs no vouching: nothing signs what you wrote yourself. A
registry profile is dropped unless a detached signature beside it verifies
against a trust root you named in `daemon.toml`.

## The signature format

Minisign, unmodified. A signature is a `<file>.minisig` beside the profile, and
briefcred's keys are minisign keys, so `minisign -S` can sign a profile
briefcred will accept, and `minisign -V` can check one briefcred produced.

The wire format is four lines: an untrusted comment, base64 of an algorithm
tag plus the eight-byte key id plus an Ed25519 signature, a *trusted* comment,
and base64 of a second signature over the first signature concatenated with the
trusted comment.

There are two algorithm tags, and **briefcred accepts both**:

| Tag | Signature is over | Who writes it |
| --- | --- | --- |
| `Ed` | the file's bytes | briefcred, and `minisign -S -H`-less older releases |
| `ED` | BLAKE2b-512 of the file | stock `minisign -S` since 0.10 |

briefcred only ever *produces* `Ed`, so a briefcred signature verifies under
every minisign release; it accepts `ED` as well, because refusing it would mean
refusing the reference implementation's ordinary output. Secret keys are read
in minisign's password-less form, including the all-zero checksum that
`minisign -G -W` writes in place of a real one — an all-zero field means
"unchecked", not "wrong", and the key's public half is still checked against
its private half either way.

All three directions are covered by tests that run whenever `minisign` is on
the machine and skip with a printed reason when it is not: a briefcred
signature checked by `minisign -V`, a stock `minisign -S` signature checked by
`briefcred profile verify`, and a `minisign -G -W` key used by
`briefcred profile sign`.

The two signatures are both checked. Only the trusted comment is covered by the
second one, which is why briefcred puts the file name there: a signature lifted
off one profile and dropped beside another still names the file it was made
for.

## Publishing

```console
$ briefcred profile keygen --out ~/keys
briefcred profile keygen
  secret     /Users/you/keys/briefcred.key (mode 0600, no password)
  public     /Users/you/keys/briefcred.pub
  key id     3F2A9C1D77B40E56

add this line to `trust_roots` in daemon.toml:
  RWQ...
```

The secret key is **password-less**, and the command says so rather than
letting you find out. briefcred signs in release pipelines, where there is
nobody to prompt for a passphrase; the protection on the file is its `0600`
mode and the filesystem it sits on. Treat it like any other release signing
key: keep it off shared machines, and if it leaks, rotate the trust root.

Sign each profile, and publish the `.yaml` and its `.minisig` together:

```console
$ briefcred profile sign profiles/analytics.yaml --key ~/keys/briefcred.key
signed profiles/analytics.yaml with key 3F2A9C1D77B40E56
  wrote profiles/analytics.yaml.minisig

$ briefcred profile verify profiles/analytics.yaml --pub ~/keys/briefcred.pub
profiles/analytics.yaml: signature is valid
```

## Consuming

`daemon.toml` names the keys you believe and the registries you fetch:

```toml
[profiles]
trust_roots = ["RWQ..."]
registries = [
  { name = "platform", url = "git+https://github.com/example/profiles.git" },
  { name = "team",     url = "https://profiles.example.com/team" },
]
dev_mode = false
```

A trust root that is not a well-formed minisign public key stops the daemon
starting, rather than leaving it running with a trust root it silently ignores.
An empty `trust_roots` is not "trust everything": it means no registry profile
can ever load.

### The three URL schemes

- **`file:///absolute/path`** — a directory of `*.yaml` and `*.minisig`. For a
  registry on a shared volume, and what the test suite uses.
- **`https://base`** — an `index.json` at `<base>/index.json` listing
  `{"profiles":[{"name","path","sha256"}]}`, then each YAML and its `.minisig`
  underneath. The SHA-256 is checked before the signature, so a mirror serving
  the wrong bytes is reported as that rather than as a signature failure. The
  fetch times out at ten seconds and will not follow a redirect to another
  host.
- **`git+https://repo`** — a `git clone --depth 1` through the system `git`,
  then read as a directory. The system binary rather than a library, because a
  private registry is usually behind an authenticating remote and `git` already
  knows about the credential helper, the SSH agent, and the proxy settings.

Nothing else. `http://`, `ssh://`, and a bare path are refused by name rather
than guessed at.

### Syncing

```console
$ briefcred profile sync
briefcred profile sync
  platform         4 profile(s) into ~/Library/Application Support/briefcred/profiles/registry/platform
  team             2 profile(s) into ~/Library/Application Support/briefcred/profiles/registry/team
    ! draft.yaml: no .minisig alongside it
```

Each registry is fetched into a staging directory and moved into place at the
end, so a sync that fails halfway leaves the previous contents intact rather
than a directory holding half of two registries. A withdrawn profile really
does disappear: the directory is replaced, not merged into.

One exception, and it is deliberate: **a fetch that produced no profiles at all
will not replace a registry directory that currently has some.** An empty
result over a working set is evidence of a bad URL or a moved branch, not of a
publisher who withdrew everything, and replacing a working profile set with an
empty directory on that evidence is the worst available answer. The sync
reports it as an error, keeps what is there, and exits non-zero. A first sync
of a genuinely empty registry still succeeds, because there is nothing to
destroy.

The exit code is non-zero if any file was skipped or any registry failed, so a
pipeline notices that half a registry did not arrive. One unreachable registry
never stops the others.

The daemon watches the registry subtree, so a sync needs no restart.

## Precedence

The daemon loads the registry subtree first, then the local directory. A local
profile with the same name wins, and says what it shadows:

```console
$ briefcred profile show analytics
analytics
  description  read-only analytics shell
  unlock       biometric (300s cache)
  source       local
  file         ~/Library/Application Support/briefcred/profiles/analytics.yaml
  signature    unsigned
  overrides    the `analytics` profile published by platform
  credentials
    db (postgres-dynamic, 900s, master `analytics-db`)
```

That is what makes a registry usable: take the set somebody publishes, and
override the one profile you need to change without forking the rest.

Two registries publishing the same name resolve in alphabetical order of
registry name, and the collision is reported as a warning. The alternative —
last one wins — would make which profile you get depend on a directory listing.

## Verification happens twice

`briefcred profile sync` refuses to write a file no trust root vouches for, and
the daemon checks again at load. That is deliberate: the CLI's check is
immediate feedback for the person running the sync, and the daemon's is the one
that decides what runs. A file that appears in the registry directory by any
other route — a script, an editor, an attacker with write access — still has to
pass the daemon's check.

Last-good does not extend to trust. A broken *file* leaves the previous profile
set in force, because dropping every profile over one typo turns a typo into an
outage. A profile whose signature stops verifying is **dropped on the next
reload**, because continuing to run a profile precisely because its signature
has just gone bad is the opposite of what the news calls for.

## `dev_mode`

Writing a registry is impossible while every unsigned draft is refused, so
there is a switch:

```toml
[profiles]
dev_mode = true
```

It is loud about what it costs. Every unverified file produces:

- a `!! PROFILE NOT VERIFIED` line on the daemon's stderr at every load,
- a `!!` line above the `briefcred profiles` table, and `signature: dev_mode`
  in that profile's row and in `briefcred profile show`,
- a `profile_trust_warning` audit row with `action: "loaded_dev_mode"` and the
  file's path.

The audit rows are the point. An operator who turns `dev_mode` on has to be
able to establish afterwards exactly which unverified profiles their daemon was
running, and for how long.

`dev_mode` is for writing a registry. It is not a way to use one.
