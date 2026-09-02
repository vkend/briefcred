# Revoking an SSH certificate

briefcred's `ssh-cert` minter signs an OpenSSH user certificate that is valid
for a few minutes and hands the subprocess the key it belongs to. This document
is about the other half: what happens when that certificate is revoked, why
that is not automatic, and what an operator has to do on their servers for it
to mean anything.

## The problem, stated honestly

**A signed certificate cannot be recalled.** It is a statement, signed by the
certificate authority, that a public key is good for certain principals until a
certain instant. Every server that trusts the CA will honour it until that
instant, whether or not briefcred still wants them to. There is no call to make
and no server to tell.

So `briefcred` revoking an SSH certificate means two different things, and only
one of them is under briefcred's control.

| What | Who does it | When it takes effect |
| --- | --- | --- |
| Delete the private key from this machine | briefcred | Immediately |
| Refuse the certificate at the server | `sshd`, if configured | When the server reads the KRL |

The first is real and immediate: the key file is deleted and nothing on the
laptop can present that certificate again. It is also the half that matters
most, because the private key is the thing an attacker who is *on the machine*
would take.

The second is what covers a certificate that has already left the machine — one
copied out of `$TMPDIR` before the revoke, or captured in transit. That needs a
key revocation list, and it needs your servers to be reading one.

## The KRL briefcred writes

Every revoke appends the certificate's serial number to:

```
<briefcred home>/state/ssh-krl
```

On macOS that is `~/Library/Application Support/briefcred/state/ssh-krl`; on
Linux, `$XDG_DATA_HOME/briefcred/state/ssh-krl`. `briefcred health` prints the
home directory if you are unsure.

The file is OpenSSH's own binary KRL format, the one `ssh-keygen -k` produces,
so every OpenSSH tool understands it:

```console
$ ssh-keygen -Q -l -f ~/Library/Application\ Support/briefcred/state/ssh-krl
# KRL version 4
# Generated at 20260901T142233
# Comment: briefcred

# Wildcard CA
serial: 10925763352062681902
serial: 2359381276194440189
```

It holds serial numbers and nothing else. A serial is a random 64-bit number
briefcred draws per mint, so the file names revoked certificates without
recording who used them, what they connected to, or when — a KRL you copy to
twenty servers is not an audit log and should not become one.

The certificates section is written with an **empty CA key**, which OpenSSH
reads as "any CA". A serial listed here is therefore revoked regardless of
which authority signed it. That is deliberate. Serials are random, so the
chance of shadowing another CA's certificate is negligible, and the direction
the ambiguity errs in is refusing a certificate rather than accepting one.

## Making a server honour it

Two directives in `sshd_config`:

```
# Certificates signed by this CA are accepted.
TrustedUserCAKeys /etc/ssh/briefcred_ca.pub

# ...unless they appear here.
RevokedKeys /etc/ssh/briefcred_krl
```

Then reload `sshd`. `RevokedKeys` is read **per authentication attempt**, not at
start-up, so replacing the file takes effect for the next connection with no
reload at all. That is what makes distribution the only hard part.

A file `sshd` cannot read is treated as fatal and *all* authentication is
refused — which is the safe direction, but it does mean a botched copy locks
you out. Copy to a temporary name and rename:

```sh
KRL=~/Library/Application\ Support/briefcred/state/ssh-krl
scp "$KRL" bastion:/tmp/briefcred_krl.new
ssh bastion 'sudo install -m 0644 /tmp/briefcred_krl.new /etc/ssh/briefcred_krl'
```

`install` writes through a rename, so `sshd` never sees a half-copied file.

## Distributing it

briefcred does not distribute the KRL. It cannot: it runs on a laptop, it has
no credentials for your fleet, and giving it any would be a much larger grant
than "may sign a certificate for myself". The file is a build artefact of your
machine and getting it to your servers is a job for whatever already
distributes configuration to them.

Whatever you use, the property to aim for is **short lag**, not zero lag. Some
sensible arrangements:

- **Configuration management.** Ansible, Chef, Puppet, or a `cron` job that
  pulls the file from object storage every minute. The window is the pull
  interval.
- **Central signing instead.** If several people mint certificates, run the CA
  somewhere shared, have briefcred talk to it, and merge every KRL centrally
  with `ssh-keygen -k -u -f merged.krl new-revocations`. A per-laptop KRL merged
  nowhere protects only against a certificate stolen from that laptop.
- **Nothing at all.** A legitimate choice when the TTL is short. Ten minutes of
  exposure for a certificate that has already been stolen may be an acceptable
  risk, and pretending otherwise while running no distribution is worse than
  saying so.

## What this does and does not buy you

**It does** stop a certificate that leaked before it expired, on every server
that has the current file.

**It does not** stop a session that is already open. `RevokedKeys` is checked at
authentication. An `ssh` connection established a minute before the revoke stays
up until it is closed. If that matters, pair the certificate with a
`force-command` or a short `ClientAliveInterval`, or do not use SSH
certificates for the thing you are worried about.

**It does not** apply to servers you forgot. A KRL is only as good as its
distribution, and a host outside the loop honours every certificate until its
`valid_before`. This is the single most important reason to keep `ttl_secs`
small in an `ssh-cert` profile: the expiry is enforced by every server without
being told anything, and the KRL is the backstop rather than the mechanism.

**It grows forever.** One serial per revoked certificate, eight bytes each. A
mint every minute for a year is about four megabytes, which `sshd` reads per
authentication. If you get anywhere near that, compact it: `ssh-keygen -k`
rewrites a KRL using ranges and bitmaps, which collapse contiguous serials, and
briefcred reads a file it did not write for the serials it does list. In
practice, deleting the file once every certificate in it has expired is simpler
and just as correct — a serial whose certificate expired last week revokes
nothing.

## Checking a certificate by hand

```console
$ ssh-keygen -Q -f /path/to/ssh-krl /path/to/id_ed25519-cert.pub
/path/to/id_ed25519-cert.pub (briefcred_t_4f2a91c05e83): REVOKED
```

Exit status is non-zero when anything given to it is revoked, which makes it
usable in a script. briefcred's own test suite runs exactly this against a
freshly minted and revoked certificate, so the format claimed here is the format
OpenSSH actually reads.
