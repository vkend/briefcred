# Security policy

briefcred holds master credentials and hands out short-lived ones, so a flaw in
it can leak a secret it was built to keep. Please report one privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/vkend/briefcred/security/advisories/new).
Do not open a public issue, pull request, or discussion for a suspected
vulnerability.

A useful report says which version or commit you tested, the platform (macOS
or Linux, and the credential backend in use), the steps to reproduce, and what
an attacker gains. A proof of concept helps but is not required.

You should get an acknowledgement within a week. Once a fix is ready, the
advisory is published alongside the release that carries it, with credit to
the reporter unless they prefer otherwise.

## Scope

[`THREAT_MODEL.md`](THREAT_MODEL.md) states what each part of briefcred
guarantees and, as plainly, what it does not. A way around a guarantee that
document makes is in scope. A limitation the document already names, such as
a process running as the same user reaching the daemon's socket, is not a
vulnerability on its own, but a way to make that limitation worse than
described is.

## Supported versions

briefcred is pre-1.0. Only the latest release and `main` receive security
fixes.
