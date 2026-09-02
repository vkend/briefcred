# The agent hook

`briefcred-hook` is a `PreToolUse` hook. An agent runs it before every shell
tool call, hands it the call as JSON on stdin, and reads a decision as JSON on
stdout. It is a filter: no state, no daemon of its own, one process per call.

## Wiring it up

In `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "briefcred-hook" }]
      }
    ]
  }
}
```

The binary is installed next to `briefcred` and `briefcred-daemon`.

## The rules

`briefcred-hook` reads `hook-rules.yaml` from the configuration directory
(`~/Library/Application Support/briefcred/hook-rules.yaml` on macOS). A missing
file means no rules, which means the hook has no opinion about anything.

```yaml
rules:
  # First match wins, so the specific rule goes above the general one.
  - match: '^psql .*\bDROP\b'
    profile: db-ro
    decision: deny

  - match: '^psql '
    profile: db-ro
    decision: allow
    rewrite: true

  - match: '^pg_dump '
    profile: db-ro
    decision: ask
```

| key | meaning |
| --- | --- |
| `match` | A regular expression tried against the whole command line. |
| `profile` | The profile whose `exec` policy governs commands this rule matches. |
| `decision` | `allow`, `deny`, or `ask`. |
| `rewrite` | With `allow`, replace the command with a `briefcred exec` of it. |

Patterns are compiled when the file is read, so a broken regex is an error the
first time the hook runs rather than a rule that silently never matches.

## How a decision is reached

Two things decide, and they are not equals.

1. **The rule file routes.** It says whether briefcred has an opinion about this
   command at all. A regex over a command line is a blunt instrument, and it is
   meant to be.
2. **The daemon enforces.** For any rule that would let the command run, the
   hook asks the daemon `HookCheck`, which runs the same `exec.allow_argv0` and
   `exec.allow_args` check `briefcred exec` would. Nothing is minted: the tool
   call being asked about may never happen.

The daemon can turn an `allow` into a `deny`. It can never turn a `deny` into an
`allow` — a `deny` rule is answered without asking the daemon at all. The hook
is only ever more restrictive than the rule file, because the rule file is the
easier of the two to get wrong.

| rule | daemon says | hook answers |
| --- | --- | --- |
| `deny` | *not asked* | `deny` |
| `allow` | permitted | `allow`, rewritten if `rewrite: true` |
| `allow` | refused | `deny`, quoting the profile's own complaint |
| `allow` | unreachable | `ask`, saying it could not check |
| `ask` | permitted | `ask` |
| *no match* | *not asked* | nothing at all |

### Failing open

When the daemon is not running the hook answers `ask`, and when no rule matches
it prints nothing and exits 0. A credential broker that blocks `ls` because a
background service is down is one nobody keeps installed.

Failing open grants nothing. Without the daemon there is no credential to grant,
so the worst case is the agent running the command with whatever it already
had — which is what it would have done if briefcred were not installed.

The hook exits 0 whatever it decides. A non-zero exit from a hook means the hook
itself failed; briefcred expresses denial in the payload, not in the exit code.

## `updatedInput`, and its caveats

With `rewrite: true`, the hook returns:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "briefcred: running under profile `db-ro` ...",
    "updatedInput": { "command": "briefcred exec --profile=db-ro -- psql -c 'SELECT 1'" }
  }
}
```

Five things to know before turning `rewrite` on.

**The agent does not have to honour it.** `updatedInput` is a request. An agent
that ignores it runs the original command, unwrapped and with no minted
credential. Treat rewriting as a convenience, never as a control: if a command
*must not* run without briefcred, the thing that stops it is the backend not
accepting the credentials the agent already has.

**The agent's transcript keeps the original.** The model asked for `psql ...`
and sees that it asked for `psql ...`. It may reason about the command it wrote
rather than the one that ran, and may be surprised by an error mentioning
briefcred. Say so in the profile description and in your agent's instructions.

**The rewrite is textual, and the shell is not.** The hook wraps the command
line as one string after `--`. That works for a simple command. It does **not**
do what you want for a pipeline, a redirect, or a `&&` chain: only the first
command ends up under briefcred, and the rest run in the wrapper's environment.
Write `match` patterns tight enough that they cannot match a compound command,
or use `decision: ask` and let a person look at it.

**Quoting survives, escaping is the caller's problem.** The command is passed
through unchanged. Whatever quoting the agent wrote is what the shell running
the rewritten line will see.

**`--` matters.** The rewrite always puts `--` before the command, so an agent's
`psql --profile analytics` is not read as briefcred's own `--profile`. Do not
build the wrapped command by hand without it.

## What the hook never does

It never mints. `HookCheck` is the policy question on its own, because a hook
runs before a tool call that may never happen, and a principal created for a
command that is then declined would have to be revoked by the reconciler.

It never sees a credential. Nothing on the hook's path returns credential
material, and the hook has no access to a session.

## Debugging

The hook writes diagnostics to stderr, which the agent shows with its hook
output. To see what it would answer for a command:

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"psql -c \"SELECT 1\""}}' \
  | briefcred-hook
```

No output means no rule matched. To check what the daemon thinks separately, run
the command under `briefcred exec` directly: a policy denial exits 4 and prints
the offending argument.
