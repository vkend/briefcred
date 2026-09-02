# Writing a proxy policy

briefcred's HTTP proxy asks one question of every request a wrapped subprocess
makes: **may this session make this request?** The answer comes from Cedar
source text in the profile's `policy:` field, evaluated against a schema
briefcred fixes.

The default is deny. A profile with no `policy:` forwards nothing, and a
profile whose policy matches nothing forwards nothing. There is no "allow all"
you can reach by omission.

## The schema

Three things go into the decision, and nothing else.

| Cedar | briefcred |
| --- | --- |
| `principal` | `Session::"<session id>"` — one `briefcred exec`, one identity |
| `action` | `Action::"GET"`, `"POST"`, `"PUT"`, `"PATCH"`, `"DELETE"`, `"HEAD"`, `"OPTIONS"` |
| `resource` | `Http::"<host><path>"`, with attributes `host`, `path`, `scheme` |

The seven methods are grouped under `Action::"http"`, so `action in
[Action::"http"]` permits any of them without listing them. A method that is
not one of the seven — `TRACE`, say — has no action at all, so no policy can
permit it and the proxy refuses it before Cedar is consulted.

```cedar
entity Session;

entity Http = {
  host: String,
  path: String,
  scheme: String,
};

action http;

action GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS in [http]
  appliesTo {
    principal: [Session],
    resource: [Http]
  };
```

### What is deliberately absent

**The query string.** It is stripped before the policy sees the path and before
the audit row is written. Query strings routinely carry API keys, and a policy
that could match on one would be a policy whose evaluation had to hold a
credential — and an audit log that recorded the decision would record the
credential with it.

**The request body.** Same reason, more so: a body is whatever the agent
decided to send, and parsing one to make a security decision means the parser
is now attack surface.

**Headers.** The one header that matters is the credential, and briefcred
already knows which credential the request is for from the token.

## A first policy

The narrowest useful shape: one host, one method, one path.

```yaml
policy_mode: enforce
policy: |
  permit(
    principal,
    action == Action::"GET",
    resource
  ) when {
    resource.host == "api.openai.com" && resource.path == "/v1/models"
  };
```

That permits `GET https://api.openai.com/v1/models` and nothing else. A `POST`
to the same path is denied. A `GET` to `/v1/chat/completions` is denied. A
`GET` to `evil.example/v1/models` is denied.

Add each endpoint you actually need:

```cedar
permit(
  principal,
  action == Action::"POST",
  resource
) when {
  resource.host == "api.openai.com"
    && resource.path == "/v1/chat/completions"
};
```

## Writing one for a real workload

You will not guess the endpoint list correctly. Start in observe mode:

```yaml
policy_mode: observe
```

The proxy still evaluates the policy, still writes a `ProxyRequest` audit row,
and forwards the request anyway — with `decision: "would_deny"` where enforcing
would have refused. So:

1. Set `policy_mode: observe` with whatever policy you have.
2. Run the workload.
3. Read the log: `briefcred audit --event proxy_request`.
4. Every `would_deny` row names a method, a host and a path. Decide, one at a
   time, whether it belongs in the policy.
5. When the `would_deny` rows stop, set `policy_mode: enforce`.

Observe mode is a way to *write* a policy, not a way to run one. A profile left
in observe has a policy that logs and a proxy that forwards everything.

## Useful clauses

**A whole host, any method.** The loosest thing worth writing, and a reasonable
starting point for step 1 above.

```cedar
permit(principal, action in [Action::"http"], resource)
when { resource.host == "api.openai.com" };
```

**A path prefix.** Cedar's `like` uses `*` as the wildcard.

```cedar
permit(principal, action == Action::"GET", resource)
when { resource.host == "api.github.com" && resource.path like "/repos/acme/*" };
```

Prefer an exact list to a prefix where you can. `/v1/*` on an LLM vendor
permits fine-tuning jobs and file uploads alongside the completions you meant.

**Reads but not writes.**

```cedar
permit(principal, action in [Action::"GET", Action::"HEAD"], resource)
when { resource.host == "api.example.com" };
```

**HTTPS only.** Worth adding when a profile also permits plain `http://`
upstreams for something local.

```cedar
permit(principal, action in [Action::"http"], resource)
when { resource.scheme == "https" && resource.host == "api.example.com" };
```

**A carve-out.** `forbid` beats `permit` unconditionally, which makes it the
right way to express "everything under this prefix except that one thing".

```cedar
permit(principal, action in [Action::"http"], resource)
when { resource.host == "api.example.com" };

forbid(principal, action, resource)
when { resource.path like "/admin*" };
```

## When a policy is wrong

A policy is compiled and validated against the schema **when the profile is
loaded**, so a typo is an error next to the file that has it rather than a
request that is quietly denied later. Two things are caught:

- Cedar that does not parse. `permit(principal` fails with the parser's own
  complaint.
- Cedar that parses but does not fit the schema. `resource.query == "x"` fails
  because the schema has no `query` attribute, and `principal == User::"bob"`
  fails because the schema has no `User` entity type. Both would otherwise be
  clauses that can never match, which is far worse than an error.

If a policy stops compiling underneath a running daemon — the file was edited
into an invalid state — the proxy denies that profile's requests and says so on
its log. It does not fall back to the last good policy: a proxy about to attach
a real credential should not be running on a policy nobody can read.

## What the decision is recorded as

Every request through the proxy writes one audit row, whatever happened to it:

```json
{"event":"proxy_request","ts":"…","mint_id":"briefcred_t_…","method":"GET",
 "host":"api.openai.com","path":"/v1/models","status":200,
 "req_bytes":0,"resp_bytes":8241,"latency_ms":312,"decision":"allow"}
```

`decision` is one of five labels, which also appear on
`briefcred_proxy_requests_total{decision,status_class}`:

| `decision` | what it tells you |
| --- | --- |
| `allow` | the policy permitted it |
| `deny` | the policy refused it, or the token did not authorise |
| `would_deny` | the policy refused it and `policy_mode` is `observe` |
| `swap_error` | the policy allowed it; briefcred could not attach the credential |
| `upstream_error` | the policy allowed it; the upstream was unreachable |

The last two are deliberately **not** `deny`. They are the cases where your
policy was right and something else went wrong, so a rising `deny` count means
a policy that is too narrow, a rising `would_deny` count means a profile
somebody forgot to promote to `enforce`, and a rising `swap_error` or
`upstream_error` count means nobody needs to touch the policy at all.

`status` is the upstream's own code, and is absent on every row that never
reached an upstream.
