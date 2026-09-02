# Policy cookbook

Five policies worth copying, each one shipped as a working profile under
`examples/profiles/`. `docs/policy.md` covers the schema and how a policy is
written from scratch; this is the shorter document you reach for when you
already know what you want to express.

Every Cedar block below appears verbatim in the profile named beside it, and a
test in `crates/briefcred-core/tests/example_profiles.rs` fails if it stops
doing so. So a recipe here is one that loads, validates, and compiles.

| recipe | profile | what it bounds |
| --- | --- | --- |
| [Method × path](#method--path) | `openai.yaml` | which endpoints exist at all |
| [A time window](#a-time-window) | `anthropic.yaml` | when the key works |
| [A per-session cap](#a-per-session-cap) | `github.yaml` | how many requests |
| [A byte budget](#a-byte-budget) | `stripe.yaml` | how much data leaves |
| [Combining with a quota](#combining-with-a-quota) | `stripe.yaml` | how fast |

## The two halves of the context

A policy sees four things about the request — `action`, and the resource's
`host`, `path` and `scheme` — and four about the *session*, in `context`:

| attribute | type | what it is |
| --- | --- | --- |
| `context.hour` | Long | hour of day, 0 to 23, **UTC** |
| `context.weekday` | Long | 0 for Monday through 6 for Sunday, **UTC** |
| `context.requests_so_far` | Long | proxied requests this session made *before* this one |
| `context.resp_bytes_so_far` | Long | response bytes this session was sent before this one |

Both counters are "before", not "including". The first request of a session
sees `requests_so_far == 0`, so `context.requests_so_far < 500` permits exactly
five hundred requests. `resp_bytes_so_far` has to work that way whether anyone
likes it or not: the size of a response is not known until it has been sent, so
a budget can only ever be checked against what the session has already had.

The clock is UTC and there is no option to change it. A policy meaning
"business hours" that read the timezone the daemon happened to start in would
be a policy that silently changed meaning when the laptop crossed a border.
Shift the numbers yourself.

## Method × path

The narrowest useful shape, and the one to start from: name the host, name the
method, name the path. From `examples/profiles/openai.yaml`.

```cedar
permit(principal, action == Action::"GET", resource)
when {
  resource.host == "api.openai.com" && resource.path == "/v1/models"
};

permit(principal, action == Action::"POST", resource)
when {
  resource.host == "api.openai.com"
    && resource.path == "/v1/chat/completions"
};
```

Two clauses because they are two different permissions. `GET /v1/models` is the
harmless call every SDK makes at startup; `POST /v1/chat/completions` is the
one that costs money. A single clause with `action in [Action::"http"]` would
permit `DELETE /v1/models`, which is not a thing anyone meant to allow.

Resist `resource.path like "/v1/*"`. On an LLM vendor that prefix covers
fine-tuning jobs and file uploads, which are the two most expensive things in
the API and the two most useful to somebody exfiltrating a corpus.

## A time window

From `examples/profiles/anthropic.yaml`. Weekdays, 08:00 to 19:00 UTC.

```cedar
permit(principal, action in [Action::"http"], resource)
when {
  resource.host == "api.anthropic.com"
    && resource.path == "/v1/messages"
    && context.weekday <= 4
    && context.hour >= 8
    && context.hour < 19
};
```

`weekday <= 4` is Monday through Friday. `hour >= 8 && hour < 19` is the
half-open interval you want: `<= 19` would include everything up to 19:59.

What this is worth: an agent that wakes at three in the morning to do something
nobody asked for is refused, and a copy of the environment taken on a Friday
evening is inert until Monday. It is not a strong control on its own — the
attacker who has your token can wait until Tuesday — but it is a very cheap one
that turns a class of incidents into a row in the audit log.

## A per-session cap

From `examples/profiles/github.yaml`. Read-only, one organisation, five hundred
requests.

```cedar
permit(principal, action in [Action::"GET", Action::"HEAD"], resource)
when {
  resource.host == "api.github.com"
    && resource.path like "/repos/acme/*"
    && context.requests_so_far < 500
};
```

Three separate narrowings, and it is worth being clear about which does what.
`action in [Action::"GET", Action::"HEAD"]` means no session opened with this
profile can push, merge or delete. The `like` prefix keeps the token inside one
organisation while leaving repository names free, which they have to be. And
`requests_so_far < 500` is the one that distinguishes an agent reading the file
it was asked about from an agent cloning the org one call at a time.

Request 501 gets a `403` and a `ProxyRequest { decision: "deny" }` row, exactly
like any other policy refusal — the counter is part of the policy, so hitting
it is a policy denial and not a quota rejection. The two look different in the
audit log on purpose; see the next section but one.

## A byte budget

From `examples/profiles/stripe.yaml`. Ten mebibytes of charge records.

```cedar
permit(principal, action == Action::"GET", resource)
when {
  resource.host == "api.stripe.com"
    && resource.path like "/v1/charges*"
    && context.resp_bytes_so_far < 10485760
};
```

A request cap bounds how many times an agent asks; a byte budget bounds how
much it gets. They come apart badly on any endpoint that paginates: five
hundred requests of a hundred records each is fifty thousand records, and one
request with `limit=100000` is one request.

Note what the budget cannot do. It is checked *before* the request, against
what the session has already been sent, so the request that crosses the line is
allowed and the next one is refused. A single response can therefore overshoot
by its own size. That is inherent — briefcred would have to buffer a whole
response to do better, and it deliberately streams — so pick a budget where
being one response over does not matter.

## Combining with a quota

A policy cannot say "not this fast". Cedar is evaluated per request against
facts about that request, and there is no clock in it that ticks. That is what
`quota:` is for, and it is a different block in the profile rather than a
Cedar clause:

```yaml
quota:
  rate: 0.5
  burst: 5
  total: 50
```

Half a token a second sustained, five available at once, fifty for the whole
session. One token is spent per HTTP proxy request, per Postgres proxy
connection, and per `briefcred exec` or `briefcred get` that mints.

`examples/profiles/stripe.yaml` runs that quota alongside a second policy
clause, and the pair is the point of this section:

```cedar
permit(principal, action == Action::"POST", resource)
when {
  resource.host == "api.stripe.com"
    && resource.path == "/v1/refunds"
    && context.requests_so_far < 20
};
```

The clause says at most twenty refunds ever. The quota says at most five in the
next ten seconds. Neither implies the other, and the profile wants both: twenty
may be a reasonable day's work and is never a reasonable four seconds' work.

### Which limit refused me

They are deliberately distinguishable, because the fixes are different.

| | policy limit | quota |
| --- | --- | --- |
| HTTP status | `403` | `429`, with `Retry-After` |
| response body | none | `{"error":"briefcred quota exceeded"}` |
| audit `decision` | `deny` | `quota` |
| Postgres SQLSTATE | `28000` | `53300` |
| metric | `briefcred_proxy_requests_total{decision="deny"}` | `briefcred_quota_rejections_total{profile,surface}` |

A rising `deny` count means a policy that is too narrow for what the workload
actually does. A rising `quota` count means the workload is doing the right
things too quickly. Widening the policy will not help the second and raising
the quota will not help the first.

Two more things worth knowing about the quota:

- **A denied request still costs a token.** The charge happens before the
  policy is evaluated. The expensive thing to defend against is a loop, and a
  loop that is being denied is still a loop — one that would otherwise get an
  unmetered retry channel precisely because it is doing something forbidden.
- **`total` does not refill.** Once a session has spent it, every charge fails
  until the session is closed, and the `429` comes back without a
  `Retry-After` because there is no time at which retrying would work. Close
  the session and open a new one.

Watch `briefcred_quota_saturation{profile}` to see this coming: it runs from 0
for an untouched bucket to 1 for an empty one, and a profile sitting at 1 is
one being throttled right now.
