# The profile schema

A profile is the work envelope: which credentials to mint, how the user proves
presence before they are minted, what the wrapped subprocess is allowed to be,
and how the minted material reaches its environment. One YAML document per
profile, in `profiles/` under the briefcred home.

This page is **generated**. The block below is the exact output of

```sh
briefcred profile schema
```

which `schemars` derives from the same Rust types `Profile::from_yaml_str`
deserialises into. A test in `briefcred-core` fails if the two disagree, so the
reference cannot describe a key the loader would reject or omit one it accepts.
Every `description` in it is the Rust doc comment on that field, which is why a
few of them carry rustdoc-style links to items in the source.

## What the schema does not say

The schema is a description of the document's shape. It is not the validator,
and three of the checks that decide whether a profile actually loads are not
expressible in JSON Schema at all:

- **`kind` must resolve to a registered minter.** The registry is populated by
  whatever minters the binary was linked with, so the legal set is a property
  of the build rather than of the schema.
- **`config` must satisfy the minter named in `kind`.** Each minter validates
  its own block when the profile is loaded, and rejects unknown keys in it the
  same way the outer document does. The schema describes `config` as an
  arbitrary value because a schema that guessed would be wrong for every minter
  but one. `README.md` documents each kind's block.
- **`${minted.<credential>.<field>}` must name a credential the profile
  declares**, and `policy` must compile against the fixed Cedar schema. Both are
  checked at load, and both are ordinary strings as far as JSON Schema is
  concerned.

A profile that satisfies this schema and fails one of those is rejected with an
error naming the file and the key.

## Using it

The document is a JSON Schema 2020-12 dialect, so an editor with YAML schema
support can complete and check profiles against it:

```sh
briefcred profile schema > ~/.config/briefcred-profile.schema.json
```

## The schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Profile",
  "description": "One profile document.\n\nUnknown keys are rejected at every level: a typo in a profile must fail\nloudly rather than silently disable a control.",
  "type": "object",
  "properties": {
    "name": {
      "description": "Profile name, as passed to `briefcred exec`.",
      "type": "string"
    },
    "description": {
      "description": "Human-facing description. Optional.",
      "type": [
        "string",
        "null"
      ]
    },
    "unlock": {
      "description": "How the user proves presence before this profile mints anything.",
      "$ref": "#/$defs/Unlock",
      "default": {
        "policy": "biometric",
        "cache_secs": 300
      }
    },
    "credentials": {
      "description": "The credentials this profile mints, in declaration order.",
      "type": "array",
      "items": {
        "$ref": "#/$defs/CredentialSpec"
      },
      "default": []
    },
    "exec": {
      "description": "What the wrapped subprocess is allowed to be.",
      "$ref": "#/$defs/ExecPolicy",
      "default": {
        "allow_argv0": [],
        "allow_args": []
      }
    },
    "env": {
      "description": "Environment handed to the subprocess, with `${...}` templates.",
      "type": "object",
      "additionalProperties": {
        "type": "string"
      },
      "default": {}
    },
    "env_passthrough": {
      "description": "Extra variables the subprocess may inherit from the caller.\n\nThe child starts with a cleared environment, so anything it needs has to\nbe named. [`crate::exec::DEFAULT_PASSTHROUGH`] is always included; this\nlist adds to it. Naming a variable here says only \"copy it if the caller\nhas it\", never \"set it\".",
      "type": "array",
      "items": {
        "type": "string"
      },
      "default": []
    },
    "trust_env": {
      "description": "Which of [`crate::ca::TRUST_ENV_VARS`] to set for the subprocess.\n\nAbsent means all of them, which is what almost every profile wants. An\nexplicit list narrows it, and an explicit empty list opts the profile\nout of the trust environment entirely — useful for a subprocess that\nmust keep talking to the real internet through its own trust store.",
      "type": [
        "array",
        "null"
      ],
      "items": {
        "type": "string"
      }
    },
    "policy": {
      "description": "Cedar policy source governing this profile's HTTP traffic.\n\nParsed and validated against [`crate::policy::SCHEMA_SOURCE`] when the\nprofile is loaded. Absent is not \"allow everything\": the proxy denies by\ndefault, so a profile with HTTP credentials and no policy forwards\nnothing.",
      "type": [
        "string",
        "null"
      ]
    },
    "policy_mode": {
      "description": "Whether a policy denial stops the request or is only recorded.",
      "$ref": "#/$defs/PolicyMode",
      "default": "enforce"
    },
    "quota": {
      "description": "How much work one session of this profile may do.\n\nAbsent means unmetered. A policy says what a session may do; this says\nhow much of it, which no allowlist of hosts and paths can express.",
      "anyOf": [
        {
          "$ref": "#/$defs/Quota"
        },
        {
          "type": "null"
        }
      ]
    },
    "proxy": {
      "description": "When the subprocess is pointed at briefcred's HTTP proxy.",
      "$ref": "#/$defs/ProxyMode",
      "default": "auto"
    }
  },
  "additionalProperties": false,
  "required": [
    "name"
  ],
  "$defs": {
    "Unlock": {
      "description": "Per-profile unlock policy.",
      "type": "object",
      "properties": {
        "policy": {
          "description": "The presence check to run. Defaults to [`UnlockPolicy::Biometric`].",
          "$ref": "#/$defs/UnlockPolicy",
          "default": "biometric"
        },
        "cache_secs": {
          "description": "How long a successful unlock is honoured for this profile, in seconds.\n\nZero means every session prompts. The cache is per profile, so\nunlocking a low-value profile never opens a high-value one.",
          "type": "integer",
          "format": "uint64",
          "minimum": 0,
          "default": 300
        }
      },
      "additionalProperties": false
    },
    "UnlockPolicy": {
      "description": "How the user proves presence.",
      "oneOf": [
        {
          "description": "Touch ID / Face ID, falling back to the device passcode.",
          "type": "string",
          "const": "biometric"
        },
        {
          "description": "Device passcode only.",
          "type": "string",
          "const": "passcode"
        },
        {
          "description": "No presence check. For unattended profiles; weakens the guarantee.",
          "type": "string",
          "const": "none"
        }
      ]
    },
    "CredentialSpec": {
      "description": "One credential to mint for a profile.",
      "type": "object",
      "properties": {
        "name": {
          "description": "Name used in `${minted.<name>.<field>}` templates. Unique per profile.",
          "type": "string"
        },
        "kind": {
          "description": "Minter kind, resolved against the minter registry at load time.",
          "type": "string"
        },
        "ttl_secs": {
          "description": "Lifetime of the minted credential in seconds.",
          "type": "integer",
          "format": "uint64",
          "minimum": 0,
          "default": 900
        },
        "source_key": {
          "description": "Key this credential's master is filed under in the master source.\n\nAbsent means the credential's own [`CredentialSpec::name`], which is\nwhat a profile with one master per credential wants. Naming it\nexplicitly lets several credentials share one master, or lets a\ncredential be renamed without moving the secret.",
          "type": [
            "string",
            "null"
          ]
        },
        "config": {
          "description": "Minter-specific configuration, interpreted by the minter for `kind`.\n\nDescribed to JSON Schema as an arbitrary value, which is the honest\nanswer: what is legal in here is decided by the minter named in\n[`CredentialSpec::kind`], and each one validates its own block when the\nprofile is loaded. A schema that guessed would be wrong for every\nminter but one.",
          "default": null
        }
      },
      "additionalProperties": false,
      "required": [
        "name",
        "kind"
      ]
    },
    "ExecPolicy": {
      "description": "Allowlists constraining the subprocess a profile may wrap.",
      "type": "object",
      "properties": {
        "allow_argv0": {
          "description": "Permitted `argv[0]` values, matched literally. Empty means \"any\".",
          "type": "array",
          "items": {
            "type": "string"
          },
          "default": []
        },
        "allow_args": {
          "description": "Regular expressions every argument must match one of. Empty means \"any\".\n\nThe match is **unanchored**: a pattern matches if it occurs anywhere in\nthe argument, so `DROP` permits `--x=DROP` and `SELECT` permits\n`NOT SELECT`. Anchor the patterns yourself with `^` and `$` wherever the\nwhole argument is what you mean, as in `'^-c$'`.\n\nLeft unanchored rather than changed, because anchoring silently would\nturn every existing profile's substring pattern into one that matches\nnothing — a list that refuses every argument rather than one that\npermits too many, which is a failure an operator discovers at the worst\nmoment.",
          "type": "array",
          "items": {
            "type": "string"
          },
          "default": []
        }
      },
      "additionalProperties": false
    },
    "PolicyMode": {
      "description": "Whether a policy decision is enforced or merely recorded.",
      "oneOf": [
        {
          "description": "A denial stops the request. The default, and the only safe default.",
          "type": "string",
          "const": "enforce"
        },
        {
          "description": "A denial is written to the audit log as `would_deny` and the request is\nforwarded anyway.\n\nThis is how a policy is written for a real workload: run in observe,\nread the `would_deny` rows, widen the policy until they stop, then\npromote to `enforce`. It is not a mode to leave a profile in.",
          "type": "string",
          "const": "observe"
        }
      ]
    },
    "Quota": {
      "description": "A per-session token bucket: a sustained rate, a burst, and a hard cap.\n\nCharged one token per HTTP proxy request, per Postgres proxy connection, and\nper `briefcred exec` or `briefcred get` that mints. The bucket is created\nwhen the session opens and dies with it, so two concurrent runs of the same\nprofile get a budget each rather than competing for one.",
      "type": "object",
      "properties": {
        "rate": {
          "description": "Tokens added per second, sustained. Must be greater than zero.\n\nFractional on purpose: `rate: 0.1` is six an hour, which is the shape a\nquota on something expensive wants.",
          "type": "number",
          "format": "double"
        },
        "burst": {
          "description": "Tokens the bucket holds, and how many may be spent at once. At least 1.",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "total": {
          "description": "A hard cap for the whole session, if there is one.\n\nOnce spent, every charge fails until the session closes: no waiting\nbrings it back, because the budget is the session's rather than the\nminute's.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        }
      },
      "additionalProperties": false,
      "required": [
        "rate",
        "burst"
      ]
    },
    "ProxyMode": {
      "description": "When `briefcred exec` sets `HTTPS_PROXY` and friends for a profile.",
      "oneOf": [
        {
          "description": "Only when the profile declares at least one HTTP credential.\n\nThe right answer almost always: a profile that mints nothing the proxy\nserves has nothing to gain from routing its traffic through it, and\nrouting it anyway would break a subprocess whose upstream briefcred has\nno leaf for.",
          "type": "string",
          "const": "auto"
        },
        {
          "description": "Always, even when the profile declares no HTTP credential.\n\nFor a profile whose value is the *policy* rather than a credential:\npointing a subprocess at the proxy with a Cedar allowlist and no\ncredentials at all is a usable egress control.",
          "type": "string",
          "const": "always"
        }
      ]
    }
  }
}
```
