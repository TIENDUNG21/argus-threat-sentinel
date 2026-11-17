# Rules

Argus detections are plain TOML files. The 25 built-in rules live in
[`src/argus/rules/builtin/`](../src/argus/rules/builtin); your own files are
added with `argus scan --rules my-rules.toml` and checked with
`argus rules check my-rules.toml`.

## A rule file

```toml
[[rule]]
id = "ssh-password-spray"            # lower-case letters, digits, dashes
title = "SSH password spraying"
severity = "medium"                  # low | medium | high | critical
technique = "T1110.003"              # MITRE ATT&CK technique id
source = "ssh"                       # web | ssh (omit to match both)
description = "Failed passwords for six or more user names from one address."
when = 'action == "failed_password"' # condition, see below (omit to match all)
group_by = ["ip"]                    # default ["ip"]
threshold = { count = 6, window = "15m", distinct = "user" }
```

Unknown keys, unknown fields, bad durations, invalid regular expressions,
literals of the wrong type and duplicate ids are rejected when the file is
loaded, with the file name, the rule id and (for conditions) the column:

```
custom.toml: rule 'demo': when: column 1: unknown field 'stauts' (did you mean 'status'?); ...
```

`technique` must be in the built-in catalog (`src/argus/attack.py`) or the rule
must name its `tactic` (`reconnaissance`, `initial-access`, ...).

## Condition language

```
status >= 400 and not (path startswith "/static/" or ext in ["css", "js"])
```

| Operator | Works on | Meaning |
|---|---|---|
| `==` `!=` | any field | equality |
| `<` `<=` `>` `>=` | numbers | ordering |
| `~` `!~` | text | regular expression search (Python `re`, use `(?i)` for case-insensitive) |
| `contains` `icontains` | text | substring, `icontains` ignores case |
| `startswith` `endswith` | text | prefix / suffix |
| `in` `not in` | any field | membership in a list literal `["a", "b"]` |
| `and` `or` `not` `( )` | conditions | `not` binds tighter than `and`, which binds tighter than `or` |

A bare boolean field (`invalid_user`) is a condition on its own.

String literals use `"..."` or `'...'` and are raw: a backslash only escapes
the quote character, so `"\.php$"` is the regular expression `\.php$`. Inside
a TOML literal string (`'...'` or `'''...'''`) nothing needs double escaping.

### Fields

| Field | Type | Source | Meaning |
|---|---|---|---|
| `source` | text | both | `web` or `ssh` |
| `ip` | text | both | client address |
| `user` | text | both | SSH user name, or the HTTP auth user of an access log |
| `hour` | number | both | hour of day, UTC |
| `host` | text | ssh | syslog host name |
| `method` | text | web | HTTP method |
| `target` | text | web | request target as logged (`/a?b=c`) |
| `path` | text | web | target without the query, as logged |
| `query` | text | web | query string, as logged |
| `uri` | text | web | `path?query` after repeated percent-decoding (catches `%252e`) |
| `ext` | text | web | lower-case extension of the last path segment |
| `protocol` | text | web | `HTTP/1.1`, ... |
| `status` | number | web | response status |
| `bytes` | number | web | response body size |
| `referrer` | text | web | Referer header |
| `user_agent` | text | web | User-Agent header |
| `action` | text | ssh | `failed_password`, `failed_publickey`, `failed_other`, `accepted_password`, `accepted_publickey`, `accepted_other`, `invalid_user`, `max_auth_exceeded`, `no_ident`, `bad_banner`, `preauth_close` |
| `invalid_user` | boolean | ssh | the user name does not exist on the server |
| `auth_method` | text | ssh | `password`, `publickey`, `keyboard-interactive/pam`, ... |
| `port` | number | ssh | client source port |

## Rule kinds

Every rule groups matching events by `group_by` (default: the client address)
and produces **episodes**: once a rule fires for a group, further matching
events extend the same alert until the group stays quiet for longer than the
window. A brute force of 5,000 attempts is one alert with `count = 5000`, not
5,000 alerts.

**threshold** (the default; without a table it is `count = 1`, `window = "10m"`).
Fires when the sliding window `[now - window, now]` holds `count` matching
events, or `count` different values of the `distinct` field.

**sequence**: ordered steps within `within`, each with its own condition and
count. The first step uses a sliding window, so a long brute force that
finally succeeds is still linked to the success.

```toml
[rule.sequence]
within = "30m"
steps = [
  { when = 'action == "failed_password"', count = 5 },
  { when = 'action startswith "accepted"' },
]
```

**new_value**: after a `learn` period (starting at the first matching event),
fires when a group shows a value of `field` it has never shown before.

```toml
group_by = ["user"]
new_value = { field = "ip", learn = "24h" }
```

## Built-in detections

Each one has a positive and a near-miss negative test in
[`tests/detections/`](../tests/detections), and the technique mapping is pinned
by `tests/detections/test_catalog.py`.

### SSH (auth log)

| Rule | Severity | ATT&CK technique | Logic |
|---|---|---|---|
| `ssh-brute-force` | medium | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing | 10 failed passwords / 5m per address |
| `ssh-password-spray` | medium | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying | 6 distinct users failing / 15m per address |
| `ssh-brute-force-success` | critical | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing | 5 failures then a successful login / 30m |
| `ssh-root-login` | high | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) Valid Accounts: Local Accounts | any successful root login |
| `ssh-new-source-for-user` | medium | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | new address for a user after 24h of learning |
| `ssh-banner-scan` | low | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) Scanning IP Blocks | 3 handshakes never completed / 2m |
| `ssh-max-auth-exceeded` | medium | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing | any "maximum authentication attempts exceeded" |

### Web reconnaissance

| Rule | Severity | ATT&CK technique | Logic |
|---|---|---|---|
| `web-scanner-user-agent` | medium | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) Vulnerability Scanning | scanner name in the User-Agent |
| `web-wordlist-scan` | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) Wordlist Scanning | 404 on 20 distinct paths / 2m |
| `web-sensitive-file-probe` | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) Wordlist Scanning | 3 distinct secret/backup paths / 10m |
| `web-sensitive-file-exposed` | high | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Credentials In Files | credential-bearing file served with 200 |
| `web-user-enumeration` | low | [T1589](https://attack.mitre.org/techniques/T1589/) Gather Victim Identity Information | 3 distinct `?author=N` / users-API requests / 10m |

### Web exploitation probes

| Rule | Severity | ATT&CK technique | Logic |
|---|---|---|---|
| `web-sqli-probe` | medium | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | SQL injection syntax in the decoded URI |
| `web-xss-probe` | medium | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | script injection in the decoded URI |
| `web-path-traversal` | medium | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | `../`, system files, PHP wrappers |
| `web-command-injection` | medium | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | shell separator followed by a command |
| `web-ssti-probe` | medium | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | template expressions such as `{{7*7}}` |
| `web-log4shell-probe` | high | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | `${jndi:` and obfuscations in URI, UA or Referer |
| `web-shellshock-probe` | high | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | `() { :; };` in UA, Referer or URI |
| `web-cloud-metadata-ssrf` | high | [T1552.005](https://attack.mitre.org/techniques/T1552/005/) Cloud Instance Metadata API | metadata address or API path in the request |

### Web shells, credentials and floods

| Rule | Severity | ATT&CK technique | Logic |
|---|---|---|---|
| `web-shell-known-name` | medium | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Web Shell | request for c99.php, wso.php, ... |
| `web-shell-upload-exec` | high | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Web Shell | script under an upload directory answered 200 |
| `web-login-brute-force` | medium | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | 15 failed logins / 5m per address |
| `web-credential-stuffing` | high | [T1110.004](https://attack.mitre.org/techniques/T1110/004/) Credential Stuffing | failed logins from 8 addresses sharing a User-Agent / 10m |
| `web-request-flood` | medium | [T1499.002](https://attack.mitre.org/techniques/T1499/002/) Service Exhaustion Flood | 300 requests / 1m per address |

## Known limitations

- Access logs do not contain request bodies or most headers, so POST payloads,
  cookies and Content-Type based attacks are invisible to these rules.
- `web-sensitive-file-exposed` cannot see the response body; a site that
  answers every path with its index page (single-page apps) can trigger it.
- Thresholds are per address. An attacker spreading a brute force over many
  addresses is only caught by `web-credential-stuffing` (shared User-Agent) or
  the anomaly model; low-and-slow attacks below the thresholds are missed. The
  [evaluation](EVALUATION.md) measures this on synthetic data.
