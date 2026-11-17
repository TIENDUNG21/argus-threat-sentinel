# Security policy

## Supported versions

Fixes go into the latest release. At the moment that is 1.0.x.

## Reporting a problem

Please do not put exploit details in a public issue. Open an issue titled
"Security contact" with no details, and a private channel will be arranged.

Useful reports include the Argus version, the command line, and a minimal log
line or rule file that reproduces the problem.

## Threat model

Argus reads logs, and every byte of a log line can be chosen by an attacker:
the request path, the query, the User-Agent, the Referer and the SSH user name
all come from the client. The design assumes that input is hostile.

In scope:

- **Parsing.** A line must never crash a scan or stop it early. Undecodable
  bytes are replaced, NUL bytes and CRLF endings are tolerated, lines over
  64 KiB are cut and counted, and every parser failure is counted as malformed
  with a reason. Property tests feed arbitrary text to each parser.
- **Reports.** The HTML report escapes every value taken from a log and carries
  a `Content-Security-Policy` that allows no scripts, no remote resources, no
  forms and no base URL changes. It contains no JavaScript of its own. Links
  point only to attack.mitre.org technique pages and are not followed unless
  clicked.
- **Rule files.** A rule file is data: conditions are compiled from a small
  expression language, never evaluated as Python. Invalid files are rejected
  before any log is read.

Out of scope, or known limits:

- **Regular expressions in custom rules** run on Python's backtracking `re`
  engine. A badly written pattern such as `(a+)+$` can take exponential time on
  a crafted line. The 64 KiB line cap bounds the input, not the run time. Treat
  rule files from others as you would treat code review: read them before use.
- **The JSON report** contains log content verbatim (JSON-escaped). Tools that
  render it into HTML must escape it themselves.
- **Evasion.** An attacker who knows the thresholds can stay under them, and
  access logs do not record request bodies. Argus is a detection aid, not a
  guarantee; [docs/EVALUATION.md](docs/EVALUATION.md) lists what the built-in
  rules miss on synthetic data.
- **Log integrity.** Argus trusts that the file it reads is the file the server
  wrote. An attacker with write access to the logs can remove their own lines.
- **Simulator.** `argus simulate` writes the probe strings that scanners send
  (for example `' OR '1'='1` or `${jndi:ldap://...}` pointing at RFC 5737
  documentation addresses) so the detectors have something to find. It does not
  send traffic anywhere and contains no working exploit chains.
