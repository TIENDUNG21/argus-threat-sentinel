# 4. Evaluate on seeded synthetic logs, and say so

Status: accepted

## Context

Detection quality has to be measured, and measuring needs ground truth: which
actors are attackers and which detection should catch each of them.

Public labelled datasets exist (CIC-IDS2017, UNSW-NB15 and similar), but they
are network flows or packet captures, not nginx and OpenSSH logs. Web server
log datasets are rarely labelled per request, often carry licences that forbid
redistribution of derived files, and contain real addresses. Real logs from a
server would be unlabelled and could not be published.

## Decision

Write a simulator (`argus.simulate`) that produces an nginx access log, an
OpenSSH auth log and `labels.json` from a seed, and evaluate on it:

- benign traffic includes the cases that trip naive rules (SQL-sounding
  searches, crawlers, an uptime monitor, an office NAT, admins who mistype,
  a travelling admin, sometimes an admin logging in as root);
- each attack scenario's label names the rules that should fire, including
  low-and-slow and evasive variants built to slip under thresholds, so misses
  are counted rather than designed away;
- thresholds were chosen on seeds 1-5; the published numbers use seeds
  100-109;
- `scripts/evaluate.py` writes `docs/EVALUATION.md` and CI regenerates it on
  Linux with `--check`, so a code change that moves any number must commit the
  new numbers.

## Consequences

- Every figure is reproducible from the repository, and the evaluation doubles
  as an end-to-end regression test.
- The numbers show that detectors behave as designed. They do not predict
  performance on a real network, where benign traffic has more variety than
  anything simulated. Precision near 100% is a property of the simulator as
  much as of the rules; the README and the evaluation say this next to the
  numbers.
- The most useful output is the table of misses by scenario, which shows the
  structural blind spots of per-address thresholds.
- Addresses come from 198.18.0.0/15 and 2001:db8::/32, so the published logs
  and the sample report name no real host.
