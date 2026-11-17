# 3. Alerts are episodes, not threshold crossings

Status: accepted

## Context

A threshold rule such as "10 failed passwords in 5 minutes from one address"
can be read two ways once an attacker sends 5,000 attempts:

1. fire every time the window holds 10 events, which gives thousands of alerts
   for one attack;
2. fire once per non-overlapping window, which gives hundreds and makes the
   count depend on where the windows happen to start;
3. fire once, then keep extending that alert while the activity continues.

Analysts triage attacks, not windows. The third reading is also the only one
where the alert's count, first and last timestamps and distinct users describe
the attack itself.

## Decision

Every rule kind produces episodes. When a rule fires for a group (by default a
client address), the alert stays open; further matching events from that group
add to its count, timestamps, distinct actors and, up to ten, its evidence
lines. The episode closes when the group has been quiet for longer than the
rule's window; activity after that opens a new alert.

The engine sweeps per-group state every 10,000 events and drops groups that can
no longer contribute to an alert, so memory follows the number of active
groups, not the length of the log.

## Consequences

- A brute force of 5,000 attempts is one alert with `count = 5000`; the report
  shows "first 10 of 5,000 lines" of evidence.
- An attacker who pauses for longer than the window gets a second alert. The
  incident layer merges both, because they share an actor and fall within the
  two-hour gap.
- Alert counts are comparable across rules and runs, which the evaluation
  relies on: it scores actors, and an actor has at most a few episodes per rule.
- Streaming mode (`argus tail`) prints an alert when it opens, not when it
  closes, so the count printed live is the count at the moment of firing.
