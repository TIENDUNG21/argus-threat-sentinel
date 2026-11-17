# 1. A small typed condition language in TOML, not Python or Sigma

Status: accepted

## Context

Detections need to be readable by someone who did not write them, reviewable
in a diff, and safe to load from a file someone else wrote. They also need to
fail loudly: a detection rule with a misspelt field does not crash anything, it
silently never matches, and a quiet detector looks exactly like a quiet network.

Options considered:

- **Python functions.** Most expressive, no parser to write. But a rule file
  becomes code execution, rules cannot be checked without running them, and
  reviewers have to read arbitrary code.
- **Sigma.** The common exchange format for SIEM rules. Its field mapping is
  per backend, its aggregation syntax was deprecated in favour of correlation
  rules that most tools implement partially, and its value is in converting to
  other engines. Argus has two fixed log schemas and needs sliding windows,
  sequences and new-value detection with well-defined semantics.
- **JSON/YAML trees of operators.** Easy to parse, unpleasant to write
  (`{"and": [{"gte": ["status", 400]}, ...]}`) and still needs type checking.

## Decision

Rules are TOML tables. The condition is a string in a small expression language
(`status >= 400 and path ~ "\.php$"`), compiled by a hand-written lexer,
recursive-descent parser and type-checking compiler into a Python closure. The
kind of rule (threshold, sequence, new value) is structured TOML, not part of
the expression.

The compiler knows the type of every field. Unknown fields, ordering operators
on text, regular expressions on numbers, invalid patterns, literals of the
wrong type and duplicate ids are errors at load time, reported with file, rule
id and column, plus a "did you mean" suggestion for misspelt fields.

String literals are raw (a backslash only escapes the quote), so regular
expressions read the same in the rule as in any regex reference.

## Consequences

- `argus rules check` validates a file without any log input, which is what a
  CI job for a rule repository needs.
- The language has no functions, arithmetic or cross-event references. Anything
  that needs state belongs to a rule kind, which keeps the state machines in
  one tested place (`rules/detectors.py`).
- Importing Sigma rules would need a converter for the subset that maps onto
  these two schemas. It is on the roadmap, not in 1.0.
