# 2. Isolation Forest written with NumPy, web actors only by default

Status: accepted

## Context

Rules catch what someone anticipated. An unsupervised model can rank actors
whose behaviour differs from the rest of the same log, with no labelled
training data, which is the situation of anyone running Argus on their own
server.

Isolation Forest (Liu, Ting and Zhou, 2008) fits this well: it needs no
distance metric, works on a few thousand rows in milliseconds, has two
parameters with published defaults (256-row subsamples, 100+ trees), and is
unaffected by linear rescaling of a feature, so the features need no
standardisation (heavy-tailed counts still go through `log1p`).

scikit-learn ships an implementation. Using it would add SciPy, joblib and
threadpoolctl to a tool whose other runtime dependency is NumPy, and it does
not expose what Argus needs most: why a given actor was isolated.

## Decision

Implement the forest in `ml/iforest.py` (about 180 lines). Trees are flat
arrays (feature, threshold, left, right, node size), so scoring moves every
actor one level down a tree per vectorised step.

Explain each score by crediting every split on an actor's path with
`log2(parent_size / child_size)` bits to the split's feature, summed over the
forest and normalised. Node sizes are already stored for the path-length
correction, so the explanation costs one extra pass.

Model web actors only unless `--ml-sources` says otherwise.

## Consequences

- Tests pin the definition of `c(n)`, check that injected outliers get shorter
  paths and higher scores, that scores stay in the unit interval on
  arbitrary input (Hypothesis), and that a seed reproduces the forest exactly.
- The SSH model is off by default because it measurably does the wrong thing:
  on an exposed SSH port most addresses are attackers, so the few legitimate
  administrators are the outliers. On the synthetic evaluation the SSH model's
  ROC-AUC is 0.083, well below chance. The rules cover SSH instead.
- The model is batch only. It needs the whole population of actors, so
  `argus tail` runs rules alone.
- Anomaly-only incidents are capped at medium severity: an outlier with no
  matching rule is a lead for an analyst, and the evaluation shows the model
  also flags unusual benign actors such as monitors and crawlers.
