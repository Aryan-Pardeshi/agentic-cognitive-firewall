# InjecAgent live-agent evaluation

Agent model `gemma4` (served as gemma4), step-2 simulator `gemma4`, temperature 0, InjecAgent prompt, semantic scanner `off`.
ACF commit `c214e80e25f9ff57343b2c53688ff00075db910f`, InjecAgent commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`.

**Pilot run:** 2 cases per split and setting. These numbers are not reportable.

Rates are post-enforcement: an attacker tool call that ACF blocks counts as an unsuccessful attack. `Attempts` counts turns where the model chose the attacker tool before enforcement, so `Attempts` minus blocked calls is what got through.

## base

| Arm | Cases | Valid | ASR-valid | ASR-all | ASR-all DH | ASR-all DS | Attempts | Blocked calls | Altered observations | Uncached calls |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 4 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 | 4 |
| full-task | 4 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 | 0 |

### base, cases with an exact lexical-pattern overlap excluded

No case contains an exact match for an ACF lexical pattern, so the scores above already exclude overlap.
