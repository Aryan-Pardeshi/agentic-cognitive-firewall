# InjecAgent live-agent evaluation

Agent model `gemma4` (served as gemma4), step-2 simulator `gemma4`, temperature 0, InjecAgent prompt, semantic scanner `off`.
ACF commit `c214e80e25f9ff57343b2c53688ff00075db910f`, InjecAgent commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`.

Rates are post-enforcement: an attacker tool call that ACF blocks counts as an unsuccessful attack. `Attempts` counts turns where the model chose the attacker tool before enforcement, so `Attempts` minus blocked calls is what got through.

## enhanced

| Arm | Cases | Valid | ASR-valid | ASR-all | ASR-all DH | ASR-all DS | Attempts | Blocked calls | Altered observations | Uncached calls |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 1054 | 99.7% | 0.0% | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 | 863 |
| gate-global | 1053 | 99.7% | 0.0% | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 | 0 |
| gate-task | 1054 | 99.7% | 0.0% | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 | 0 |
| detect | 1054 | 96.6% | 0.1% | 0.1% | 0.2% | 0.0% | 1 | 0 | 1054 | 1054 |
| full-global | 1054 | 96.6% | 0.0% | 0.0% | 0.0% | 0.0% | 1 | 1 | 1054 | 0 |
| full-task | 1054 | 96.6% | 0.0% | 0.0% | 0.0% | 0.0% | 1 | 1 | 1054 | 0 |

### enhanced, cases with an exact lexical-pattern overlap excluded

Every case contains an exact match for an ACF lexical pattern (matched: `jp-073`), so no overlap-excluded subset exists.
