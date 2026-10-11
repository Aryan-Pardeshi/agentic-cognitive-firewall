# Content scanners on AgentDojo's attack wordings

agentdojo `0.1.35` (suites v1.2.2), every 1 replayable case(s), threshold 0.5, device `cuda`. ACF commit `0e2dd0237b0fca57c9db8fc5a63cc457adabfb81`.

Scanners in isolation: no agent model, no policy. A flag is a scanner's signal, not ACF's final decision. `window` scores overlapping 48-word windows and takes the maximum; it is an experiment, not SDK behaviour.

## Injected tool results flagged

| Scanner | Mode | direct | system_message | ignore_previous | injecagent | important_instructions | tool_knowledge |
|---|---|---:|---:|---:|---:|---:|---:|
| lexical | whole | 0/609 (0.0%) | 0/609 (0.0%) | 0/609 (0.0%) | 609/609 (100.0%) | 0/609 (0.0%) | 0/609 (0.0%) |
| tfidf | whole | 119/609 (19.5%) | 119/609 (19.5%) | 380/609 (62.4%) | 609/609 (100.0%) | 83/609 (13.6%) | 84/609 (13.8%) |
| tfidf | window | 173/609 (28.4%) | 173/609 (28.4%) | 519/609 (85.2%) | 609/609 (100.0%) | 119/609 (19.5%) | 133/609 (21.8%) |
| gemma | whole | 12/609 (2.0%) | 13/609 (2.1%) | 30/609 (4.9%) | 75/609 (12.3%) | 0/609 (0.0%) | 9/609 (1.5%) |
| gemma | window | 96/609 (15.8%) | 92/609 (15.1%) | 195/609 (32.0%) | 486/609 (79.8%) | 255/609 (41.9%) | 517/609 (84.9%) |

## Benign text flagged, and cost

| Scanner | Mode | User requests | Tool results | Highest benign score | Scoring time s |
|---|---|---:|---:|---:|---:|
| lexical | whole | 0/97 | 0/149 | 0.0 | 1.2 |
| tfidf | whole | 7/97 | 3/149 | 1.0 | 1.2 |
| tfidf | window | 8/97 | 7/149 | 1.0 | 5.2 |
| gemma | whole | 8/97 | 0/149 | 0.7128 | 83.2 |
| gemma | window | 10/97 | 0/149 | 0.7128 | 180.8 |

## Time for one text

Median of repeated single calls, whole text, on the device above.

| Scanner | Short | Median | Long | Load s |
|---|---:|---:|---:|---:|
| lexical | 0.2 ms (32 words) | 0.28 ms (121 words) | 0.2 ms (338 words) | 0.9 |
| tfidf | 0.13 ms (32 words) | 0.16 ms (121 words) | 0.3 ms (338 words) | 0.3 |
| gemma | 14.31 ms (32 words) | 17.8 ms (121 words) | 21.07 ms (338 words) | 74.9 |
