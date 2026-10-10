# ACF runtime overhead

ACF commit `7474137baa5c5099740ccc762e1b9fb9c276d794` (tracked changes: True), started 2026-09-13T21:30:55+00:00.

| Machine | Value |
|---|---|
| CPU | None |
| Cores / logical | None / 14 |
| RAM GB | None |
| OS | None |
| OS build | None |
| Power plan | Balanced |
| On AC power | None |
| Go | go version go1.26.3 windows/amd64 |
| Python | 3.14.5 |
| IPC | Windows named pipe |
| Clock | QueryPerformanceCounter (Go internal/clock, Python perf_counter_ns) |

**Quick run:** request counts cut tenfold. These numbers are not reportable.

Latencies are median across repetitions, with the [min–max] of the per-repetition value when there is more than one repetition.

## Python SDK: per hook call

Public hook method, end to end, in ms.

| Scanner | Hook | p50 | p95 | p99 |
|---|---|---:|---:|---:|
| off | on_prompt | 0.217 | 0.295 | 0.427 |
| off | on_context | 0.262 | 0.439 | 0.553 |
| off | on_tool_call | 0.249 | 0.385 | 0.436 |
| off | on_memory | 0.250 | 0.519 | 0.680 |
| tfidf | on_prompt | 0.678 | 1.123 | 1.446 |
| tfidf | on_context | 0.717 | 1.085 | 1.251 |
| tfidf | on_tool_call | 0.596 | 0.960 | 1.288 |
| tfidf | on_memory | 0.723 | 1.193 | 1.427 |

Where an SDK call's time goes: p50 per phase in µs, from the step-by-step loop.

| Scanner | Hook | Semantic scan | Serialise | Sign | IPC round trip | Decode | Total | Scanner init s |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| off | on_prompt | 0.3 | 9.2 | 10.8 | 188.2 | 4.9 | 214.7 | 0.00 |
| off | on_context | 0.3 | 9.7 | 11.2 | 231.4 | 5.2 | 259.4 | 0.00 |
| off | on_tool_call | 0.3 | 10.4 | 11.2 | 179.6 | 5.0 | 208.5 | 0.00 |
| off | on_memory | 0.3 | 10.3 | 11.5 | 198.4 | 5.4 | 226.8 | 0.00 |
| tfidf | on_prompt | 351.6 | 10.9 | 11.7 | 275.8 | 5.1 | 661.7 | 16.80 |
| tfidf | on_context | 351.1 | 12.2 | 11.2 | 326.6 | 5.1 | 719.9 | 16.80 |
| tfidf | on_tool_call | 355.6 | 10.0 | 12.3 | 279.3 | 6.8 | 648.9 | 16.80 |
| tfidf | on_memory | 346.1 | 11.7 | 11.8 | 282.9 | 5.9 | 643.5 | 16.80 |

## Sidecar: where a request's time goes

Real sidecar, one client, integration corpus, per-request timing log. µs.

| Step | p50 | p99 | mean | share of mean total |
|---|---:|---:|---:|---:|
| read | 5.1 | 35.0 | 7.8 | 5.4% |
| verify | 1.6 | 8.6 | 2.1 | 1.5% |
| nonce | 0.6 | 1.7 | 0.9 | 0.6% |
| unmarshal | 9.7 | 23.3 | 10.4 | 7.2% |
| validate | 0.3 | 0.6 | 0.3 | 0.2% |
| normalise | 5.2 | 18.8 | 6.1 | 4.2% |
| scan | 2.6 | 13.3 | 3.6 | 2.5% |
| aggregate | 0.4 | 0.8 | 0.4 | 0.3% |
| policy | 86.0 | 214.4 | 94.0 | 65.4% |
| sanitise | 1.2 | 3.7 | 1.3 |  |
| log | 10.3 | 32.3 | 11.2 | 7.8% |
| write | 5.5 | 10.0 | 5.5 | 3.8% |
| total | 130.8 | 354.9 | 143.7 |  |

`read` includes waiting for the client's bytes; `sanitise` is over the requests OPA sanitised only.

## Sidecar: client-observed latency

Go load generator, new connection per request, ms.

| Condition | Reps | p50 | p95 | p99 | Throughput req/s | Errors |
|---|---:|---:|---:|---:|---:|---:|
| c1/corpus | 1 | 0.176 | 0.279 | 0.495 | 5161 | 0 |
| c1/corpus/timing-log-off | 1 | 0.168 | 0.283 | 0.444 | 5391 | 0 |
| c1/corpus/stderr-discarded | 1 | 0.174 | 0.295 | 0.494 | 5183 | 0 |
| c1/context-256B | 1 | 0.185 | 0.257 | 0.405 | 5063 | 0 |
| c1/context-1024B | 1 | 0.253 | 0.381 | 0.756 | 3690 | 0 |
| c1/context-4096B | 1 | 0.453 | 0.713 | 1.184 | 2103 | 0 |
| c1/context-16384B | 1 | 1.599 | 2.525 | 3.980 | 577 | 0 |
| c1/context-65536B | 1 | 4.885 | 7.379 | 7.896 | 196 | 0 |
| closed/c2/corpus | 1 | 0.177 | 0.298 | 10.300 | 5393 | 0 |
| closed/c4/corpus | 1 | 0.183 | 0.419 | 10.565 | 5566 | 0 |
| closed/c8/corpus | 1 | 0.185 | 10.260 | 21.271 | 5584 | 0 |
| closed/c16/corpus | 1 | 0.193 | 10.688 | 51.390 | 5843 | 0 |
| closed/c32/corpus | 1 | 0.196 | 31.094 | 102.964 | 5645 | 0 |
| closed/c64/corpus | 1 | 0.204 | 71.800 | 188.735 | 4284 | 0 |

## Payload size

on_context chunk, one client. Client ms, sidecar steps µs (p50).

| Size | Client p50 | Client p99 | Unmarshal | Normalise | Scan | Policy | Sidecar total |
|---|---:|---:|---:|---:|---:|---:|---:|
| 256B | 0.185 | 0.405 | 10.8 | 19.4 | 3.2 | 77.8 | 137.9 |
| 1024B | 0.253 | 0.756 | 15.1 | 71.3 | 7.3 | 79.0 | 203.4 |
| 4096B | 0.453 | 1.184 | 27.1 | 165.8 | 16.6 | 72.8 | 345.1 |
| 16384B | 1.599 | 3.980 | 102.0 | 1103.0 | 59.7 | 101.2 | 1443.0 |
| 65536B | 4.885 | 7.896 | 273.9 | 3922.1 | 188.3 | 88.0 | 4746.2 |

## Open loop

Fixed arrival rate as a fraction of the peak closed-loop throughput (5843 req/s in repetition 1). Latency from each request's scheduled send time, ms.

| Load | Rate req/s | p50 | p99 | p99.9 | Send lag p99 | Errors |
|---|---:|---:|---:|---:|---:|---:|
| 25pct | 1461 | 0.220 | 0.657 | 10.313 | 0.027 | 0 |
| 50pct | 2922 | 0.210 | 1.182 | 20.506 | 0.018 | 0 |
| 75pct | 4383 | 0.212 | 9.985 | 31.294 | 0.013 | 0 |
| 90pct | 5259 | 0.218 | 20.519 | 71.964 | 0.019 | 0 |

## Go benchmarks

`go test -run ^$ -bench . -benchmem -count 1 -benchtime 100ms ./internal/pipeline ./internal/transport ./internal/crypto`. µs/op median [min–max] over runs.

| Benchmark | µs/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| pipeline/BenchmarkStage/validate/corpus | 0.06 | n/a | 128 | 1 |
| pipeline/BenchmarkStage/normalise/corpus | 2.26 | n/a | 401 | 7 |
| pipeline/BenchmarkStage/scan/corpus | 0.48 | n/a | 219 | 3 |
| pipeline/BenchmarkStage/aggregate/corpus | 0.07 | n/a | 128 | 1 |
| pipeline/BenchmarkPolicy/on_prompt | 29.90 | n/a | 21505 | 519 |
| pipeline/BenchmarkPolicy/on_context | 44.37 | n/a | 30110 | 743 |
| pipeline/BenchmarkPolicy/on_tool_call | 34.27 | n/a | 22809 | 532 |
| pipeline/BenchmarkPolicy/on_memory | 37.40 | n/a | 26053 | 590 |
| pipeline/BenchmarkPipeline/corpus | 43.63 | n/a | 25291 | 584 |
| pipeline/BenchmarkPipeline/on_prompt | 36.29 | n/a | 22348 | 529 |
| pipeline/BenchmarkPipeline/on_context | 52.54 | n/a | 31625 | 756 |
| pipeline/BenchmarkPipeline/on_tool_call | 36.77 | n/a | 23350 | 540 |
| pipeline/BenchmarkPipeline/on_memory | 44.48 | n/a | 27441 | 604 |
| pipeline/BenchmarkSize/normalise/benign/size=256 | 10.45 | 24.5 | 1235 | 7 |
| pipeline/BenchmarkSize/normalise/benign/size=1024 | 41.98 | 24.4 | 5664 | 8 |
| pipeline/BenchmarkSize/normalise/benign/size=4096 | 168.71 | 24.3 | 22470 | 8 |
| pipeline/BenchmarkSize/normalise/benign/size=16384 | 912.84 | 17.9 | 88274 | 8 |
| pipeline/BenchmarkSize/normalise/benign/size=65536 | 4195.01 | 15.6 | 352714 | 9 |
| pipeline/BenchmarkSize/normalise/injected/size=256 | 11.08 | 23.1 | 1235 | 7 |
| pipeline/BenchmarkSize/normalise/injected/size=1024 | 45.73 | 22.4 | 5661 | 8 |
| pipeline/BenchmarkSize/normalise/injected/size=4096 | 187.23 | 21.9 | 22571 | 8 |
| pipeline/BenchmarkSize/normalise/injected/size=16384 | 920.86 | 17.8 | 88276 | 8 |
| pipeline/BenchmarkSize/normalise/injected/size=65536 | 3983.86 | 16.4 | 352462 | 8 |
| pipeline/BenchmarkSize/scan/benign/size=256 | 0.84 | 304.1 | 387 | 2 |
| pipeline/BenchmarkSize/scan/benign/size=1024 | 3.33 | 307.7 | 1157 | 2 |
| pipeline/BenchmarkSize/scan/benign/size=4096 | 12.91 | 317.2 | 4255 | 2 |
| pipeline/BenchmarkSize/scan/benign/size=16384 | 51.12 | 320.5 | 16571 | 2 |
| pipeline/BenchmarkSize/scan/benign/size=65536 | 197.90 | 331.2 | 65901 | 2 |
| pipeline/BenchmarkSize/scan/injected/size=256 | 1.08 | 236.6 | 565 | 6 |
| pipeline/BenchmarkSize/scan/injected/size=1024 | 3.83 | 267.5 | 1341 | 6 |
| pipeline/BenchmarkSize/scan/injected/size=4096 | 13.31 | 307.8 | 4432 | 6 |
| pipeline/BenchmarkSize/scan/injected/size=16384 | 50.75 | 322.8 | 16749 | 6 |
| pipeline/BenchmarkSize/scan/injected/size=65536 | 193.46 | 338.8 | 66179 | 6 |
| pipeline/BenchmarkSize/pipeline/benign/size=256 | 49.19 | 5.2 | 25222 | 538 |
| pipeline/BenchmarkSize/pipeline/benign/size=1024 | 91.19 | 11.2 | 30430 | 539 |
| pipeline/BenchmarkSize/pipeline/benign/size=4096 | 225.63 | 18.1 | 50239 | 539 |
| pipeline/BenchmarkSize/pipeline/benign/size=16384 | 1061.70 | 15.4 | 129361 | 540 |
| pipeline/BenchmarkSize/pipeline/benign/size=65536 | 4201.50 | 15.6 | 444462 | 541 |
| pipeline/BenchmarkSize/pipeline/injected/size=256 | 70.93 | 3.6 | 35894 | 861 |
| pipeline/BenchmarkSize/pipeline/injected/size=1024 | 105.89 | 9.7 | 41238 | 860 |
| pipeline/BenchmarkSize/pipeline/injected/size=4096 | 249.83 | 16.4 | 61456 | 860 |
| pipeline/BenchmarkSize/pipeline/injected/size=16384 | 1107.89 | 14.8 | 139404 | 861 |
| pipeline/BenchmarkSize/pipeline/injected/size=65536 | 4184.77 | 15.7 | 455000 | 862 |
| pipeline/BenchmarkNormaliseAdversarial/benign/size=4096 | 193.77 | 21.1 | 22488 | 8 |
| pipeline/BenchmarkNormaliseAdversarial/benign/size=65536 | 3997.06 | 16.4 | 353306 | 12 |
| pipeline/BenchmarkNormaliseAdversarial/base64-tokens/size=4096 | 185.37 | 22.1 | 49690 | 276 |
| pipeline/BenchmarkNormaliseAdversarial/base64-tokens/size=65536 | 6718.49 | 9.8 | 850827 | 4131 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=1/size=4096 | 120.86 | 33.9 | 19357 | 9 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=1/size=65536 | 2877.29 | 22.8 | 320217 | 10 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=3/size=4096 | 88.42 | 46.3 | 22478 | 13 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=3/size=65536 | 1682.29 | 39.0 | 361066 | 15 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=6/size=4096 | 74.07 | 55.3 | 24412 | 19 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=6/size=65536 | 1339.92 | 48.9 | 392630 | 22 |
| pipeline/BenchmarkNormaliseAdversarial/url-depth=4/size=4096 | 195.39 | 21.0 | 26913 | 11 |
| pipeline/BenchmarkNormaliseAdversarial/url-depth=4/size=65536 | 4093.31 | 16.0 | 443798 | 16 |
| pipeline/BenchmarkNormaliseAdversarial/url-depth=12/size=4096 | 207.50 | 19.7 | 41820 | 19 |
| pipeline/BenchmarkNormaliseAdversarial/url-depth=12/size=65536 | 3324.13 | 19.7 | 672313 | 27 |
| pipeline/BenchmarkNormaliseAdversarial/zerowidth/size=4096 | 81.22 | 50.4 | 23747 | 9 |
| pipeline/BenchmarkNormaliseAdversarial/zerowidth/size=65536 | 1475.44 | 44.4 | 371673 | 10 |
| pipeline/BenchmarkScanPatterns/patterns=79/size=4096 | 15.61 | 262.4 | 4311 | 6 |
| pipeline/BenchmarkScanPatterns/patterns=1000/size=4096 | 13.01 | 314.8 | 4172 | 2 |
| pipeline/BenchmarkScanPatterns/patterns=10000/size=4096 | 13.63 | 300.6 | 4717 | 2 |
| pipeline/BenchmarkScanPatterns/patterns=100000/size=4096 | 18.92 | 216.4 | 15345 | 3 |
| pipeline/BenchmarkSanitise/size=1024 | 0.10 | 9775.5 | 32 | 2 |
| pipeline/BenchmarkSanitise/size=16384 | 0.10 | 161455.2 | 32 | 2 |
| transport/BenchmarkDecodeRequest/size=256 | 0.17 | 2454.9 | 528 | 3 |
| transport/BenchmarkDecodeRequest/size=1024 | 0.37 | 3199.6 | 1296 | 3 |
| transport/BenchmarkDecodeRequest/size=4096 | 0.87 | 4913.5 | 5008 | 3 |
| transport/BenchmarkDecodeRequest/size=16384 | 2.74 | 6039.0 | 18576 | 3 |
| transport/BenchmarkDecodeRequest/size=65536 | 12.17 | 5399.3 | 73872 | 3 |
| transport/BenchmarkVerify/size=256 | 0.67 | 544.6 | 928 | 7 |
| transport/BenchmarkVerify/size=1024 | 1.12 | 1012.2 | 1792 | 7 |
| transport/BenchmarkVerify/size=4096 | 2.90 | 1449.5 | 5376 | 7 |
| transport/BenchmarkVerify/size=16384 | 10.10 | 1633.0 | 18944 | 7 |
| transport/BenchmarkVerify/size=65536 | 36.66 | 1790.9 | 74240 | 7 |
| transport/BenchmarkUnmarshal/corpus | 1.84 | n/a | 876 | 17 |
| transport/BenchmarkUnmarshal/size=256 | 2.27 | 161.0 | 679 | 11 |
| transport/BenchmarkUnmarshal/size=1024 | 4.97 | 228.1 | 1448 | 11 |
| transport/BenchmarkUnmarshal/size=4096 | 15.96 | 263.5 | 4520 | 11 |
| transport/BenchmarkUnmarshal/size=16384 | 61.34 | 268.9 | 16808 | 11 |
| transport/BenchmarkUnmarshal/size=65536 | 223.27 | 294.0 | 65960 | 11 |
| transport/BenchmarkHandleConn/corpus/log=discard | 64.81 | n/a | 29257 | 630 |
| transport/BenchmarkHandleConn/corpus/log=file | 72.21 | n/a | 28931 | 634 |
| transport/BenchmarkHandleConn/corpus/log=discard/timing=on | 67.76 | n/a | 29827 | 672 |
| transport/BenchmarkHandleConn/size=256/log=discard | 77.58 | n/a | 29162 | 577 |
| transport/BenchmarkHandleConn/size=1024/log=discard | 122.17 | n/a | 36697 | 578 |
| transport/BenchmarkHandleConn/size=4096/log=discard | 372.27 | n/a | 67777 | 578 |
| transport/BenchmarkHandleConn/size=16384/log=discard | 1768.49 | n/a | 187260 | 581 |
| transport/BenchmarkHandleConn/size=65536/log=discard | 5655.10 | n/a | 666930 | 587 |
| transport/BenchmarkIPCRoundTrip/auth-only/corpus | 69.90 | n/a | 4003 | 48 |
| transport/BenchmarkIPCRoundTrip/full/corpus | 179.51 | n/a | 31126 | 652 |
| crypto/BenchmarkNonceStoreSeen/stored=0 | 0.33 | n/a | 216 | 1 |
| crypto/BenchmarkNonceStoreSeen/stored=100000 | 0.32 | n/a | 204 | 1 |
