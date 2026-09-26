# Local validation measurements

The opt-in measurements use only the repository's synthetic certificate/key
fixtures and an in-memory CRL cache. They perform no HTTP requests. The chain
pool contains 128 unrelated certificates followed by the actual intermediate;
the trust store contains 128 unrelated anchors followed by the root. Every
chain build still verifies its issuer signature. Repeated validation verifies
both links. The cache fixture is a signed, 21,263-byte CRL with 1,000 entries.

On Apple silicon macOS with Rust 1.90, default RustCrypto/ring features, the
following seven-sample medians were recorded before and after the changes:

| Workload | Before | After |
|---|---:|---:|
| Certificate parsing | 31.12 µs | 29.41 µs |
| Issuer lookup, 129 anchors | 1.39 µs | 1.29 µs |
| Chain construction, 129 pool certificates | 5.14 ms | 2.24 ms |
| Repeated two-link chain validation | 4.43 ms | 4.40 ms |
| HTTP client construction | 7.80 µs | 5.89 µs |
| HTTP client clone | 22 ns | 22 ns |
| CRL cache hit, 1,000 entries | 436.80 µs | 0.79 µs |

The implemented performance changes compare issuer names before DER-encoding
pool candidates and retain fully parsed CRL freshness dates in the cache. A
cache hit still checks the current caller's freshness/grace/body policy; full
signature, issuer, and historical freshness validation runs on every
authoritative revocation check. Signature verification and constant-time
comparisons are unchanged. No parsing, issuer-index, HTTP-construction, or
signature-caching optimization is claimed from the other timing differences.

These are unoptimized test-profile timings with debug information and
incremental compilation disabled to fit limited disk space. They identify
repeated work, not production throughput. Samples include scheduling and
allocator noise, use a fixed certificate order, and do not measure network
latency, TLS sessions, allocation counts, concurrency contention, or FIPS/HSM
performance. A typical small certificate pool will benefit less. Returned CRL
bytes are still copied and authoritative CRL validation remains linear in list
size. HTTP cloning already shares reqwest's pool; callers should reuse clients.

Run the same local workloads:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo test --locked --test local_performance -- \
  --ignored --nocapture --test-threads=1
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo test --locked --lib local_crl_cache_performance -- \
  --ignored --nocapture --test-threads=1
```

Each reports the median and min/max range of seven samples. Raw session logs
are in `target/review/`; they are disposable build artifacts. Crypto providers
are mutually exclusive: use explicit supported feature combinations for
additional measurements, never `--all-features`.
