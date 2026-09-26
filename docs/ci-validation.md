# Release validation

CI builds the published crates.io dependency graph from `Cargo.toml` and the
committed registry `Cargo.lock`, with `--locked` on build and test commands.
There are no sibling checkouts, path overrides or temporary source pins. The
manifest requires riptering 0.7.0 or a compatible patch release.

Native Linux, Windows and macOS run complete supported RustCrypto profiles.
Linux also tests the document/TLS combinations and explicit FIPS initialization
and attestation on x86_64 and ARM. Those FIPS fixtures are the supported gate;
an unrestricted fixture suite is not a FIPS conformance claim. Physical HSM
validation remains deployment work.

Publish riptering before refreshing the ritsp-ltv registry lockfile. The release
commit must pass native CI against that graph before merging and publishing
ritsp-ltv. Validate the package with `cargo publish --locked --dry-run` from a
clean checkout and Cargo configuration without local patches, and review
`cargo package --list --locked` for license, documentation and fixture coverage.
Do not use `--allow-dirty` for release validation. Publish downstream XML crates
and risaml afterward in dependency order. These workflows do not publish crates
or merge PRs; successful CI does not establish that deployed consumers upgraded.
