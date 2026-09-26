# Coordinated review validation

The security review spans riptering, ritsp-ltv, ribergshamra and risaml. Draft
PR CI tests immutable sibling commits from `.github/coordinated-stack.json`.
The setup script fetches and verifies those SHAs, applies Cargo path overrides
only on the ephemeral runner, explicitly selects the pinned package versions,
and rejects unrelated dependency version changes. Subsequent commands use
`--locked`. Production manifests and the committed registry lockfile remain
unchanged by the setup script.

Native Linux, Windows and macOS run complete supported RustCrypto profiles.
Linux also tests the document/TLS combinations and explicit FIPS initialization
and attestation on x86_64 and ARM. Those FIPS fixtures are the supported gate;
an unrestricted fixture suite is not a FIPS conformance claim. Physical HSM
validation remains deployment work.

Merge and release from the dependency layer upward: riptering, ritsp-ltv, the
ribergshamra workspace in crate dependency order, then risaml. Downstream PRs
must update published minimum dependency versions and registry lockfiles and
remove the temporary CI pins before their final merge. Passing coordinated
source CI does not establish that published or deployed consumers have the
fixes. These workflows do not publish crates or merge PRs.
