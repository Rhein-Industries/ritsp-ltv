# Contributing to ritsp-ltv

ritsp-ltv is Rhein Industries' maintained fork of
[tsp-ltv](https://github.com/kushaldas/tsp-ltv). Issues and pull requests are
welcome at <https://github.com/Rhein-Industries/ritsp-ltv>. Report security
problems privately as described in [SECURITY.md](SECURITY.md).

## License of contributions

ritsp-ltv is licensed under BSD-2-Clause (see [LICENSE](LICENSE)). By
submitting a contribution you agree that it is licensed under the same terms.
No contributor license agreement and no DCO sign-off are required.

## Checks

CI (`.github/workflows/ci.yml`) builds, lints and tests every provider
combination, the MSRV and the FIPS build on GitHub-hosted runners. Pull
requests must pass it; `--all-features` is intentionally invalid because the
document providers are mutually exclusive.

## Releases

Publishing to crates.io is manual for now and done by the maintainers in the
`crates-maintainers` team.
