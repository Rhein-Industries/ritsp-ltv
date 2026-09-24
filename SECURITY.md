# Security policy

ritsp-ltv is Rhein Industries' maintained fork of
[tsp-ltv](https://github.com/kushaldas/tsp-ltv). Security problems in
ritsp-ltv are handled by Rhein Industries. Please do not send ritsp-ltv
reports to the tsp-ltv author.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting:

<https://github.com/Rhein-Industries/ritsp-ltv/security/advisories/new>

Do not open a public issue, pull request or discussion for a suspected
vulnerability. Please include the affected version or commit, the enabled
features (document provider, TLS provider, `fips`, `legacy-algorithms`), and
a description of the impact with, if possible, a minimal reproduction.

We acknowledge reports as soon as we can and agree on a disclosure timeline
with the reporter. Fixes are released as a patch release and announced
through a GitHub security advisory. If the problem also affects upstream
tsp-ltv, we notify its author privately before any public disclosure.

## Supported versions

| Version | Supported |
|---|---|
| 0.5.x (latest) | Yes |
| < 0.5 | No (tsp-ltv releases; see upstream) |

Cryptographic operations are provided by
[riptering](https://github.com/Rhein-Industries/riptering); see its security
policy for provider-level issues.
