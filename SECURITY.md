# Security Policy

## This library has not had an independent security audit

sorocharge-core signs and verifies payment authorization entries. It is
covered by unit tests, golden-vector diffs against the reference
`@stellar/stellar-sdk`, and CI — but **no independent third party has
audited this code**. Treat it accordingly: do not deploy it as the sole
guardian of material funds without your own review, and assume bugs in
signature construction or verification logic are possible.

## Reporting a vulnerability

Report suspected vulnerabilities **privately**. Do not open a public issue
for anything that could be exploited — including:

- signature malleability or verification bypass (accepting an entry that
  should be rejected),
- byte-level divergence from the reference SDK that would make our
  signatures or XDR non-interchangeable with Stellar's,
- use of predictable, biased, or misused randomness in signing,
- anything that could leak private keys or seed material through logging,
  fixtures, or error messages.

**Preferred channel:** GitHub → the repository's **Security** tab →
**Report a vulnerability**, which opens a private advisory visible only to
the maintainers.

**If that is unavailable**, contact the maintainer directly on GitHub
([@ciscokwiz](https://github.com/ciscokwiz)) and ask for a private channel
before sharing details.

Include: affected crate and version, a minimal reproduction or the exact
inputs that trigger the behavior, impact (what an attacker gains), and any
fix you've already validated.

## Supported versions

Pre-1.0, the `main` branch is the only line that receives fixes. Released
versions are tagged from `main`; if you are on an older tag, update first
and re-check before reporting.
