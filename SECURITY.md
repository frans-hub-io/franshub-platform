# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub private vulnerability reporting
(Security tab, "Report a vulnerability"), not in public issues or pull requests. Include the
affected version, a description, and steps to reproduce. You will get an answer within five
working days.

## Principles

- Every API call is authenticated; failures to authenticate look the same whatever the reason.
- Defaults are restrictive; anything that widens access is an explicit setting.
- A caller can never grant more than it holds.
- Secrets are stored as hashes where possible and never appear in logs, errors or debug output.
- Caches and rate limits are bounded, so unauthenticated input cannot grow them without limit.
- Changes to access are audited.
- Dependencies are kept current and checked against published advisories.
