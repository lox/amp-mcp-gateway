# Security policy

Amp MCP Gateway supports isolated owner accounts, but remains a prototype, not a
production security product. Accounts share a trusted process, host and operator;
they are not sandboxes against compromise of that process or host.
Only the latest commit on `main` receives security fixes.

## Reporting a vulnerability

Please do not open a public issue with vulnerability details. Use GitHub's private
vulnerability reporting at
<https://github.com/lox/amp-mcp-gateway/security/advisories/new>. If that form is
unavailable, contact the maintainer privately through the contact method on the
[`@lox`](https://github.com/lox) profile before sharing details.

Include the affected revision, impact, reproduction steps and any suggested
mitigation. Do not include real credentials, tokens or private user data.

The maintainer will acknowledge reports on a best-effort basis. There is no
guaranteed response or disclosure timeline while the project remains a prototype.
