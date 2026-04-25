# Security Policy

## Supported Versions

Only the latest release is supported with security fixes. Pin to a specific release and watch the
repository for advisories.

## Reporting a Vulnerability

Use the **Security** tab > **Report a vulnerability** to file a private advisory. Include reproduction
steps and the output of `kyrisd --version`.

We aim to acknowledge reports within 48 hours and provide a fix or mitigation within 14 days.

## Scope

Kyris is a local routing proxy and governance layer for AI agent LLM traffic. Security concerns include:

- Provider credential exposure
- Policy bypass
- LLM request interception or tampering
- Event log tampering
- Privilege escalation
- Attribution spoofing
- Shell hook bypass
- MCP wrapper bypass
