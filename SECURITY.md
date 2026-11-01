# Security Policy

Armada runs with root-equivalent privileges on every node (it runs its own container runtime), holds the
cluster CA, and stores application secrets. We take reports seriously.

## Reporting a vulnerability

Please **do not open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository.

Include the affected version (`armada version -o json`), a description of the impact, and
steps to reproduce. We aim to acknowledge reports within 3 business days and to agree on a
disclosure timeline with you.

## Supported versions

Armada is pre-1.0. Only the latest release receives security fixes.

## Scope

In scope: the `armada` binary (server, agent, CLI), the install script, release artifacts,
and the HAProxy configuration Armada generates. Known limitations are documented in
[docs/threat-model.md](docs/threat-model.md); reports that bypass them are still welcome.
