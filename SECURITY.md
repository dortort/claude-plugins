# Security policy

## Supported versions

Each plugin in this marketplace is supported at the release pinned in
[`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json). Fixes ship as a new
release of the affected plugin, followed by a promotion of that pin. Older releases do not
receive fixes.

| Plugin | Supported |
| --- | --- |
| `scheduler` | release pinned in the marketplace |
| `artifact-callbacks` | release pinned in the marketplace |
| `artifact-callbacks-channel` | release pinned in the marketplace |
| `taint-guard` | release pinned in the marketplace |

The `dortort` entry points to [dortort/skills](https://github.com/dortort/skills), which
has its own policy.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub:
[open a private security advisory](https://github.com/dortort/claude-plugins/security/advisories/new).
Do not open a public issue, discussion or pull request for a suspected vulnerability.

Include the affected plugin and version, the steps to reproduce, and the impact you
observed. You will get an acknowledgement within 7 days and a status update at least
every 14 days until the report is resolved.
