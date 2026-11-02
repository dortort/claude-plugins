# Releasing plugins

Each plugin has an independent version and release tag. The marketplace distributes
exact published versions of the plugins maintained here. The scheduler uses npm;
the callback variants use tagged Git subdirectories pinned to full commit SHAs, and
TaintGuard will too once its first release is promoted.
The separately maintained skills plugin keeps its own distribution policy.

## Artifact Callbacks

For the plugin being changed:

1. Bump `version` in its `.claude-plugin/plugin.json`, `package.json`, and both
   version fields in `package-lock.json`. Claude uses the plugin manifest's version
   to detect updates; changes under an unchanged version may not reach existing users.
2. Add `plugins/<plugin>/releases/<version>.md` describing the shipped changes,
   requirements, and how to update. Keep the channel's research-preview restrictions
   explicit. The channel MCP server reads its version from the plugin manifest.
3. Open a PR and let Artifact Callbacks CI pass before merging.
4. After merging, wait for the **Artifact Callbacks** workflow on `main` to pass.
   If the current commit did not trigger it, run that workflow manually on `main` first.
   Run **Release Artifact Callbacks and TaintGuard** in GitHub Actions and select the
   plugin, or use:

   ```bash
   gh workflow run artifact-release.yml --repo dortort/claude-plugins --ref main \
     -f plugin=artifact-callbacks
   gh workflow run artifact-release.yml --repo dortort/claude-plugins --ref main \
     -f plugin=artifact-callbacks-channel
   ```

Run only the command for each plugin whose version changed. The workflow refuses
non-`main` refs, checks the CI result and matching versions, and requires release
notes. It creates `<plugin>--v<version>` at the checked commit, for example
`artifact-callbacks--v0.1.1` and `artifact-callbacks-channel--v0.1.1`, with separate
GitHub release notes. Existing releases are not overwritten. These releases do not
replace the repository's latest scheduler release.

Publishing creates a release, but does not change the stable marketplace pin.
Follow **Promote a release to the marketplace** below to make the release available.
After promotion, users refresh and update with:

```bash
claude plugin marketplace update dortort
claude plugin update artifact-callbacks@dortort
# Or, for the channel alternative:
claude plugin update artifact-callbacks-channel@dortort
```

Reload plugins or restart Claude after updating. Enable only one variant per session.
Publishing a channel release does not add it to Anthropic's channel allowlist;
the documented development flag or an organization allowlist is still required.

## TaintGuard

TaintGuard (`plugins/taint-guard`) uses the same tag-and-GitHub-release flow as the
callback plugins, gated on its own **TaintGuard** workflow
(`.github/workflows/taint-guard.yml`):

1. Bump `version` in `plugins/taint-guard/.claude-plugin/plugin.json`, `package.json`,
   and both version fields in `package-lock.json`. The docs suite
   (`npm run test:unit`) fails when they disagree.
2. Add `plugins/taint-guard/releases/<version>.md` with what ships, the requirements
   (Claude Code 2.1.287+ in the terminal, 2.1.286+ in Desktop's Code tab), how to
   install or update, and the known limitations.
3. Open a PR and let TaintGuard CI pass before merging.
4. After merging, wait for the **TaintGuard** workflow on `main` to pass. If the current
   commit did not trigger it, run that workflow manually on `main` first. Then run
   **Release Artifact Callbacks and TaintGuard** and select `taint-guard`, or use:

   ```bash
   gh workflow run taint-guard.yml --repo dortort/claude-plugins --ref main
   gh workflow run artifact-release.yml --repo dortort/claude-plugins --ref main \
     -f plugin=taint-guard
   ```

The workflow checks that the **TaintGuard** run for that commit succeeded, that the
versions match and that release notes exist, then creates `taint-guard--v<version>`
(for example `taint-guard--v0.1.0`) at the checked commit with its own GitHub release.

The catalog has no `taint-guard` entry yet, and `scripts/marketplace.mjs` does not know
the plugin. The first promotion PR therefore adds the marketplace tooling support
before it pins the release: `taint-guard` in `managedPlugins` (a `git-subdir` source like
the callback plugins), a `taint-guard` entry in `.claude-plugin/marketplace.json`, the
plugin in `scripts/check-marketplace-install.mjs` and its tests, and then
`node scripts/marketplace.mjs promote taint-guard <version>`. Later releases are promoted
like any other plugin. After promotion, users install or update with:

```bash
claude plugin marketplace update dortort
claude plugin install taint-guard@dortort   # first time
claude plugin update taint-guard@dortort    # later releases
```

Organizations that run TaintGuard as a managed mod replace the plugin directory in
their administrator-only marketplace instead; see the
[deployment guide](plugins/taint-guard/docs/deployment.md#updating).

## Scheduler

The scheduler is published to npm from `plugins/scheduler`. Its `scheduler--v<version>`
GitHub release triggers the npm workflow. Follow the
[scheduler release instructions](plugins/scheduler/README.md#releasing).

## Promote a release to the marketplace

Source changes, publication, and marketplace promotion are separate steps. Keep the
catalog on the previous release while developing and testing a newer version.
After publishing and confirming that the release is downloadable, create a branch
from `main` and run the appropriate command from the repository root:

```bash
node scripts/marketplace.mjs promote scheduler 0.4.1
# Or promote one of the callback variants:
node scripts/marketplace.mjs promote artifact-callbacks 0.1.1
node scripts/marketplace.mjs promote artifact-callbacks-channel 0.1.1
```

Use the version just published; the examples show the initial pinned releases.
TaintGuard's first promotion needs the tooling support described under
[TaintGuard](#taintguard) first.
The command verifies a published, non-prerelease GitHub release and its manifest.
It also checks npm publication for the scheduler. It updates only that plugin's
catalog entry, leaving other releases in place. For a callback plugin it records
both the release tag and the exact commit, so moving the tag cannot silently change
installed code.

Before opening the promotion PR, run:

```bash
node scripts/marketplace.mjs check
node --test scripts/marketplace.test.mjs
node scripts/check-marketplace-install.mjs
```

These commands require Node.js 22.18+, npm, Claude Code, and an authenticated `gh` CLI.
The installation check uses a temporary Claude configuration and does not change your
installed plugins. It validates publication and tag/commit agreement, installs all
three pinned releases, validates their installed manifests, and runs the scheduler
CLI. Its local fixture contains fake newer builds to verify they cannot be selected.
CI runs the same checks on catalog changes and release tooling changes.

Commit the catalog update with a conventional message such as
`chore(marketplace): promote artifact-callbacks 0.1.2`, then open a PR. Merge it once
CI passes. Marketplace users receive the release when they refresh and update.
A rollback uses the same process with an older published version.

The release workflows print the promotion command in their job summaries. They do
not commit to `main`, create promotion PRs, or advance stable pins automatically.
