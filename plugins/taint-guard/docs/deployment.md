# Deploying TaintGuard in an organization

This guide is for the administrator who deploys Claude Code's managed settings. It installs
TaintGuard as the **organization's mod**, runs it ahead of every mod a user installs, pins
its security-relevant options, and adds a managed policy layer that users and repositories
cannot weaken.

Read the [README](../README.md) first for what TaintGuard does, its presets and its policy
file format.

## Why managed

Hooks on one event form a middleware chain: the first mod sees the event first and decides
whether later mods run ([the order mods run in](https://code.claude.com/docs/en/plugins/mods/events#the-order-mods-run-in)).
Managed `PreToolUse` hooks run before every mod; settings `PreToolUse` hooks and permission
rules run after the last mod calls `next`. Installed as an ordinary user mod, TaintGuard's
guarantee holds only against mods that run after it: a mod earlier in the chain can answer
or rewrite a tool call before TaintGuard sees it.

Deployed as described here, TaintGuard:

- **runs first.** Listed in managed `prependPlugins`, it sees every tool call before any
  user-installed mod.
- **runs all of its hooks.** Where Claude Code's built-in guard (`sec-default@builtin`)
  loads, it passes over a user mod's hooks on `classic.*` events and `session.compact`.
  As the organization's mod, TaintGuard keeps them, so it rebuilds taint after `/resume`
  and `/branch`, resets on `/clear`, writes the compaction taint record and notes
  background tasks.
- **cannot be switched off or weakened by users.** The managed `enabled` lock, the preset
  floor and the managed policy path are read from managed settings alone, and with either
  the lock or a preset in place, a user policy can no longer lower `mode`,
  `userDeclassify` or `onUnknownHistory`.

## Requirements

- Claude Code with mods: 2.1.287 or later in the terminal, or the Desktop Code tab with
  bundled Claude Code 2.1.286 or later ([mods overview](https://code.claude.com/docs/en/plugins/mods/overview)).
- A way to deliver managed settings ([deploy managed settings](https://code.claude.com/docs/en/managed-settings))
  and to place a directory on every machine (MDM or configuration management). Managed
  settings delivered from the claude.ai admin console can carry the keys below, but cannot
  put the directory on a machine.
- No Node.js or npm on users' machines: the mod runs inside Claude Code.

## 1. Place the marketplace directory

Claude Code treats a mod as the organization's only when managed `enabledPlugins` turns it
on and its marketplace is a directory on the machine, named by absolute path, from which
the plugin loads in place ([install your organization's mods](https://code.claude.com/docs/en/plugins/mods/admin#install-your-organizations-mods)).
A copy installed from GitHub, git, a URL or npm, including `taint-guard@dortort`, counts as
a user's mod and is skipped by `prependPlugins`.

Copy a released TaintGuard into a marketplace directory, here `/opt/acme/claude-plugins`:

```bash
git clone --depth 1 --branch taint-guard--v0.1.0 https://github.com/dortort/claude-plugins.git /tmp/claude-plugins
sudo mkdir -p /opt/acme/claude-plugins/.claude-plugin /opt/acme/claude-plugins/plugins
sudo cp -R /tmp/claude-plugins/plugins/taint-guard /opt/acme/claude-plugins/plugins/taint-guard
claude plugin validate --strict /opt/acme/claude-plugins/plugins/taint-guard
```

Add the marketplace manifest, which lists the plugin by a relative path:

```json
{
  "name": "acme-security",
  "owner": { "name": "Acme" },
  "plugins": [
    {
      "name": "taint-guard",
      "source": "./plugins/taint-guard",
      "description": "Refuse risky tool calls once sensitive or untrusted sources entered the session"
    }
  ]
}
```

Save it as `/opt/acme/claude-plugins/.claude-plugin/marketplace.json`. Make the directory,
and every directory above it, writable only by an administrator, as the managed settings
file is: anyone who can write there can rewrite the mod. Distribute the same directory to
the same path on every machine.

`claude plugin validate --strict` prints the `hooks:` and `calls:` lines of the mod, so you
can review what it receives and which mods API methods it calls before you deploy it.

## 2. Write the managed policy

The managed policy layer is a TaintGuard policy file at a path only managed settings can
name. It sits above the user and project layers: a managed rule cannot be switched off by
a user or a repository, and the managed layer may switch off any other rule. Its global
settings join the strictest-value merge (`mode`, `userDeclassify`, `onUnknownHistory`),
and its `resetOnClear` wins over the user's.

**The managed floor on the globals.** Once managed settings set `enabled: true` or a
`preset` (step 3), `mode`, `userDeclassify` and `onUnknownHistory` are taken from the
managed policy, the preset and the defaults (`enforce`, `confirm`, `assume-tainted`) alone.
A user policy can only make them stricter: a user `mode: "audit"` or `"ask"`,
`userDeclassify: "allow"` or `onUnknownHistory: "ignore"` is ignored, and `/taintguard`
lists a warning saying so. Without the lock or a preset, a user may lower them for their
own sessions, down to what the managed policy sets. A repository's project policy can never
lower them. So a managed policy needs to set a global only to go beyond the defaults, as
`userDeclassify: "never"` does below.

This example keeps the preset's rules, adds a CRM source, refuses shells and web tools
after secrets or customer data, refuses Slack posts after private or customer data, and
forbids declassification. Save it where only an administrator can write, for example
`/etc/claude-code/taint-guard.json` on Linux or
`/Library/Application Support/ClaudeCode/taint-guard.json` on macOS:

```json
{
  "$schema": "https://raw.githubusercontent.com/dortort/claude-plugins/main/plugins/taint-guard/schema/taint-guard.schema.json",
  "version": 1,
  "description": "Acme managed TaintGuard policy",
  "mode": "enforce",
  "resetOnClear": true,
  "userDeclassify": "never",
  "onUnknownHistory": "assume-tainted",
  "labels": {
    "private": { "description": "Data the user owns: mail, documents, chats" },
    "untrusted": { "description": "Text written by third parties" },
    "secret": { "description": "Credentials and keys" },
    "customer": { "description": "Customer records from the CRM" }
  },
  "sources": [
    {
      "id": "crm-read",
      "description": "Any tool on a Salesforce or HubSpot MCP server",
      "match": { "tool": { "regex": "^mcp__(claude_ai_)?(salesforce|hubspot)[^_]*__", "flags": "i" } },
      "on": "attempt",
      "taints": ["customer", "untrusted"]
    }
  ],
  "sinks": [
    {
      "id": "no-egress-after-secrets",
      "when": { "anyOf": ["secret", "customer"] },
      "block": [
        { "tool": { "exact": "Bash" } },
        { "tool": { "anyOf": ["WebFetch", "WebSearch"] } }
      ],
      "action": "deny",
      "reason": "Shells and web tools are disabled after reading secrets or customer records."
    },
    {
      "id": "no-slack-posts",
      "when": { "anyOf": ["private", "customer"] },
      "block": [
        { "tool": { "regex": "^mcp__(claude_ai_)?slack[^_]*__(.*_)?(send|post|reply|schedule)", "flags": "i" } }
      ],
      "action": "deny",
      "reason": "Posting to Slack is disabled in a session that holds private or customer data."
    }
  ]
}
```

Check it before you ship it: `/taintguard reload` in a test session reports any error, and
the file validates against the [policy schema](../schema/taint-guard.schema.json) with any
JSON Schema draft 2020-12 validator. An invalid managed policy, or one that exists but
cannot be read, puts every session in **lockdown**: every label is treated as present and
the `strict` preset's rules are added, so a broken file fails closed. So does a
`managedPolicyPath` that names no file: a missing managed policy is a lockdown, never
"no managed layer".

## 3. Write the managed settings

Add these keys to the managed settings file
([where managed settings live](https://code.claude.com/docs/en/managed-settings)):

```json
{
  "extraKnownMarketplaces": {
    "acme-security": {
      "source": { "source": "directory", "path": "/opt/acme/claude-plugins" }
    }
  },
  "enabledPlugins": {
    "taint-guard@acme-security": true,
    "taint-guard@dortort": false
  },
  "prependPlugins": ["taint-guard@acme-security", "sec-default@builtin"],
  "pluginConfigs": {
    "taint-guard@acme-security": {
      "options": {
        "enabled": true,
        "preset": "trifecta",
        "managedPolicyPath": "/etc/claude-code/taint-guard.json"
      }
    }
  }
}
```

What each key does:

- **`extraKnownMarketplaces`** names the directory that holds the `acme-security`
  marketplace; `path` is the absolute path of the directory that contains
  `.claude-plugin/marketplace.json`.
- **`enabledPlugins`** turns TaintGuard on for everyone who receives these settings, and
  keeps a second copy from the public `dortort` marketplace off.
- **`prependPlugins`** runs TaintGuard first and the built-in guard second, both ahead of
  any mod a user installs. Setting the list replaces the default, so keep
  `sec-default@builtin` in it; the recommended list is
  `["taint-guard@<marketplace>", "sec-default@builtin"]`.
- **`pluginConfigs["taint-guard@<marketplace>"].options`** pins TaintGuard's options:
  - `enabled: true` is a lock: the user's own `enabled: false` is then ignored.
  - `preset` is a floor: the stricter of the managed and the user's preset applies
    (`strict` > `trifecta` > `none`), and the user cannot switch off preset rules from
    their policy file.
  - Either of the two puts the globals under the managed floor (step 2).
  - `managedPolicyPath` names the managed policy file. Only this managed value counts; the
    same key in user settings is ignored with a warning.

TaintGuard reads these three options with `$.settings.read({ source: "policy" })`, which
returns managed settings alone, because the merged `options` would fall back to the user's
value for any key managed settings leave out. If that read fails, TaintGuard turns itself
on and enters lockdown, as the built-in guard fails closed when it cannot read managed
settings ([set options on the built-in guard](https://code.claude.com/docs/en/plugins/mods/admin#set-options-on-the-built-in-guard)).
The other options (`showBand`, `auditLog`, `auditArguments`, `userPolicyPath`) are
preferences: managed values for them are defaults a user can change.

### Self-protection

Every session also carries one rule that is in no policy file: `builtin:self-protect`.
While any label is held, during lockdown, and until a restart or resume rebuild has
finished, it refuses `Write`, `Edit`, `MultiEdit` and `NotebookEdit` calls, and MCP tools
with a write verb, that target the managed policy file, the user policy file, the
project's `.claude/taint-guard.json`, `.claude/settings.json` and
`.claude/settings.local.json`, the config directory's
`settings.json` and `settings.local.json`, or anything under its `taint-guard/` (audit log)
and `plugins/` directories (for a move, rename or delete, also any directory that holds
them), and `Bash` commands whose text mentions `taint-guard`, a `.claude` directory or
`settings.local.json`. It applies in every `mode`, and no layer,
managed included, can switch it off.

It keeps injected text from rewriting the user's own files so that the next session loads
a weaker policy. It is not what protects the organization's files: the managed settings
file, the managed policy and the marketplace directory stay safe because only an
administrator can write them, and the `Bash` check reads the command's text, so a command
that builds a path at run time gets past it. Keep those paths administrator-only, as step 1
and step 2 say.

To also keep users' own mods from running at all, add the built-in guard's
`allowManagedModsOnly` option and, if you want, `disableSideloadFlags`; TaintGuard is the
organization's mod and keeps running
([allow only your organization's mods](https://code.claude.com/docs/en/plugins/mods/admin#allow-only-your-organizations-mods)).

## 4. Verify on a test machine

1. **Chain position.** Start a session with `claude --debug` and search the debug log for
   `taint-guard@acme-security`. The line `hooks module taint-guard@acme-security loaded`
   must carry `tier prepend`. With `tier user`, and a line saying `prependPlugins names
   taint-guard@acme-security, which is not an enabled managed plugin with a hooks module;
   skipped`, the marketplace is not a managed directory or the plugin is not enabled in
   managed settings.
2. **Managed layer.** Run `/taintguard`. The heading reads `TaintGuard: clean`, and under
   *Policy layers* the managed layer reads
   `managed: loaded, <n> rules, /etc/claude-code/taint-guard.json` next to the preset you
   set as a floor. `invalid` with an error (`file not found`, a JSON or schema error) means
   the session is in lockdown.
3. **A rule fires.** Run `/taintguard explain Bash {"command":"ls"}` (allowed while clean),
   have Claude read a file named `.env`, then run the same `explain`: it names the rule that
   refuses Bash.
4. **The lock holds.** Set `enabled` off and `preset` to `none` in TaintGuard's options in
   the config menu, start a new session, and check that `/taintguard` still shows it on
   with the managed preset.
5. **Audit.** `/taintguard audit` prints the path of the session's audit log
   (`~/.claude/taint-guard/audit/<sessionId>.jsonl`) and its last entries.

To check the settings reached the machine at all, see
[check that a policy is in force](https://code.claude.com/docs/en/managed-settings#check-that-a-policy-is-in-force).

## What a user can and cannot change

| Setting | User | Repository (`.claude/taint-guard.json`) |
| --- | --- | --- |
| Turn TaintGuard off | No, with managed `enabled: true` | No |
| Lower the preset | No below the managed floor | No |
| Point at another managed policy | No: `managedPolicyPath` is read from managed settings only | No |
| Switch off a managed rule | No | No |
| Switch off a preset rule | No, once managed settings set a `preset` | No |
| Add labels, sources and sinks | Yes, in the user policy | Yes; a broken project file is dropped with a warning |
| Lower `mode`, `userDeclassify` or `onUnknownHistory` | No, once managed settings set `enabled: true` or a `preset`: the user layer can then only tighten them. Otherwise only where no managed value is stricter | No |
| Have Claude write the policy or settings files in a tainted session | No: `builtin:self-protect` refuses it while any label is held; the user can still edit their own files outside Claude | No |
| Set `resetOnClear` | Only when the managed policy does not | No (ignored with a warning) |
| Clear labels with `/taintguard clear` | Only as `userDeclassify` allows (`never` refuses) | No: Claude and SDK hosts cannot run it |
| Answer **Allow once** on an `ask` sink | Yes, audited; use `deny` sinks where that is not acceptable | — |
| `showBand`, `auditLog`, `auditArguments`, `userPolicyPath` | Yes | No |
| Change the chain order | No: `prependPlugins` is read from managed settings only | No |

## Updating

Replace `/opt/acme/claude-plugins/plugins/taint-guard` with the new release's
`plugins/taint-guard` directory, run `claude plugin validate --strict` on it, and keep the
directory administrator-only. Running sessions pick the new code up on `/reload-plugins` or
restart; the taint set survives a reload. Release notes for each version are in
[releases/](../releases).

## References

- [Mods overview](https://code.claude.com/docs/en/plugins/mods/overview)
- [React to events with a mod](https://code.claude.com/docs/en/plugins/mods/events)
- [Mods reference](https://code.claude.com/docs/en/plugins/mods/reference)
- [Use the mods API](https://code.claude.com/docs/en/plugins/mods/api)
- [Draw in the interface (keep state)](https://code.claude.com/docs/en/plugins/mods/interface)
- [Manage mods for your organization](https://code.claude.com/docs/en/plugins/mods/admin)
- [Test a mod](https://code.claude.com/docs/en/plugins/mods/test)
- [Configure permissions](https://code.claude.com/docs/en/permissions)
- [Claude Code mod type declarations (claude-code.d.ts)](https://github.com/anthropics/claude-code/blob/main/mods/types/claude-code.d.ts)
