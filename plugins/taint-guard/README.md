# TaintGuard

*Prevent sensitive context from reaching unsafe tools.*

A Claude Code mod that remembers which sensitive or untrusted sources have entered a
session and refuses risky tool calls once they have. Claude reads your mail through a
Gmail MCP server; from then on, every `Bash` call in that session needs your approval,
and once it has read an `.env` file, `Bash`, `WebFetch` and outbound MCP tools are
refused outright. Claude is told what is blocked the moment it happens, the band above
the prompt shows it, and every taint, refusal and declassification goes to an audit log.

TaintGuard defends against prompt injection that arrives in a tool result (an email, a
web page, a shared document) and asks Claude to send data or secrets out through a later
tool call. It reasons about which tools ran, not about which bytes flow where.

## Install

```bash
claude plugin marketplace add dortort/claude-plugins
claude plugin install taint-guard@dortort
```

The catalog installs the latest promoted release (see [Releases](#releases)). To try
unreleased changes, load it from a checkout of this repository instead:

```bash
claude --plugin-dir ./plugins/taint-guard
```

Requirements: Claude Code with mods, **2.1.287 or later in the terminal**, or the Desktop
Code tab with bundled Claude Code **2.1.286 or later** ([mod requirements](https://code.claude.com/docs/en/plugins/mods/overview)).
Nothing else: the hooks module runs inside Claude Code, so there is no Node.js, npm
package or build step at runtime.

Organizations should deploy TaintGuard as a managed mod listed in `prependPlugins`, so
that no user-installed mod sees a tool call before it does. The
[deployment guide](docs/deployment.md) has the managed settings.

## How it works

A session carries one **taint set**: the labels its sources have added.

| Term | What it is | Example |
| --- | --- | --- |
| Label | A named kind of risk carried by context, declared in the policy | `private`, `untrusted`, `secret` |
| Source | A tool-call matcher plus the labels it adds when it fires | Any read on a mail MCP server adds `private` and `untrusted` |
| Trigger timing | `attempt` fires before the tool runs, even if it then fails or is refused; `success` fires only after it returns without `deny` or `isError` | Mail: `attempt`; `WebFetch`: `success` |
| Sink | A label condition (`anyOf` / `allOf`), the tools it blocks, optional exceptions, and an action | Refuse `Bash` while `secret` is present |
| Action | `deny` (refuse), `ask` (the user decides), or `audit` (log only) | `ask` before posting to Slack |
| Declassification | An explicit, logged removal of labels by the user | `/taintguard clear untrusted` |

Every tool call Claude makes, built-in or MCP, from the main agent or a subagent, passes
TaintGuard's `tool.call` hook, which decides in this order:

1. **Sinks first, on earlier taint.** The call is checked against every sink whose label
   condition the taint set *as it was before this call* satisfies. The strictest match
   wins (`deny` > `ask` > `audit`). A refused call never starts.
2. **`attempt` sources** on this call add their labels.
3. **The tool runs** (`next`), still subject to Claude Code's own permission rules and
   settings hooks.
4. **`success` sources** add their labels if the tool returned without `deny` or `isError`.
5. **Claude is told.** If the taint set grew, the tool's result carries one context line
   naming the new labels and the tools that are now refused or need approval.

A call that is both a source and a sink (sending mail after reading mail) is judged on
earlier taint only. Subagents share the session's taint set: a subagent that reads mail
taints its parent too.

**Fail closed.** The hook has a `.catch` handler. If the guard throws or times out before
the tool ran, the handler re-checks the active sinks by tool name alone (an argument
predicate counts as matching, an `except` is ignored, a project-layer regex is assumed to
match without being run, and `ask` becomes `deny`) and refuses on any match, writing a
`guard-failure` audit entry. If no policy was loaded yet, it refuses. If the failure came
after the tool ran, the result is returned as it is. An invalid managed or user policy, or
a failed read of managed settings, puts TaintGuard in **lockdown** (below).

The taint set lives in the mod's `$.state`, so it survives a save or `/reload-plugins`.
A copy is kept in `$.store` under `taint:<sessionId>` (copies older than 14 days are
pruned at session start). After `/resume`, `/branch` or a restart, TaintGuard rebuilds
the set from the conversation history, including subagent transcripts, replaying sources
exactly as they fired, and merges the result into the stored copy and into any label added
while the rebuild ran, so a rebuild can keep or add taint but never lose it. Until the
rebuild has succeeded, every call is judged as if every label were held; a failed rebuild is
retried on the next call. When the history may be cut, `onUnknownHistory: "assume-tainted"`
adds every label. History counts as cut when the API returns its limit of 4,096 entries,
when the stored copy cannot be read, and when subagent history is unknown: a subagent
transcript that cannot be read, more than the newest 20 subagents, or a subagent cut at
4,096 entries. Subagents started before a `/taintguard clear` are not read again, so a
cleared label does not come back on restart. While tainted, a
compaction asks the summarizer to keep a one-line taint record
(`TaintGuard taint record v1: labels=private,untrusted`) and appends the same line to the
compacted messages, so a later resume or branch finds it. A record can only add labels.
`/clear` empties the set when `resetOnClear` is true (the default).

## Presets

The `preset` option loads a built-in rule pack beneath your policy files. Presets match
MCP tools by server family and verb, because exact tool names differ between servers and
change over time. They cover local servers and claude.ai connectors
(`mcp__claude_ai_<server>__<tool>`), case-insensitively.

| Server family | The server name contains |
| --- | --- |
| mail | `gmail`, `google_mail`, `google-mail`, `googlemail`, `outlook`, `mail` |
| documents | `drive`, `gdrive`, `google_drive`, `google-drive`, `docs`, `google_docs`, `notion`, `onedrive`, `sharepoint` |
| chat | `slack`, `teams`, `chat` |
| web | `fetch`, `browser`, `chrome`, `puppeteer`, `playwright`, `selenium`, `crawl`, `scrape`, `tavily`, `brave`, `web` |

Mail, documents and chat servers hold the user's private data. Web servers read pages
written by third parties and reach URLs Claude chooses, so every tool on them, whatever
its verb, is both an `untrusted` source and an outbound tool. No other server is
classified: GitHub, Jira, Confluence, Linear, Zendesk and other issue trackers and ticket
systems are not labelled by any preset (see the limitations below).

A verb counts when it starts the tool's name or follows `_` or `-` in it. Read verbs: get,
read, search, list, fetch, download, history. Write verbs: send, post, reply, forward,
create, update, upload, share, schedule, comment, invite.

Both `trifecta` and `strict` declare the labels `private`, `untrusted` and `secret`, and
the same sources:

| Source id | Fires on | When | Adds |
| --- | --- | --- | --- |
| `preset:private-read` | A read verb on a mail, documents or chat server (`gmail_search_messages`, `read_message`, `slack_search_public`) | `attempt` | `private`, `untrusted` |
| `preset:private-other` | A tool with neither a read nor a write verb on such a server (`apply_label`, `archive`) | `attempt` | `private`, `untrusted` |
| `preset:web-content` | `WebFetch`, `WebSearch` | `success` | `untrusted` |
| `preset:web-mcp` | Any tool on a web server (`mcp__fetch__fetch`, `mcp__playwright__browser_navigate`, `mcp__chrome__get_page_text`) | `success` | `untrusted` |
| `preset:secret-files` | `Read` of a secret file | `attempt` | `secret` |
| `preset:secret-grep` | `Grep` whose `path` is a secret file | `attempt` | `secret` |
| `preset:secret-grep-glob` | `Grep` whose `glob` names a secret file (`.env*`, `**/.env`) | `attempt` | `secret` |

Secret files are `.env` and `.env.*` (except `.env.example`, `.env.sample`,
`.env.template`, `.env.dist`), `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`,
`credentials`, `.git-credentials`, `.netrc`, `.pgpass`, `.npmrc`, `*.pem`, `*.key`, and the
CLI login stores `gh/hosts.yml`, `.docker/config.json` and `.kube/config`.

The **outbound** tools are `Bash`, `WebFetch`, any MCP tool with a write verb
(`slack_send_message`, `create_issue`, `upload_file`), every tool on a web server, and the
unknown-verb tools on private-data servers, which are therefore both source and sink: the
fail-safe answer for a tool TaintGuard cannot classify is to taint and to block. The write
verbs are the spec's list; an MCP tool named with another verb, such as `push_files` or
`put_object`, is not outbound.

| Preset | Sinks |
| --- | --- |
| `trifecta` (default) | `preset:outbound-secret`: outbound tools and `WebSearch` are **refused** while `secret` is present. `preset:outbound-private`: outbound tools **ask** while `private` and `untrusted` are both present, except a mail server's `create_draft`. |
| `strict` | `preset:outbound-any`: outbound tools, plus `WebSearch`, `Write`, `Edit` and `NotebookEdit`, are **refused** once any label is present. |
| `none` | No rules; only your policy files apply. |

The generated presets are [presets/trifecta.json](presets/trifecta.json) and
[presets/strict.json](presets/strict.json).

### What the presets cost on ordinary work

The benign-task eval replays 120 ordinary tasks (90 coding, 30 mail triage) through the
presets ([results](evals/RESULTS.md#benign-task-eval)). The spec's target for `trifecta`
counts only misfires, an ask or refusal raised because a source labelled content that is not
actually private, third-party or secret: under 5% of tasks interrupted by one, and under 1%
unable to finish because of one. The asks and refusals the preset exists to raise, an outbound
call after reading private third-party content or after reading a secret, are designed gates,
reported separately and not counted against the target. `trifecta` meets it:

| Preset | Interrupted by a misfire | Failed by a misfire | Interrupted by a designed gate | Failed by a designed gate | Hit an ask or refusal (all causes) | Could not finish (all causes, asks approved) | Spec target |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `trifecta` | 0.8% | 0.8% | 17.5% | 1.7% | 18.3% | 2.5% | misfires under 5% and under 1% |
| `strict` | 0.8% | 0.8% | 39.2% | 39.2% | 40.0% | 40.0% | none |

The one misfire is a test certificate: the `secret` rule matches every `*.pem`, so reading
`test/fixtures/localhost.pem` refuses Bash until you run `/taintguard clear`. It sits close to
the 1% target, which one more such task in 120 would miss. Under `trifecta` the designed gates
are the preset at work: after reading mail it asks before replying to, forwarding or
labelling mail, before creating a calendar entry and before Bash; in a coding task it asks
before Bash after reading Slack or Notion; and after `.env` is read it refuses Bash, so the
tasks that read `.env` and then needed Bash could not finish. In a headless session nobody
answers the asks, so every one of them stops its task. Under `strict` every web lookup, mail
read and Slack or Notion read ends Bash, `Write` and `Edit`.

If that is too much friction for your work, write a user policy that switches off the
preset rule that gets in the way, such as
`{ "id": "preset:outbound-private", "enabled": false }` in `sinks`, and add a narrower sink
of your own; or set `preset` to `none` and write all the rules yourself. Neither works where
managed settings set a preset: an organization's floor is not yours to lower.

## Options

Set them in the plugin's options in the config menu (`userConfig` in
[.claude-plugin/plugin.json](.claude-plugin/plugin.json)). Claude Code stores them under
`pluginConfigs["taint-guard@<marketplace>"].options`.

| Option | Type | Default | What it does |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch. Off, every call passes unchecked and one `disabled` audit entry is written per session. Ignored when managed settings set `enabled: true`. |
| `preset` | `strict` / `trifecta` / `none` | `trifecta` | Built-in rule pack loaded beneath the policy files. A preset set in managed settings is a floor: the stricter of the two applies (`strict` > `trifecta` > `none`). |
| `userPolicyPath` | string | `~/.claude/taint-guard.json` | The user policy layer. A leading `~` is your home directory. |
| `managedPolicyPath` | string | `""` | The managed policy layer. Read only from managed settings; the same key in user settings is ignored with a warning. |
| `showBand` | boolean | `true` | Draw the band above the prompt while the session is tainted. |
| `auditLog` | boolean | `true` | Write the JSONL audit log. |
| `auditArguments` | boolean | `false` | Also log the first 200 characters of the raw tool arguments; a keyed hash is always logged. |

`enabled`, `preset` and `managedPolicyPath` are read from managed settings alone
(`$.settings.read({ source: "policy" })`), because the merged options would fall back to
user values for any key managed settings leave out. If that read fails, TaintGuard turns
itself on and enters lockdown.

## The policy file

The rules live in versioned JSON policy files validated against the
[policy schema](schema/taint-guard.schema.json) (JSON Schema draft 2020-12). TaintGuard
loads up to four layers, from most to least trusted:

| Layer | Where it comes from |
| --- | --- |
| managed | The file at `managedPolicyPath`, set in managed settings only |
| user | `userPolicyPath`, by default `~/.claude/taint-guard.json` |
| project | `.claude/taint-guard.json` in the session's working directory |
| preset | The `preset` option (lowest trust, loaded beneath the others) |

A repository is untrusted input, so the merge lets a lower-trust layer only tighten:

- **Rules combine.** Labels, sources and sinks from every layer apply together. Rule ids
  are namespaced by layer: `managed:gmail-read`, `user:no-shell-after-mail`,
  `preset:outbound-private`. A label a layer uses must be declared by some layer.
- **Switching rules off.** A rule written with `"enabled": false` is off. To switch off
  another layer's rule, list a reference `{ "id": "<layer>:<id>", "enabled": false }` in
  `sources` or `sinks`. The managed layer may switch off any rule; the user layer its own,
  project and preset rules (but not preset rules when the preset floor came from managed
  settings); the project layer only its own. A reference that is not allowed is ignored
  with a warning and the rule stays on.
- **Globals take the strictest value.** `mode`: enforce > ask > audit (default enforce).
  `userDeclassify`: never > confirm > allow (default confirm). `onUnknownHistory`:
  assume-tainted > ignore (default assume-tainted). A project layer cannot lower any of
  them below what the trusted layers, or the defaults, give.
- **The managed floor.** When managed settings lock TaintGuard on (`enabled: true`) or set
  a `preset`, `mode`, `userDeclassify` and `onUnknownHistory` come from the managed layer,
  the preset and the defaults alone. The user layer can then only tighten them: a user
  `mode: "audit"`, `userDeclassify: "allow"` or `onUnknownHistory: "ignore"` is ignored
  with a warning. Without managed settings, the user layer may lower them for its own
  sessions.
- **`resetOnClear`** comes from the managed layer, else the user layer, else `true`; a
  project value is ignored with a warning. **`subagents`** is `shared`, the only v1 value.
- **The managed path** comes only from managed settings, so no user or project file can
  point TaintGuard at a different managed policy.

**Validation and lockdown.** Each layer is validated at session start and on
`/taintguard reload`: the schema, unknown label names, duplicate ids within a layer and
regexes that fail to compile. A project layer's regexes are limited further, so a
repository cannot stall the guard: no nested unbounded quantifiers (`(a+)+`), no
alternation under an unbounded quantifier (`(a|aa)+`), at most 256 characters each, and at
most 50 in the file. Rules that match no tool are not errors: MCP servers connect and change
their tools during a session, and `/taintguard tools` shows which rules match what. An
invalid managed or user layer, an unreadable policy file, or a failed read of managed
settings puts TaintGuard in **lockdown**: every label is treated as present, the `strict`
preset's rules are added, `mode` is `enforce`, and the band shows the error in red. An
invalid project layer is dropped with a warning, so a repository cannot switch protection
off by breaking its file. A user or project policy file that does not exist is simply
absent; a managed policy path that names no file is a lockdown.

### Example policy

The motivating rule plus an egress guard, as a user policy at `~/.claude/taint-guard.json`
(with `preset` set to `none` to use it alone, or on top of a preset):

```json
{
  "$schema": "https://raw.githubusercontent.com/dortort/claude-plugins/main/plugins/taint-guard/schema/taint-guard.schema.json",
  "version": 1,
  "mode": "enforce",
  "subagents": "shared",
  "resetOnClear": true,
  "userDeclassify": "confirm",
  "onUnknownHistory": "assume-tainted",
  "labels": {
    "private": { "description": "Data the user owns: mail, documents, chats" },
    "untrusted": { "description": "Text written by third parties" },
    "secret": { "description": "Credentials and keys" }
  },
  "sources": [
    {
      "id": "gmail-read",
      "match": {
        "tool": {
          "regex": "^mcp__(claude_ai_)?(gmail|google[_-]?mail)[^_]*__(.*_)?(get|read|search|list|fetch|download|history)",
          "flags": "i"
        }
      },
      "on": "attempt",
      "taints": ["private", "untrusted"]
    },
    {
      "id": "web-content",
      "match": { "tool": { "anyOf": ["WebFetch", "WebSearch"] } },
      "on": "success",
      "taints": ["untrusted"]
    },
    {
      "id": "secret-files",
      "match": {
        "tool": { "exact": "Read" },
        "arguments": [
          { "pointer": "/file_path", "matches": "(^|/)([.]env[^/]*|id_(rsa|ed25519|ecdsa)|credentials)$" }
        ]
      },
      "on": "attempt",
      "taints": ["secret"]
    }
  ],
  "sinks": [
    {
      "id": "no-shell-after-mail",
      "when": { "anyOf": ["private", "secret"] },
      "block": [{ "tool": { "exact": "Bash" } }],
      "action": "deny",
      "reason": "Bash is disabled because this session has read private mail or secrets."
    },
    {
      "id": "outbound-after-untrusted-private",
      "when": { "allOf": ["private", "untrusted"] },
      "block": [
        { "tool": { "exact": "WebFetch" } },
        {
          "tool": {
            "regex": "^mcp__.+__(.*_)?(send|post|reply|forward|create|update|upload|share|schedule|comment|invite)",
            "flags": "i"
          }
        }
      ],
      "except": [
        { "tool": { "regex": "^mcp__(claude_ai_)?(gmail|google[_-]?mail)[^_]*__(.*_)?create_draft$", "flags": "i" } }
      ],
      "action": "ask",
      "reason": "This would send data out of a session that holds private, third-party content."
    }
  ]
}
```

### Schema reference

| Path | Type | Required | Notes |
| --- | --- | --- | --- |
| `$schema` | string | no | The published schema URL above |
| `version` | integer | yes | `1`. Unknown versions fail validation. |
| `description` | string | no | Free text |
| `mode` | `enforce` / `ask` / `audit` | no, `enforce` | `ask` turns every `deny` into `ask`; `audit` turns every action into `audit` (dry run) |
| `subagents` | `shared` | no | The only v1 value; `per-agent` is reserved for v1.1 |
| `resetOnClear` | boolean | no, `true` | Empty the taint set on `/clear` |
| `userDeclassify` | `allow` / `confirm` / `never` | no, `confirm` | Whether `/taintguard clear` works, and whether it asks first |
| `onUnknownHistory` | `assume-tainted` / `ignore` | no, `assume-tainted` | Rebuild behavior when history may be cut |
| `labels.<name>` | object | yes, at least 1 | `description` (string). Names: letters, digits and `-`, up to 32 characters. |
| `sources[]` | object | no | `id`, `description`, `match`, `on` (`attempt` / `success`, default `attempt`), `taints` (label names, at least 1), `enabled` |
| `sinks[]` | object | no | `id`, `description`, `when`, `block` (at least 1 matcher), `except`, `action` (`deny` / `ask` / `audit`, default `deny`), `reason` (at most 1,000 characters), `enabled` |
| `id` | string | yes in a rule | Letters, digits, `.`, `_` and `-`, up to 64 characters, unique within the layer. A reference `<layer>:<id>` has exactly the keys `id` and `enabled: false`. |
| `when` | object | yes in a sink | `anyOf` and/or `allOf` (label names). Both present: both must hold. Empty object: always active. |
| matcher | object | — | `tool` selector plus optional `arguments` predicates; all must match |
| `tool` selector | object | — | Exactly one of `exact` (name), `prefix`, `regex` (ECMAScript, anchored by the author), `anyOf` (names); optional `flags: "i"` with `prefix` or `regex` |
| `arguments[]` | object | no | `pointer` (JSON Pointer into the tool's arguments, which are the call's fields other than `tool`, `tool_use_id`, `agentId` and `consent`) plus exactly one of `equals`, `matches`, `notMatches`, `exists`; optional `flags: "i"` with `matches` or `notMatches` |

**Argument text over 100,000 characters** is never run through a regex. It fails closed
instead: a `matches` or `notMatches` predicate counts as matching inside a source or a
sink's `block`, and as not matching inside an `except`. Padding an argument therefore adds
taint and keeps a sink active rather than slipping past either.

### Built-in self-protection

Under `trifecta`, `Write` and `Edit` are not sinks, so without more, injected text could
have Claude rewrite TaintGuard's own policy or settings, and the change would load on the
next restart or `/reload-plugins`. One rule is therefore built in and not part of any
layer: `builtin:self-protect`. While any label is held, during lockdown, and while a
rebuild is pending, it refuses:

- `Write`, `Edit`, `MultiEdit` and `NotebookEdit` on the user policy file, the managed
  policy file, the project's `.claude/taint-guard.json`, `.claude/settings.json` and
  `.claude/settings.local.json`, the config directory's `settings.json` and
  `settings.local.json`, and anything under its `taint-guard/` (the audit log) and
  `plugins/` directories;
- an MCP tool with a write verb (`write`, `edit`, `move`, `delete`, `put`, `save`, …) whose
  arguments name one of those paths, or, for a move, rename or delete, a directory that
  holds one of them (`~/.claude` itself); a call whose arguments are too many or too deeply
  nested to inspect is refused as well;
- a `Bash` command whose text mentions `taint-guard`, a `.claude` directory or
  `settings.local.json`.

It applies in every `mode`, `audit` included, and no policy file can switch it off. The
`Bash` check is best effort: it reads the command's text, so a command that builds the path
at run time (a variable such as `$CLAUDE_CONFIG_DIR`, an encoding) is not recognised. Refusals name the rule and are audited as `deny` entries with
`rule: "builtin:self-protect"`.

## What Claude and the user see

**The band.** While any label is present, one line is drawn above the prompt (yellow; red
in lockdown); nothing is drawn while the session is clean:

```text
TaintGuard · tainted: private, untrusted (mcp__gmail__get_email, 14:02) · blocked: Bash · asks: WebFetch, 4 MCP tools · /taintguard
TaintGuard · LOCKDOWN: user policy /home/me/.claude/taint-guard.json: invalid JSON: … · all sinks active
```

Where nothing draws (`claude -p`, cloud sessions), the same text goes to the transcript
log once per change.

**When a source fires**, the tool's result carries one context line, which Claude reads
right after the result and the user does not see, so Claude learns of the block before it
plans its next call:

```text
TaintGuard: this session now holds private, untrusted content (from mcp__gmail__read_message). From now on these tools will be refused: Bash. These need user approval: WebFetch, mcp__slack__slack_send_message.
```

**On each prompt** while tainted (or in lockdown), the same summary is added as a context
line for Claude, ending with "Do not try to reach a refused result through another tool."

**When a call is denied**, Claude's tool result is written as an instruction. A reason
written in a project policy is prefixed with `(repository policy)`, so a repository cannot
speak in TaintGuard's own voice, and where a trusted sink and a project sink take the same
action, the trusted one supplies the words:

```text
TaintGuard refused Bash. Bash is disabled because this session has read private mail or secrets.
Active labels: private, untrusted (from mcp__gmail__get_email). Rule: user:no-shell-after-mail.
Do not retry this call or reach the same result through another tool. Continue with allowed tools, or tell the user what you need run and why.
```

The transcript gets one line, `TaintGuard refused Bash (user:no-shell-after-mail)`, and
repeated refusals of the same tool in a turn are collapsed into a count at the end of the
turn.

**Ask flow.** For an `ask` sink, the call is held and TaintGuard asks you, with the tool,
a one-line summary of its arguments, the reason and the labels, offering **Allow once**
and **Refuse**. The summary puts destination fields (a channel, recipient or URL) first
and, past 600 characters, shows both the start and the end, where a long shell command
usually names where it sends data. Dismissing the question, typing an answer, or a session
where TaintGuard cannot ask (`claude -p`) all refuse. **Allow once** passes the call on, so
Claude Code's normal permission checks still apply after it, and is audited with the
labels it overrode. TaintGuard asks itself rather than returning a native permission
`ask`, so the question reaches a person in every permission mode, including auto mode and
`bypassPermissions`. An ask waits until someone answers: use `deny` sinks for unattended
sessions.

## `/taintguard`

| Command | Effect |
| --- | --- |
| `/taintguard` | Status: on, off, clean, tainted or lockdown; each label with the rule, tool, subagent and time that added it; active rules; refused calls; what is refused or needs approval now; the policy layers loaded and any warnings; background tasks started before taint. `/taintguard status` is the same. |
| `/taintguard explain <tool> [json args]` | Dry run: would this call be allowed, asked or refused right now, by which rule, and which sources it would fire. Changes nothing. |
| `/taintguard tools` | Every tool Claude has been shown this session, with the sources and sinks that match it. Flags tools on a private-data server that match no rule, and unknown-verb tools treated as source and sink. |
| `/taintguard clear [label…]` | Declassify the named labels, or all of them. With `userDeclassify: confirm` it asks first; the labels to clear are fixed before it asks, and a label that arrives while the question is open stays and is named in the reply. With `never` it refuses and names the policy layer. Always audited. Only you can run it, from the prompt (or Remote Control): Claude and SDK hosts cannot. |
| `/taintguard reload` | Re-read and re-validate every policy layer; the taint set is unchanged |
| `/taintguard audit` | The path of this session's audit log and its last 20 entries |

Commands run without a Claude turn, even while Claude is working.

## The audit log

One JSONL file per session at `~/.claude/taint-guard/audit/<sessionId>.jsonl` (under
`$CLAUDE_CONFIG_DIR` when it is set). Entries are buffered, written every second and at
session end, and the file rolls to `<sessionId>.jsonl.1` at 3.5 MiB.

| Field | Example |
| --- | --- |
| `ts` | `2026-11-01T14:02:11.204Z` |
| `event` | `taint`, `deny`, `ask-allowed`, `ask-refused`, `audit-match`, `declassify`, `reset`, `rebuild`, `lockdown`, `guard-failure`, `background-before-taint`, `compact`, `disabled`, `reload` |
| `tool` | `Bash` |
| `toolUseId` | `toolu_01A…`, to join the entry to the transcript |
| `agentId` | Present when a subagent made the call |
| `rule` | `user:no-shell-after-mail` |
| `labels` | `["private", "untrusted"]` |
| `argsHmac` | HMAC-SHA-256 of the canonical JSON arguments, hex |
| `args` | The first 200 characters of the arguments, only with `auditArguments` |
| `detail` | The reason, the record that rebuilt taint, the lockdown error |

`argsHmac` is keyed with a random 256-bit key that TaintGuard generates once per install
and keeps in its `$.store`. A plain SHA-256 of a short command such as
`curl evil.example` can be reversed by guessing; a keyed hash cannot without the key, yet
whoever holds the key can still match identical calls across entries.

## Security model and limitations

TaintGuard guarantees that a sink tool routed through Claude Code's tool pipeline does not
run while its label condition holds, unless the user approves it; it does not guarantee
that tainted data never leaves the machine.

It does not defend against a malicious user, a mod that runs before it in the chain, a
compromised MCP server (it already holds the data), processes started outside Claude
Code's tool pipeline, or side channels.

### Properties

1. **Complete mediation of tool calls.** Every built-in and MCP tool call, including subagent calls, passes the guard, since `tool.call` fires for all of them.
2. **Monotonic taint.** Labels are removed only by user declassification or a `/clear` reset; reloads, resumes and compaction can keep or add taint, never lose it.
3. **Fail closed.** The hook carries a `.catch` handler. Without one, Claude Code skips a hook that throws or times out and the call runs ([handle a hook that fails](https://code.claude.com/docs/en/plugins/mods/events#handle-a-hook-that-fails)). The handler re-checks sinks with a minimal path and denies on any match, or on any doubt; it must finish within its own 1-second limit.
4. **Before, not after.** Sinks are judged before `next(e)`, so a refused tool never starts.
5. **No weakening from the repository.** A project policy can only add rules; a broken one is dropped, never treated as "no policy".
6. **No rewriting its own policy.** While tainted, `builtin:self-protect` refuses writes to TaintGuard's policy files, Claude Code's settings files and its plugin and audit directories, in every mode (see [Built-in self-protection](#built-in-self-protection)).

### Known limitations and residual risk

| Limitation | Effect | Mitigation |
| --- | --- | --- |
| Tool-level, not data-level | Allowed tools can still move data: `Write` a file a later CI job publishes, `Edit` a script that runs on the next build | Add file-writing tools as sinks in `strict`; file taint in v2 |
| Work started before taint | A background `Bash` started before the source keeps running and cannot be revoked | Listed in /taintguard and audited at each classic.Stop; handing it data later needs a tool call TaintGuard mediates, so sources are not refused while tasks run |
| Argument matching is text matching | Regex allowlists on `Bash` commands are easy to evade (aliases, `sh -c`, encodings) | Prefer whole-tool sinks for shells; document that `except` on `Bash` is advisory |
| Chain position | A mod earlier in the chain can answer or rewrite a call before TaintGuard sees it | Deploy via managed `prependPlugins`; managed `PreToolUse` hooks still run first and stay final |
| Other mods' own API calls | Another mod's `$.http.fetch` or `$.process.run` is not a tool call | v2 hardening: as a prepended mod, intercept later mods' API calls (each is an event) while tainted |
| History cap | `$.session.messages()` returns the newest 4,096 entries, and a rebuild reads at most the newest 20 subagent transcripts | `$.store` backup copy plus `assume-tainted`, which also covers an unreadable or cut subagent transcript |
| Hook time limit | 10 s of the hook's own time per event | Hot path is in-memory and precompiled; no I/O before the decision |
| Approved escape | **Allow once** lets a sink through | Every approval is audited with the labels it overrode |
| Mods are not sandboxed | TaintGuard runs with the user's permissions | Ship small, dependency-free, reviewed with `claude plugin validate --strict`, whose `calls:` line lists the nine API namespaces it uses: `clock` (timestamps and the one-second audit flush), `command` (registers `/taintguard`), `env` (reads `CLAUDE_CONFIG_DIR`, `HOME` and `USERPROFILE` to find the policy, settings and audit paths), `fs` (reads policy files, writes the audit log), `session` (the session id and working directory, and the history a rebuild reads), `settings` (reads managed settings for the lock, the preset floor and the managed policy path), `state` (the taint set and the status the band draws), `store` (the taint copy and the audit-hash key) and `ui` (the ask and clear questions, transcript lines and the band) |
| Sources outside the preset families | No preset labels GitHub, Jira, Confluence, Linear, Zendesk or other issue trackers and ticket systems, or a mail file read with `Read`, though they carry injected text as well as mail does; their content passes through clean | Add them as sources in a user or managed policy; see [known gaps](evals/RESULTS.md#known-gaps-reported-not-gated) |
| MCP write verbs outside the spec's list | An MCP tool that writes under another verb (`push_files`, `put_object`, `paste`, `tweet`, `put_file`) is not outbound, so no preset sink blocks it | Add a sink for those tools in a user or managed policy; see [known gaps](evals/RESULTS.md#known-gaps-reported-not-gated) |
| Self-protection reads Bash text | `builtin:self-protect` refuses a `Bash` command only when its text names `taint-guard`, `.claude/settings` or `settings.local.json`; a command that builds the path at run time gets through it. Under `trifecta`, the preset still refuses `Bash` once `secret` is held and asks once `private` and `untrusted` are, but after `untrusted` content alone (a web page) such a command runs | Deploy as a managed mod with the managed policy in an administrator-only path, which the user's shell cannot write; under `strict`, `Bash` is refused once any label is held |
| Friction on ordinary work | Under `trifecta`, 18.3% of ordinary tasks hit an ask or a refusal and 2.5% could not finish. Designed gates account for 17.5% and 1.7%; misfires, which the spec's target counts, for 0.8% and 0.8% (targets: under 5% and under 1%, both met) | See [What the presets cost on ordinary work](#what-the-presets-cost-on-ordinary-work) |
| Compaction while TaintGuard was off | A session compacted while TaintGuard was disabled or not installed carries no taint record, so resuming or branching it later can come back clean | /resume of the same session still has the $.store copy; organizations deploy TaintGuard as a managed mod so it is always loaded |

One more applies to an ordinary (user-installed) TaintGuard wherever Claude Code's
built-in guard loads, which is on any machine with managed settings and on Team and
Enterprise logins: the guard passes over a user mod's hooks on `classic.*` events and
`session.compact` ([admin guide](https://code.claude.com/docs/en/plugins/mods/admin)).
There, TaintGuard still enforces every rule and rebuilds after a restart, but it cannot
rebuild after `/resume` or `/branch`, reset on `/clear`, write the compaction record, or
note background tasks. Deployed as the [organization's mod](docs/deployment.md), all of
its hooks run.

## Development

The hooks module ([hooks/register.tsx](hooks/register.tsx)) and the policy engine
([src/](src)) are TypeScript with erasable syntax only. Claude Code runs the hooks module
directly; Node.js >= 22.18 runs the unit tests and scripts directly. There is no build
step and nothing compiled is shipped. Node test files are named `*.spec.ts`, because
`claude plugin test` treats every `*.test.ts` as a hooks suite.

```bash
cd plugins/taint-guard
npm ci                       # dev-only typescript, @types/node and ajv
npm test                     # the node:test unit suites
npm run test:unit            # the same: tests/unit/*.spec.ts (policy, presets, schema, state, audit, ui, docs)
npm run typecheck            # tsc --noEmit over src, scripts and the node test suites
npm run typecheck:hooks      # tsc --noEmit over the hooks module and its suites (needs .claude-plugin/types)
npm run validate             # claude plugin validate .: manifest, hooks module and the calls it makes
npm run test:hooks           # claude plugin test .: the hooks suites, tests/acceptance.test.ts and tests/hooks.test.ts
npm run test:e2e             # a real claude session with the mod loaded (skips, saying why, without the CLI or model access)
npm run eval                 # the injection and benign-task evaluations against the presets, offline
npm run eval:live            # the same evaluations through real claude sessions (needs the CLI and model access)
node scripts/presets.ts      # regenerate presets/*.json from src/presets.ts (--check only verifies them)
```

`validate`, `test:hooks`, `test:e2e` and `eval:live` need the `claude` CLI on `PATH`;
`test:e2e` and `eval:live` also need model access. `typecheck:hooks` needs the API
declarations in `.claude-plugin/types/`, which Claude Code writes (git-ignored) each time a
session loads the mod from this folder, for example under
`claude --plugin-dir ./plugins/taint-guard`. CI has no session to write them, so there it
runs `typecheck` and checks the hooks module with `claude plugin validate --strict` and
`claude plugin test`. Do not load the mod into the session you develop it in: it would
judge that session's own tool calls.

CI runs `typecheck`, the unit tests and the presets check on Linux, macOS and Windows,
`claude plugin validate --strict`, `claude plugin test` and `test:e2e` in
[`.github/workflows/taint-guard.yml`](../../.github/workflows/taint-guard.yml).

## License

[MIT](../../LICENSE)

## Releases

Release notes are in [releases/](releases). See the [release process](../../RELEASING.md)
for versions, tags, and the separate promotion into the marketplace catalog.
