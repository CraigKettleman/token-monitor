---
summary: "WorkBuddy provider notes: transcript roots and shared session readers, the app-owned credential session, its encryption boundary, and the billing contract."
ids: [workbuddy]
read_when:
  - Changing WorkBuddy session discovery, titles, turn status or Session Detail
  - Adding or changing WorkBuddy limits collection
  - Changing how the WorkBuddy desktop session is read, validated, or reported
  - Debugging a WorkBuddy row that shows as signed out on a signed-in machine
  - Changing WorkBuddy credential handling or the app-session security boundary
---

# WorkBuddy provider

WorkBuddy's usage, transcript enrichment and quota reads have independent sources. Keep them separate when changing or debugging the provider.

| Data plane | What it measures | Primary runtime | Inputs |
| --- | --- | --- | --- |
| Token/session activity | Local model-token activity attributed to WorkBuddy | Shared usage collector through `tokscale` | Local WorkBuddy conversation data |
| Session metadata and Detail | Titles, turn boundaries, prompts, tools and per-turn tokens | Shared local metadata and Session Detail readers | WorkBuddy JSONL transcripts |
| Limits/quota | Remaining WorkBuddy Credits | Shared limits runtime | The installed WorkBuddy desktop app's session, or an explicit billing token |

Local App quota monitoring runs in the Electron main process on macOS and Windows. Linux has no supported local app credential session, and the Widget reports that capability as unavailable rather than falling back to a token. This platform restriction does not apply to local transcript readers.

## Session transcripts

Session discovery checks `~/.workbuddy/projects/**/*.jsonl`, then `~/.workbuddy-ai/projects/**/*.jsonl`; the latter is the home used by WorkBuddy 5.5. Both remain supported because tokscale scans both, and the first matching transcript wins. `providers/workbuddy/sessionMetadata.js` binds the shared CodeBuddy metadata reader to these roots. Token totals continue to come from tokscale, independently of whether a local transcript can be resolved.

The shared resolver receives the client id in its context and keeps existing metadata under `workbuddy:<sessionId>`. Bare session ids can coincide with CodeBuddy ids; sharing a parser must not share cached titles, turn state or project identity across clients.

WorkBuddy shares the [CodeBuddy transcript format and readers](codebuddy.md#workbuddy-writes-the-same-family), with two compatibility rules: a non-empty `custom-title` takes priority over `ai-title`, and older records without `providerData.messageId` or cache details still produce turns from their usage-bearing records. WorkBuddy's `<user_query>` prompt is extracted from the surrounding context envelope. Token conversion follows the pinned Tencent Buddy parser, including usage-object precedence, conditional cache subtraction and additive reasoning/cache writes; live rows, history and Detail share the same total.

On-demand Session Detail uses the shared streaming line reader and CodeBuddy parser. It retains the 16 MiB per-record bound and explicit read-error results; Windows detail resolution follows the async native-to-WSL fallback contract. There is no CodeBuddy VS Code extension-store fallback for WorkBuddy, whose conversations use the transcript roots above.

The shared metadata scanner still skips records above 64 KiB, so oversized user or assistant records can leave turn status stale. This metadata limit is separate from Session Detail's record bound. The desktop credential-encryption boundary described below concerns quota access; it does not prevent reading local session transcripts.

## Limits and quota

`fetchWorkbuddyLimits()` in `src/shared/providers/workbuddy/limits.js` owns the request and the response mapping. Both billing paths post to `/v2/billing/meter/get-user-resource` for personal accounts and `/v2/billing/meter/get-enterprise-user-usage` when an enterprise id is present, under a host the account's region picks. The personal request mirrors the official client's package selection (`ProductCode: p_tcaca`, `Status: [0, 3]`) but aggregates only `Status 0` rows, because the `Status 3` history packages are not part of the spendable balance.

`parsePersonalUsage()` fails closed when any active package carries unusable quota data: a partial aggregate would look plausible while silently omitting a package. An account with no active package stays a configured row with zero resources instead of becoming an error.

### Source selection

The desktop widget may only use the app-owned session. `electronLimitsConfig()` passes `workbuddyDesktopSessionOnly: true`, and `limitsConfigFromSettings()` turns that into empty settings and env for the WorkBuddy lane, so a stale `.env` or legacy settings token cannot silently outrank the app session. The headless agent and CLI keep the `TOKEN_MONITOR_WORKBUDDY_*` fallback; those fields are not a widget setup path.

Within the widget lane, an explicit token still wins when one is actually resolved, and `useLocalApp` requires no token plus an enabled lane plus an injected `workbuddyFetch`. Keep that precedence: the local session is the default, not an override.

## The app-owned session

`src/electron/providers/workbuddy/localAuth.js` reads the session the installed app writes. On Windows it prefers `%LOCALAPPDATA%` and falls back to `%APPDATA%`; on macOS it reads `~/Library/Application Support`. In both cases the path is `CodeBuddyExtension/Data/Public/auth/`, and the client picks the file name: `workbuddy-desktop.info` for the domestic client, `workbuddy-desktop-ai.info` for the international one. Both are read from the same directory, domestic first, because that is the file this reader has always taken and two installed clients must not silently change which account is reported. The two files differ only in that name — both hold the same document, and both seal the credential.

Non-obvious constraints that must survive refactors:

- **The first directory with canonical state decides.** Once the preferred location holds the file or a `.logged-out` marker, the reader does not fall back to a legacy directory, so a stale roaming copy cannot revive a session the user ended.
- **Only the two canonical filenames are trusted.** A sibling file is never read, even when it looks like a session — the backup copies the client leaves beside them carry timestamps and are not among the candidates.
- **Symlinks and oversized files are refused** through `readRegularFileNoFollow` and the 1 MB cap.
- **No credential is stored by Token Monitor.** The access token lives in memory for the duration of one billing request: it is never written to settings, logs, or Token Monitor's own wire, and it leaves the machine only inside the allowlisted HTTPS billing request described under [Request contract](#request-contract).

### Two regions

WorkBuddy ships as two products with separate sign-in realms, and a credential from one is rejected by the other's billing host. The region therefore picks the host, and nothing else:

| Region | Sign-in domain | Billing host | Client file |
| --- | --- | --- | --- |
| Domestic | `www.workbuddy.cn`, `www.codebuddy.cn` | `https://copilot.tencent.com` | `workbuddy-desktop.info` |
| International | `www.workbuddy.ai` | `https://www.codebuddy.ai` | `workbuddy-desktop-ai.info` |

`workbuddyEndpoint()` resolves the host from the account's own `domain`, because that is the one field both readers carry in the clear: the switch file writes it, and the app file writes `auth.domain` unsealed even when the credential beside it is not. The rule is the TLD, anchored to the end of the domain — the product spells the domestic region as both `workbuddy.cn` and `codebuddy.cn`, and a host that merely contains `.ai` is not the international one. An empty domain keeps the domestic host, which is what every caller built before regions existed.

Both hosts sit in `WORKBUDDY_API_HOSTS`, the transport's allowlist. It stays a list of exact hosts rather than a pattern, so it still names every host a token can ever reach. The request headers do not change with the region: both hosts answer to the same `requestHeaders()` output, and the account's `domain` already travels in `X-Domain`.

### Credential encryption

WorkBuddy 5.6.0 and later seal individual credential fields with the at-rest key their own runtime holds, so `auth.accessToken` arrives as a `{$wbEncrypted: 1, envelope: …}` shell instead of a string. Token Monitor cannot open that envelope and must not try to: the key is loaded by the app's own native binding, and no supported surface exposes it.

The reader therefore reports *why* a session is unusable rather than collapsing every failure into "not signed in". `WORKBUDDY_SESSION_READ_REASONS` names the states — `absent`, `unsupported`, `malformed`, `incomplete`, `encrypted`, `expired` — and `getSessionInfo()` carries the non-empty one on a failed read. Only the encrypted case changes the limits outcome, through `WORKBUDDY_SESSION_REASON_ENCRYPTED` in the shared module (the one value both layers agree on) becoming `actionRequired: appSessionEncrypted`.

That distinction is the whole point: an encrypted credential is not a signed-out app, and telling the user to sign in again sends them to a screen that cannot change the outcome. Keep the two apart when adding read states:

| Read reason | Limits outcome | Renderer |
| --- | --- | --- |
| `encrypted` | `notConfigured` + `actionRequired: appSessionEncrypted` | "Encrypted by app" |
| `absent`, `incomplete`, `malformed` | `notConfigured` | "Sign in" |
| `expired` | `unauthorized` | "Sign in again" |

The encrypted row appears only when no account could be read at all. When the switch source below supplies accounts, they are reported normally and the app file's read reason never reaches the renderer.

`expired` is the one state where the read and the request disagree, and it is worth knowing why: `getSessionInfo()` hides an expired session, so the enabled local lane proceeds to a request, and `request()` re-reads the same file and rejects it as `unauthorized`. That rejection is what produces the "Sign in again" prompt.

`normalizeStoredSession()` stays the session-or-null accessor for callers that only want a session; `inspectStoredSession()` returns the `{ session, reason }` pair. Both live in the Electron layer, so the shared limits module receives the reason as plain configuration rather than reaching back into the reader.

### Multiple accounts

Sealing the credential is not the only reason the app file is insufficient: it also describes **one** account — whichever was active — while a user can be signed in to several. A second source is read first for that reason:

1. **`~/.wb-switch/accounts.json`**, written by the third-party [`workbuddy-switch`](https://github.com/changexbc/workbuddy-switch) tool. It holds every account the user has signed in to, already in plaintext, and it is the only source that can hold more than one.
2. **The app's own file**, `workbuddy-desktop.info` or `workbuddy-desktop-ai.info` depending on which client is installed. Read when the switch file yields nothing usable.

The order matters and is not incidental: the app file can only ever describe the account that is currently active, so reading it first would hide every other account a switch install holds. The app file is the fallback, which is what keeps an install without `workbuddy-switch` reading exactly what it read before this existed.

The switch file is a **read of a file the user's own tooling produced**. Token Monitor does not decrypt anything here, does not hold a key, and does not write to that file; it also never asks the user to install anything. `WORKBUDDY_SWITCH_ACCOUNTS_FILE` and `readSwitchSessions()` are the whole surface.

Rules that keep the read honest:

- **The switch accounts win when they exist.** Expired entries are dropped first, so a switch file holding only expired accounts falls through to the app file rather than reporting nothing.
- **An injected `authDirectory` disables the second source.** A caller that supplies its own auth directory supplies the whole environment, so a test never reads the machine's real `~/.wb-switch`.
- **Expired entries are skipped**, not repaired, and a uid appearing twice is kept once: either mistake would publish a wrong balance.
- **A partial entry is dropped.** An entry without both `access_token` and `uid` cannot authenticate, so it is skipped rather than guessed at.

Each resolved account becomes its own limits row on the Limits page. `accountName` is the switch nickname, falling back to the uid, because two personal accounts are otherwise identical on screen. `providerCollapseKey()` in the shared limits module lists `workbuddy` alongside `claude`, `codex`, `alibaba` and the rest, which is what keeps the aggregate from folding the rows into one; its `accountKey` is the account uid, so it is stable across platforms.

### How the two surfaces divide the accounts

The Limits page and Home answer different questions, so they present the accounts differently and share the arithmetic that makes them agree.

**The Limits page unfolds them.** The group header states the combined balance — every account's `remaining` and `limit` summed — and the accounts sit under it behind a fold. `workbuddyCombinedWindow()` is that sum, and it is what the header's percentage and meter are computed from, so the header and the rows under it can never disagree. WorkBuddy opens folded; the dock card supplies no fold state and so keeps drawing every row.

**Home states one row per provider.** Home's own grouping is one row per provider record, and WorkBuddy answers once per account, so `collapseWorkbuddyAccounts()` rewrites the WorkBuddy entries into one before Home groups them. It rewrites only those entries and leaves every other provider in place; a version that replaced the whole array handed one provider's numbers to another provider's row.

Two details that are easy to get wrong:

- **The collapsed window carries `preferPercent: true`.** A credits window normally states its balance, because a top-up has no denominator and an amount is all it can state. WorkBuddy's accounts each report a real cycle denominator, so the collapsed row has one too and states a percentage — the way Qoder's row already reads. The marker is explicit rather than inferred from the window's shape, and `homeOverview.js` passes it through when it copies a window onto a Home row.
- **A sum that cannot be computed is not published.** Fewer than two accounts, or any account that reported no denominator, and the entries are returned unchanged: separate honest rows are better than one row stating a total it left an account out of. The group header follows the same rule, so a group that cannot be summed states its count and stays open.

**This is the only provider that resolves several accounts this way.** Every other multi-account provider reads its own credential store or settings. Applying the same fallback to another provider means repeating this section for it, not generalising the reader.

## Request contract

`createWorkbuddyLocalAuth().request()` injects authentication only after `isAllowedWorkbuddyApiUrl()` has matched the exact https host, path and method with no credentials, port, query or fragment. It sets `redirect: 'error'` so the token can never follow a redirect, strips caller-supplied authentication headers, and re-reads the session after the response to reject a mid-request account switch. Preserve all four when touching the transport: they are the reason the provider is allowed to handle an app-owned credential at all.

## Change map

| Concern | Primary files |
| --- | --- |
| Transcript metadata and roots | `src/shared/providers/workbuddy/sessionMetadata.js`, shared CodeBuddy transcript readers |
| Transcript discovery and streaming Detail | `src/shared/sessionFiles.js`, `src/shared/sessionDetail.js`, `src/shared/sessionDetailResolver.js` |
| App session reading, encryption detection, read reasons, account resolution | `src/electron/providers/workbuddy/localAuth.js` |
| Billing request and response mapping | `src/shared/providers/workbuddy/limits.js` |
| Widget lane configuration and reason plumbing | `src/electron/main.js`, `src/electron/runtimeConfig.js` |
| Multi-account grouping and per-account fold | `src/electron/renderer/limits/windowsView.js`, `src/electron/renderer/app.js` |
| Home's one row per provider | `src/electron/renderer/homeOverview.js` |
| Action hint bounds | `src/shared/limits/core.js`, generated `worker/src/shared/limits/core.js` |
| Status label and localized strings | `src/electron/renderer/limits/providerPresentation.js`, `src/electron/renderer/i18n.js` |
| Wire contract | `docs/API.md` |

## Verification checklist

- both transcript roots, custom-title precedence and older ungrouped usage records;
- streamed Session Detail, oversized-record errors and async WSL fallback;
- personal and enterprise billing mapping, including the unlimited enterprise plan;
- an empty active-package list staying visible as configured;
- a sealed credential reporting `encrypted` rather than a missing sign-in;
- the switch accounts winning over the app file, and the app file answering only
  when the switch file has nothing usable;
- the international host and file name, and the domestic pair still winning when
  both clients are installed;
- one limits row per resolved account, and a per-account refresh asking only for
  the account it names;
- the collapsed Home row summing the accounts, and a sum it cannot compute
  leaving the accounts as separate rows;
- the read reasons for absent, malformed, oversized, incomplete and expired sessions;
- the widget lane refusing a legacy `.env` or settings token;
- an explicit token outranking the local session;
- the allowlisted endpoint, header stripping, and mid-request session switch rejection.

Run focused tests while iterating, then `npm run sync:worker` when `src/shared/limits/core.js` changed, `npm run verify`, and `git diff --check`.

For session changes, run `node --test tests/shared/workbuddySessionMetadata.test.js tests/shared/sessionDetail.codebuddy.test.js tests/shared/sessionDetailStreaming.test.js tests/shared/sessionDetailResolver.test.js`.
