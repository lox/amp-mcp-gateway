# Reviews integration

Reviews runs inside the Go gateway, with its own encrypted SQLite ledger in each
existing account database. It is not an MCP tool or an organisation-wide account.
The browser owner approves the repositories that may spend review credits.
The normal MCP operation-approval queue is not involved.

## Ownership and execution authority

Choose an individual Amp user to administer each integration. Their existing Amp
login controls configuration, cancellation and manual reruns. An account
can administer several Apps; other gateway users cannot see or operate them.
There is no implicit organisation membership, shared admin role or delegation.

Use **one public GitHub App**, with separate explicitly approved installations for
`lox` and `sporevm`. Private Apps still work, but can only be installed on their
owning account. Each integration stores one App ID, private key, webhook secret
and webhook URL. Its installations select a named execution credential and contain
repository/project rows. Enabling a row is the repository approval: there is no
second allowlist, owner-wide approval or automatic enrolment.

A webhook signature authenticates the App, not permission to spend credits.
Intake additionally matches the approved installation, repository name and numeric
repository ID before recording work. GitHub verifies new installation owner IDs
and repository IDs on save; subsequent execution verifies the App/installation/
owner again and uses a token restricted to that repository. Repository recreation
or transfer does not inherit approval. Unknown installations and repositories are
rejected without creating jobs. All installations of an App use its one webhook
URL; the account segment routes to an isolated gateway account, never grants access.

The gateway's retained browser OAuth grant is **not an execution credential**.
Use an [Amp service account](https://ampcode.com/docs/collaborate/workspaces#service-accounts)
API key, authorised to launch orbs in the mapped projects. A workspace admin creates
it under **Workspace Settings → Service Accounts → Generate an API Key**. This
requires Enterprise, or Team with a payment method. Threads belong to the service
account and usage is billed to its workspace. Connect its GitHub access separately
so the orb can clone the mapped repositories; gateway App credentials never supply
that access. Ensure the execution account loads the pinned review-mode plugin.

Store the key once under a name such as `reviews-bot`; each installation explicitly
selects it. Both installations can share one credential, or use separate service
accounts for different trust/billing boundaries. Personal Amp API keys also work.
The gateway does not prove the key's owner or introspect its scopes before launch.
Keep **Members Can Drive Threads** off unless workspace members should be able to
use the account's connected access. When enabled, new service-account orb threads
are workspace-shared and multiplayer; do not assume the gateway's visibility
setting overrides Amp workspace policy.

All configuration and credentials have one source of truth: the encrypted
`reviews/config/v1` record in the owner's database (payload version 2). App keys
live on integrations; execution keys live in the account's named credential map,
never duplicated per installation. Job snapshots contain settings, identity and
execution-credential bindings and PR context, never keys. No reviews environment
configuration or second management app exists. Blank secret fields retain values.
Settings default at integration level, with optional repository overrides.
Changes fence only affected queued/running jobs; a shared key change fences all
jobs using that key. Committed revocation does not depend on the browser remaining
connected. GitHub identity verification does not hold the execution mutex; a
concurrent config save rejects the stale candidate rather than overwriting it.
Pausing/removing already verified configuration needs no GitHub request.

Removing an installation or repository retains history and cleanup access to its
original named execution key. Drain cleanup before rotating that key: old jobs
never borrow a replacement to archive threads or read usage. Saved execution
credentials are retained even when no installation currently selects them.

## Configure a review integration

1. Install the GitHub App on selected repositories. Required repository permissions: **Checks: read/write**,
   **Contents: read**, **Pull requests: read** (plus GitHub's mandatory metadata
   read). Subscribe to **Pull request** and **Check run** events.
2. In **Integrations → Reviews**, choose **Add review integration**. The overview
   shows existing integrations and review history; **Configure** opens an existing
   integration. Store the App ID, PEM private key and webhook secret once. Add a
   named Amp execution credential, then installation sections with their owner,
   installation ID and chosen credential. Use fake credentials only in demo mode;
   demo saves unverified paused drafts and never calls GitHub or Amp.
3. Add individual `owner/repo` → Amp `namespace/project` rows, then explicitly
   enable the desired rows. New rows start disabled. The mapped project must contain that repository, grant the execution
   account access and allow fetching the exact PR commits, including fork heads.
4. Install [pinned-models.js](reviews/pinned-models.js) in the execution account's
   **User or Workspace Plugins repository** (once, not additionally in each
   project). Replace the legacy all-purpose plugin with this production-only
   version: it removes the evaluation judge and message-triggered shell setup hook.
   Keep evaluation tooling separate from production execution accounts. It registers
   `reviewbot-v1` with main model `openai/gpt-5.6-sol`, medium reasoning and the same
   Oracle model at high reasoning. Plugin provisioning is a separate operator step;
   this feature never changes global plugins.
5. Copy the account/App-specific webhook URL displayed after saving into the App
   settings. A signed ping verifies delivery even while paused, but does not
   authorise repositories. Select default severity threshold, private/workspace
   visibility and a 5–120 minute timeout, then enable the integration. Repository
   rows may override these defaults. Do not make the live legacy App public until
   the authorized gateway intake has been deployed and verified.

Enabling also scans **all approved, mapped repositories**, not only repositories
already seen in webhooks. Review project setup runs before the prompt: keep setup,
plugins and project secrets trusted and minimal. The prompt's instruction to treat
PR content as data is not a sandbox against malicious repository code. GitHub App
keys/tokens are never passed to the CLI or review orb. Amp/project access comes
from the execution account and project, not a GitHub credential injected by the
gateway.

The Docker image includes a pinned native Amp CLI; Node is only a build tool, not
a review service runtime. For non-container deployment install the version pinned
in `Dockerfile` on the service PATH. The Go executor uses the official CLI's
`--execute --stream-json --orb-execute` protocol, as the old Amp SDK did. Each call
has an isolated temporary HOME and a minimal environment. It rejects a stream
whose mode is not `reviewbot-v1`; this verifies the mode key, **not cryptographic
attestation of its model definition**. Keep the execution account's plugin under
operator control.

## Lifecycle and operational limits

- Signed `opened`, `reopened`, `synchronize` and `ready_for_review` events enqueue
  non-draft PRs. `closed` and `converted_to_draft` are accepted; the live GitHub
  state check cancels closed/draft work, so delayed events cannot cancel a reopened
  PR. Other actions do not launch reviews. Delivery IDs deduplicate; an active or unknown head cannot
  be enqueued again. Explicit reruns use stored base/head SHAs and PR text, while
  reauthorising against current mappings/settings. Superseded heads do not execute.
- Persist and atomically claim before dispatch. One active review per gateway
  account, four host slots with FIFO waiters, at most 100 queued/running jobs and
  ten Apps per account. Each App supports twenty installations, each with at most
  one hundred repository rows; an account stores at most twenty execution keys.
  Apps and installations in one account share its slot. No replicas: the
  gateway's existing process/volume lock remains required.
- Live PR state is checked before launch, every ten seconds during execution and
  before publication. Exact base/head comparisons select changed right-side lines.
  As in the source service, advancing the base does not invalidate a frozen review
  or trigger another paid review of the same head. A new head supersedes it.
  Missing patches cannot produce annotations; comparisons at GitHub's 300-file
  limit fail explicitly. Validated JSON permits at most 20 findings; unanchored
  findings are omitted before calculating the conclusion. A blocking severity
  yields `failure`, advisory findings `neutral`, none `success`. If findings are
  omitted, the free-form summary is replaced with an omission notice, matching
  the source check publisher so discarded claims do not remain in the summary.
  If the publication checkpoint fails, closing the check sends only a failure or
  cancellation message, never the findings; any computed result stays in history.
- Safe GitHub reads retry at most three times. Check creation/publication never
  automatically replays an ambiguous write. Definite HTTP rejections (such as
  401/403/422) fail the job without pausing the account; timeouts, transport errors
  and server errors remain ambiguous. Only an explicit terminal transient
  Amp result can continue the known thread, at most twice within the job timeout.
  Malformed/truncated streams or uncertain launches remain `unknown`. Cancellation
  signals the CLI; if remote cancellation cannot be confirmed, the outcome also
  remains unknown. Any unknown outcome pauses new executions for that account,
  without occupying a host execution slot; other accounts keep running. Inspect
  GitHub and stop the external execution before acknowledging a rerun, or choose
  **Resolve without re-running** (also available when paused). Resolve records the
  owner's acknowledgement; it does not stop a remote orb or repair a GitHub check.
  GitHub reruns cannot acknowledge unknown outcomes.
- Restart marks interrupted work unknown. Recovery can requeue pre-dispatch work,
  discover an already-created check, or confirm a completed publication by its
  App, external ID, SHA and conclusion. It never guesses that an uncertain launch
  failed. Persistently unknown jobs need the owner; their threads are not silently
  archived. Check creation recovery is bounded to 1,000 checks for the commit.
- A failed finalization database write stops the worker and propagates through
  the gateway's supervised process. After storage is healthy, restart recovery
  handles the last durable checkpoint; the worker never silently leaves a review
  running while continuing to dispatch new work.
- Reconciliation runs every five minutes, at most 1,000 open PRs per mapped
  repository and ten new reviews per pass. It considers PRs updated between five
  minutes and seven days ago, and never repeats a known head. Older/missing events
  require a GitHub redelivery or a new PR event. Dependency errors leave the next
  pass to retry reads rather than manufacturing a successful review.
- Cleanup processes up to twenty terminal records per minute. Successful archival
  and usage capture are persisted separately; failed archival retries on later
  passes. Unavailable usage is recorded explicitly, not as zero. Amp credits and
  provider list-price estimates are separate. The UI shows the latest 100 reviews
  plus the next unresolved outcome when older,
  linked checks/threads, frozen SHAs, findings, stage and errors; all history remains
  stored. There is no retention deletion, historical pagination or spend budget yet.

## Migrate lox-amp-reviewbot without dual execution

The behavioural source is `lox/amp-reviewbot` at
[`d2cbd0f`](https://github.com/lox/amp-reviewbot/commit/d2cbd0f04a6fd103c66e0ec95b94fb8d47274e90).
Its review methodology and mode plugin are bundled with their MIT licence. The
gateway intentionally replaces its replay-prone retries with the stricter unknown
outcome rules above. The evaluation harness is not part of this service migration.

These are **operator steps requiring approval**, not automatic deployment actions:

1. Back up the gateway's account databases/encryption material and the source
   Postgres database. Deploy this version with Reviews unconfigured/paused. Do not
   change `lox-amp-reviewbot` yet. Configure the existing App, its `lox` installation,
   repository rows and execution credential in your gateway account, paused.
   Keep the App private during this stage.
2. Disable the old App's webhook delivery temporarily, keeping the source worker
   available to drain existing jobs and finish archival/usage collection. Observe
   `review_jobs` until no queued/running jobs remain. Investigate unresolved work
   rather than rewriting it as completed. Then stop the old Fly service so its
   reconciliation cannot create further work. Retain its database and rollback
   configuration. Record the start of the delivery gap.
3. Export using `psql -XAt -f docs/reviews-export.sql > reviews.jsonl` against the
   **drained source**. The export contains private PR text: protect it like a
   database backup, never commit it.
4. Drain and stop the gateway too, then run the [offline import tool](#one-off-history-import)
   against its existing account database. Confirm the configured execution key
   belongs to the original execution account; map/approve every repository in the
   export. There is no browser upload or HTTP import endpoint.
5. Compare imported counts and sampled SHAs, check IDs, findings and costs with the
   source. Restart the gateway. Point the App webhook at the gateway's displayed URL, enable this App,
   re-enable GitHub delivery and redeliver events from the gap as needed. Do **not**
   run both workers. Only after verifying authorized and denied intake, approve
   making the App public and installing it on `sporevm`. Add that installation to
   the same Reviews integration and explicitly enable its repository rows (no
   legacy import needed). Unapproved public installations must never execute.
6. On an approved disposable PR, verify signed delivery, a real orb using
   `reviewbot-v1`, linked check/annotations, severity conclusion, rerun, cancellation,
   archival and usage. Check both organisations and denied/unmapped repositories.
   Only then retire the old deployment. No paid/live review or production cutover
   is implied by the local fake-provider tests.

### One-off history import

This is a cutover script, not a runtime feature. Build it from this checkout for
the maintenance host's OS/architecture:

```sh
mise exec -- go build -tags=reviewimport -o /tmp/import-reviews ./docs/reviews/import.go
```

For the existing single-user deployment, use the primary `Database` path and its
existing `GATEWAY_ENCRYPTION_KEY` environment variable. Do not put the key in
command-line arguments. With **both services stopped**, run on the maintenance
host that has the database and protected export:

```sh
/tmp/import-reviews -database /data/gateway.db -app lox-reviews < reviews.jsonl
```

The tool takes the gateway's database lock and reads its saved account identity
and paused App configuration; it does not start workers or contact GitHub/Amp.
It rejects active, foreign-installation and unapproved records, preserves checks,
frozen context, results, thread IDs and usage, and never queues historical work.
A partial failure reports the count; rerunning the export skips known deliveries.
Raw legacy error text is deliberately left in the protected source backup rather
than copied into the UI, since provider errors may contain credentials.
Numeric old check IDs resolve only within their authenticated App. Pre-context
legacy jobs remain visible but cannot be rerun with invented text.

The importer and its tests are excluded from normal gateway builds. Before use,
run `mise exec -- go test -tags=reviewimport ./internal/reviews -run TestLegacyOfflineImport`.
No production-sized export has been rehearsed yet; allow for offline import time.

### Existing gateway configuration

The previous one-installation configuration loads as **paused** installation drafts
under the same integration IDs and webhook URLs. Only previously approved mappings
are retained; history and original cleanup keys remain accessible. Save each draft
to verify numeric GitHub identities before re-enabling it. New work never assumes
that an old repository name still identifies the same repository. Existing frozen
jobs with old policy bindings are not silently reauthorized.

For an existing two-private-App setup, keep the `lox` integration and its history.
Drain and pause the separate `sporevm` integration before switching repositories
to a new installation of the public App. Do not enable both integrations for the
same repositories during cutover. Retain the old paused integration for historical
check ownership; history is not reassigned between Apps.

### Rollback

Rollback: pause gateway intake, resolve and stop outstanding Amp executions, drain
cleanup, then stop its review worker before restoring old webhook routing and
starting the old service. Keep the gateway ledger for reviews created since cutover;
there is no reverse importer. Do not restore an old database snapshot over newer
gateway operations. Old numeric check reruns can use the old service; checks created
by this gateway need its history/runner. Retain both backups until that distinction
no longer matters.
