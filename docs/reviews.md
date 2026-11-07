# Reviews integration

Reviews runs inside the Go gateway, with its own encrypted SQLite ledger in each
existing account database. It is not an MCP tool or an organisation-wide account.
The browser owner approves the repositories that may spend review credits.
The normal MCP operation-approval queue is not involved.

## Ownership and execution authority

Choose an individual Amp user to administer each integration. Their existing Amp
login controls configuration, import, cancellation and manual reruns. An account
can administer several Apps; other gateway users cannot see or operate them.
There is no implicit organisation membership, shared admin role or delegation.

Use **separate private GitHub Apps** for `lox` and `sporevm`. The existing
[amp-reviewbot App](https://github.com/apps/amp-reviewbot) stays private to `lox`.
Each configuration binds one App ID, installation ID and approved owner. Those
identities cannot be reassigned under the same integration ID. A webhook signature
only authenticates the App: installation, owner, repository approval and an exact
project mapping must also match. The installation API verifies the installed App
and owner before issuing a token restricted to that repository.

The gateway's retained browser OAuth grant is **not an execution credential**.
Supply a separate Amp API key, from the account authorised to spend credits and
launch orbs in every mapped project. It can be a different execution account from
the gateway administrator; that is an explicit delegation by the administrator.
Use separate keys/accounts for different organisational trust boundaries. The
gateway does not prove the key's owner or introspect its scopes before launch.

All configuration and credentials have one source of truth: the encrypted
`reviews/config/v1` record in the owner's database. Job snapshots contain settings,
identity bindings and PR context, never keys. No reviews environment-variable
configuration or second management app exists. Blank secret fields retain stored
values; saving changed settings fences queued work and requests cancellation of
active work. Drain cleanup before rotating an execution key: old jobs never borrow
the replacement key to archive threads or read usage.

## Configure a review integration

1. Install a private GitHub App owned by the relevant account/organisation on the
   selected repositories. Required repository permissions: **Checks: read/write**,
   **Contents: read**, **Pull requests: read** (plus GitHub's mandatory metadata
   read). Subscribe to **Pull request** and **Check run** events.
2. In **Integrations → Reviews**, choose **Add review integration**. The overview
   shows existing integrations and review history; **Configure** opens an existing
   integration. In the setup form, create a paused configuration with its App ID,
   installation ID, PEM RSA private key, webhook secret and separate Amp execution
   API key. Use fake credentials only in demo mode; demo never runs review workers.
3. Approve specific `owner/repo` names, or explicitly approve the entire owner.
   Either choice still requires an exact repository → Amp `namespace/project`
   mapping. The mapped project must contain that repository, grant the execution
   account access and allow fetching the exact PR commits, including fork heads.
4. Install [pinned-models.js](reviews/pinned-models.js) in the execution account's
   **User or Workspace Plugins repository** (once, not additionally in each
   project). Existing installations of the same file can be retained. It registers
   `reviewbot-v1` with main model `openai/gpt-5.6-sol`, medium reasoning and the same
   Oracle model at high reasoning. The evaluation mode remains available but the
   gateway does not run evaluations. Plugin provisioning is a separate operator
   step; this feature never changes global plugins.
5. Copy the account/App-specific webhook URL displayed after saving into the App
   settings. A signed ping verifies delivery even while paused, but does not
   authorise repositories. Select severity threshold, private/workspace thread
   visibility and a 5–120 minute timeout, then enable intake and execution.

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
  ten Apps per account. Apps in one account share its slot. No replicas: the
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
   change `lox-amp-reviewbot` yet. Configure both Apps, mappings and execution
   credentials in the owning gateway account(s), paused.
2. Disable the old App's webhook delivery temporarily, keeping the source worker
   available to drain existing jobs and finish archival/usage collection. Observe
   `review_jobs` until no queued/running jobs remain. Investigate unresolved work
   rather than rewriting it as completed. Then stop the old Fly service so its
   reconciliation cannot create further work. Retain its database and rollback
   configuration. Record the start of the delivery gap.
3. Export using `psql -XAt -f docs/reviews-export.sql > reviews.jsonl` against the
   **drained source**. The export contains private PR text: protect it like a
   database backup, never commit it. Split large exports on line boundaries into
   files of at most 32 MiB / 10,000 records.
4. Open the paused destination App's **Import amp-reviewbot history** form. Confirm
   the execution key belongs to the original execution account and upload each
   JSONL file. The importer rejects active/foreign-installation/unapproved records,
   preserves checks, frozen context, results, thread IDs and usage, and never queues
   historical work. It is resumable: a partial failure reports the count; importing
   again skips known deliveries. Map/approve every repository represented in the
   export. Numeric old check IDs resolve only within this authenticated App.
   Pre-context legacy jobs remain visible but cannot be rerun with invented text.
5. Compare imported counts and sampled SHAs, check IDs, findings and costs with the
   source. Point the App webhook at the gateway's displayed URL, enable this App,
   re-enable GitHub delivery and redeliver events from the gap as needed. Do **not**
   run both workers. Do the same for the new `sporevm` App (no legacy import needed).
6. On an approved disposable PR, verify signed delivery, a real orb using
   `reviewbot-v1`, linked check/annotations, severity conclusion, rerun, cancellation,
   archival and usage. Check both organisations and denied/unmapped repositories.
   Only then retire the old deployment. No paid/live review or production cutover
   is implied by the local fake-provider tests.

Rollback: pause gateway intake, resolve and stop outstanding Amp executions, drain
cleanup, then stop its review worker before restoring old webhook routing and
starting the old service. Keep the gateway ledger for reviews created since cutover;
there is no reverse importer. Do not restore an old database snapshot over newer
gateway operations. Old numeric check reruns can use the old service; checks created
by this gateway need its history/runner. Retain both backups until that distinction
no longer matters.
