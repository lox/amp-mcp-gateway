# ReviewBench submission

[ReviewBench](https://review-bench.ai/) scores reviewers on 219 frozen public PRs.
A vendor supplies a `linux/amd64` image on `ghcr.io`, pinned by digest, that
follows its [agent contract](https://github.com/review-bench/ReviewBench/blob/main/AGENT_CONTRACT.md):
one container per PR, checkout at `/work/repo`, findings JSON at `$RB_OUT`, and
egress only to declared hosts. There is no GitHub App or API access.

[`cmd/reviewbench-agent`](../cmd/reviewbench-agent) runs the same review as the
gateway: the `reviewbot-v1` mode from [pinned-models.js](reviews/pinned-models.js),
the embedded methodology and severity rubric, `ParseResult` validation and
changed-line anchoring. Differences from production: the Amp CLI runs locally in
the container rather than in an orb (there is nothing to clone from), and the
prompt says the checkout is already at head. It fails the PR unless the thread
records plugin mode `reviewbot-v1` (locally run plugin modes report their base
mode, `medium`, in the stream, so the stream's label is not checked). Each finding's message is
`[severity] title: message Suggested fix: suggestion`.

## Build and try

```sh
docker build --platform linux/amd64 -f cmd/reviewbench-agent/Dockerfile -t amp-review-bench .
# from a ReviewBench clone; spends Amp credits
scripts/try-agent.sh amp-review-bench --pr 0 -e AMP_API_KEY
```

The key must belong to an account that may run `reviewbot-v1` threads. Threads
are private and archived after each review.

To score locally, follow ReviewBench's
[offline evaluation](https://github.com/review-bench/ReviewBench/blob/main/docs/OFFLINE_EVAL.md)
with judge `claude-sonnet-5`. Its `models.json` example also needs
`"compat": { "forceAdaptiveThinking": true }` and `"maxTokens": 8192` (as in its
Harbor export); otherwise Anthropic rejects every judge call and the matcher
reports invalid JSON. Use `--concurrency 1` unless the Anthropic key allows more
concurrent connections.

## Register

Push the image to `ghcr.io` and register it at <https://review-bench.ai/submit/>
(GitHub sign-in). The portal opens the manifest PR; a maintainer merging it is
the approval. The package is public, so ReviewBench pulls it anonymously.
Then enter `AMP_API_KEY` in the portal's credentials form. Expected manifest:

```json
{
  "name": "amp-review",
  "display_name": "Amp Review",
  "provider": "Amp",
  "image": "ghcr.io/lox/amp-mcp-gateway-reviewbench@sha256:<digest>",
  "image_visibility": "public",
  "configuration": [{ "key": "mode", "value": "reviewbot-v1" }],
  "secrets": { "env": ["AMP_API_KEY"] },
  "model_api_url": "https://ampcode.com",
  "contacts": ["lox"]
}
```

A portal test run covers the 25 test PRs; a final run is three rounds of all 219
(about 680 reviews). If the first PR fails on a refused host, add that host to
`egress`.
