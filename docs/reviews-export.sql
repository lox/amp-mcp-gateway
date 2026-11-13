-- Run against the drained amp-reviewbot database, not the gateway database.
-- psql -XAt -f docs/reviews-export.sql > reviews.jsonl
-- Contains private PR content. Protect the output as a database backup.
SELECT jsonb_build_object(
  'job', to_jsonb(j),
  'threads', COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY t.created_at)
                      FROM review_threads t WHERE t.job_id = j.id), '[]'::jsonb),
  'result', (SELECT to_jsonb(r) FROM review_results r WHERE r.job_id = j.id)
)
FROM review_jobs j ORDER BY j.id;
