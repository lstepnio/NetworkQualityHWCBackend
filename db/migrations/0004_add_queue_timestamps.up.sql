-- Two optional client-supplied timestamps from the publish queue,
-- documented in fisiontv-cert-contract v1.1.0:
--   enqueued_at  — when the row first hit the local PublishQueue
--   submitted_at — when this POST attempt left the device (refreshed on retry)
--
-- Both nullable: payloads from clients on older builds will not carry them
-- and we want to ingest those without failure. The dashboard and analytics
-- treat NULL as "older client; fall back to received_at".
alter table certifications
    add column enqueued_at  timestamptz,
    add column submitted_at timestamptz;

-- The lists + per-device feeds now sort by completed_at (when the cert
-- actually ran on the STB) instead of received_at (when the API got the
-- POST). Composite indexes covering (device_id|hsn|achieved_tier) already
-- key on completed_at desc; add a single-column index so unfiltered list
-- queries don't need a sort.
create index certifications_completed_at_idx
    on certifications (completed_at desc);
