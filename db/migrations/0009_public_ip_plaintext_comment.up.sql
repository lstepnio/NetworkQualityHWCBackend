-- Update the column-level note on `certifications.public_ip` to match
-- the new policy: future inserts are plaintext (matches what the
-- payload's network.publicIp now carries since pii.piiPaths dropped
-- the redaction entry). Existing rows that were stored under the
-- previous hashed-policy keep their SHA-256 strings — one-way hash, no
-- backfill possible. The admin filter now does plaintext exact-match
-- and won't return those legacy rows.
--
-- No data change; just the column comment. Down migration restores
-- the prior comment for reversibility audit.

comment on column certifications.public_ip is
  'Network public IP (plaintext for rows ingested >=v0.7.11; legacy rows carry the SHA-256+pepper hash from the pre-policy-change era). Indexed for support search.';
