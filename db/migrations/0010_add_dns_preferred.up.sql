-- Per-row DNS-policy verdict, denormalized out of payload.dnsAssessment
-- for efficient list-view queries and operator filtering at fleet scale.
--
-- Trichotomy:
--   NULL  — no policy was in effect when this row was ingested, OR a
--           pre-v2.3.0 client that doesn't emit dnsAssessment.
--   FALSE — at least one of the STB's actual dnsServers was not in the
--           configured preferredServers list. Dashboard flags this.
--   TRUE  — every actual server was preferred, OR the actual list was
--           empty (vacuously preferred per contract SPEC §6.1).

alter table certifications add column dns_preferred boolean;

-- Backfill from JSONB for rows that already carry an assessment from
-- the contract v2.3.0 / android v0.9.15 deploy window. Rows ingested
-- under earlier code don't have `dnsAssessment` at all; they stay NULL.
update certifications
   set dns_preferred = (payload->'dnsAssessment'->>'allPreferred')::boolean
 where payload ? 'dnsAssessment'
   and payload->'dnsAssessment' ? 'allPreferred';

-- Partial index supports the operator's "show flagged only" filter
-- (the unusual state) without bloating the index with the
-- preferred-majority. Indexed on received_at desc to match the list
-- view's default sort.
create index certifications_dns_flagged_idx
    on certifications (received_at desc)
 where dns_preferred = false;
