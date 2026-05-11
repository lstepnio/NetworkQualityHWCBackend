-- Drops the request_ip_hash + isp_asn + isp_name columns added in 0006.
--
-- Reason: the ASN tagging via Cymru DNS was added for an on-net/off-net
-- distinction that turned out to be premature for MVP. Removing the
-- columns now keeps the schema honest and avoids storing data the rest
-- of the system doesn't consume. If we revisit, 0006's logic is preserved
-- in git history at commit 48acf40.

drop index if exists certifications_isp_asn_idx;
drop index if exists certifications_request_ip_hash_idx;
alter table certifications drop column if exists isp_name;
alter table certifications drop column if exists isp_asn;
alter table certifications drop column if exists request_ip_hash;
