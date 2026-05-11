-- Server-derived signals for "is this an HWC customer's connection?" Q.
--
-- request_ip_hash: peppered SHA-256 of the HTTP request's source IP, captured
-- at POST /v1/certifications. The STB also reports a `network.publicIp`
-- discovered via STUN/ipify; the request-observed IP is more trustworthy
-- (no STB-side spoofing surface) and is what the dashboard search prefers.
--
-- isp_asn / isp_name: looked up at ingest via Team Cymru's `origin.asn.cymru.com`
-- DNS service. Populated when the lookup succeeds; left null on transient
-- failure. The dashboard surfaces these as "ISP: Hotwire Communications
-- (AS7029)" badges. Future filter: tier by ASN for "off-net" reports.

alter table certifications
    add column request_ip_hash text,
    add column isp_asn         int,
    add column isp_name        text;

create index certifications_request_ip_hash_idx
    on certifications (request_ip_hash)
    where request_ip_hash is not null;

create index certifications_isp_asn_idx
    on certifications (isp_asn, completed_at desc)
    where isp_asn is not null;
