-- Drop the foreign key on certifications.config_version.
--
-- SPEC §6.2 says configVersion is "opaque (string). The app round-trips it
-- in the result POST so support can correlate which config a given run used."
-- The FK from §7's storage shape over-tightens that semantic: any client
-- running its bundled defaults — or any historical config the operator has
-- since pruned — will 500 on POST. The column itself stays for correlation;
-- only the constraint is removed.
alter table certifications
    drop constraint certifications_config_version_fkey;
