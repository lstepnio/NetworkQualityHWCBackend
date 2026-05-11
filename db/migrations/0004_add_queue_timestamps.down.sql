drop index if exists certifications_completed_at_idx;
alter table certifications drop column submitted_at;
alter table certifications drop column enqueued_at;
