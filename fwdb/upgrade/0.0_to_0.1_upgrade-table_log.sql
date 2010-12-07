-- If you are using table_log, run this as the user that owns the log tables
ALTER TABLE hosts_log ADD COLUMN is_group BOOLEAN DEFAULT FALSE;

SELECT public.table_log_init(5,'hosts_to_groups');

ALTER TABLE hosts_log ALTER COLUMN host DROP NOT NULL;

