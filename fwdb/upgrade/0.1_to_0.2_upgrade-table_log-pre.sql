-- If you are using table_log, run this as the user that owns the log tables
ALTER TABLE real_interfaces_log ADD COLUMN temp_fwid integer;

ALTER TABLE real_interfaces_log ALTER COLUMN firewall_id DROP NOT NULL;

