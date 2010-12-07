-- If you are using table_log, run this as the user that owns the log tables
SELECT public.table_log_init(5,'firewalls');

ALTER TABLE real_interfaces_log RENAME COLUMN firewall_id TO old_firewall_id;

ALTER TABLE real_interfaces_log RENAME COLUMN temp_fwid TO firewall_id;


