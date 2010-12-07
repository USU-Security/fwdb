-- run with --single-transaction

DROP VIEW iptables;

CREATE TABLE firewalls (
	id serial primary key,
	name varchar UNIQUE NOT NULL
);

ALTER TABLE real_interfaces ADD COLUMN temp_fwid integer REFERENCES firewalls(id);

INSERT INTO firewalls(name) (SELECT DISTINCT firewall_id FROM real_interfaces);

UPDATE real_interfaces SET temp_fwid=(SELECT firewalls.id FROM firewalls WHERE name=real_interfaces.firewall_id);

ALTER TABLE real_interfaces ALTER COLUMN temp_fwid SET NOT NULL;

ALTER TABLE real_interfaces DROP COLUMN firewall_id;

ALTER TABLE real_interfaces RENAME COLUMN temp_fwid TO firewall_id;

