-- run with --single-transaction
ALTER TABLE hosts ADD COLUMN is_group BOOLEAN DEFAULT FALSE;

ALTER TABLE hosts DROP CONSTRAINT hosts_check;
ALTER TABLE hosts ADD CHECK ( ( (host IS NOT NULL AND host_end IS NULL )
			OR ( host IS NOT NULL AND masklen(host) = 32 AND masklen(host_end) = 32
				 AND host < host_end ) AND is_group = FALSE )
			OR ( host IS NULL AND host_end IS NULL AND is_group IS TRUE) );

CREATE UNIQUE INDEX hosts_host_key_2 ON hosts(host) WHERE host_end IS NULL;

CREATE FUNCTION disallow_is_group_change () RETURNS trigger AS '
  BEGIN
       IF OLD.is_group != NEW.is_group THEN
               RAISE EXCEPTION ''is_group may not be changed'';
       END IF;
       RETURN NEW;
  END;
' LANGUAGE 'plpgsql';

CREATE TRIGGER disallow_is_group_change_on_hosts
       BEFORE UPDATE
               ON hosts FOR EACH ROW
       EXECUTE PROCEDURE disallow_is_group_change();

CREATE TABLE hosts_to_groups (
       id serial primary key,
       -- we want gid == hid if this is an individual host, see trigger below
       gid integer references hosts(id) NOT NULL,
       hid integer references hosts(id) NOT NULL,
       UNIQUE (hid,gid)
);

CREATE FUNCTION check_host_to_group () RETURNS trigger AS '
  DECLARE
       gid_is_group BOOLEAN;
       hid_is_group BOOLEAN;
  BEGIN
       SELECT INTO gid_is_group is_group FROM hosts WHERE hosts.id = NEW.gid;
       SELECT INTO hid_is_group is_group FROM hosts WHERE hosts.id = NEW.hid;

       IF gid_is_group != TRUE AND NEW.gid != NEW.hid THEN
               RAISE EXCEPTION ''Cannot add to a host.'';
       END IF;

       IF hid_is_group != FALSE THEN
               RAISE EXCEPTION ''Cannot add a group to a group.'';
       END IF;

       RETURN NEW;
  END;
' LANGUAGE 'plpgsql';

CREATE TRIGGER check_host_to_group_vals
       BEFORE INSERT OR UPDATE
               ON hosts_to_groups FOR EACH ROW
       EXECUTE PROCEDURE check_host_to_group();

INSERT INTO hosts_to_groups(gid,hid) (SELECT id,id FROM hosts);

CREATE FUNCTION add_host_to_own_group () RETURNS trigger AS '
  BEGIN
       IF NEW.is_group = FALSE THEN
               INSERT INTO hosts_to_groups(gid, hid) VALUES (NEW.id, NEW.id);
       END IF;
       RETURN NULL;
  END;
' LANGUAGE 'plpgsql';

CREATE TRIGGER fix_hosts_to_groups
       AFTER INSERT
               ON hosts FOR EACH ROW
       EXECUTE PROCEDURE add_host_to_own_group();


DROP VIEW iptables;
CREATE VIEW iptables AS (
	SELECT rules.id, rules.ord, tbl.name AS tbl, chain.name AS chain, if_in.name AS if_in, src.host AS src, sport.port AS sport, sport.endport AS endsport,
		if_out.name AS if_out, dst.host AS dst, dport.port AS dport, dport.endport AS enddport, proto.name AS proto, rules.additional, target.name AS target
	FROM rules LEFT OUTER JOIN chains AS chain ON chain.id=rules.chain
		LEFT OUTER JOIN tables AS tbl ON tbl.id = chain.tbl
		LEFT OUTER JOIN protos AS proto ON proto.id=rules.proto
		LEFT OUTER JOIN hosts_to_groups AS sh2g ON sh2g.gid = rules.src
	       	LEFT OUTER JOIN hosts AS src ON src.id = sh2g.hid
		LEFT OUTER JOIN ports AS sport ON sport.id = rules.sport
		LEFT OUTER JOIN hosts_to_groups AS dh2g ON dh2g.gid = rules.dst
	       	LEFT OUTER JOIN hosts AS dst ON dst.id = dh2g.hid
		LEFT OUTER JOIN ports AS dport ON dport.id=rules.dport
		LEFT OUTER JOIN chains AS target ON target.id = rules.target
		LEFT OUTER JOIN real_interfaces AS if_in ON if_in.pseudo = rules.if_in
		LEFT OUTER JOIN real_interfaces AS if_out ON if_out.pseudo = rules.if_out
	WHERE
		if_in.firewall_id = if_out.firewall_id OR ( if_in.firewall_id IS NULL OR if_out.firewall_id IS NULL )
	ORDER BY rules.ord
);

ALTER TABLE hosts ALTER COLUMN host DROP NOT NULL;

