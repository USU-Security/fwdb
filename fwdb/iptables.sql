-- Mmm... firewall rules...

CREATE TABLE users (
	id serial primary key,
	name varchar UNIQUE NOT NULL,
	email varchar,
	a_number varchar
);

INSERT INTO users(name) VALUES ('admin');

CREATE TABLE interfaces (
	id serial primary key,
	name varchar NOT NULL UNIQUE,
	description varchar
);

INSERT INTO interfaces(name,description) VALUES ('internal', 'interface connected behind the firewall'), ('external', 'interface connected to the rest of the network'), ('loopback', 'loopback interface');

CREATE TABLE firewalls (
	id serial primary key,
	name varchar UNIQUE NOT NULL
);

CREATE TABLE chain_patterns (
	-- patterns that match our firewall-specific chains
	id serial primary key,
	pattern varchar UNIQUE NOT NULL,
	description varchar
);

CREATE TABLE firewalls_to_chain_patterns (
	-- which fw-specific patterns should be loaded by the firewalls
	id serial primary key,
	fw integer references firewalls(id) NOT NULL,
	pat integer references patterns(id) NOT NULL,
	unique(fw,pat)
);

CREATE TABLE real_interfaces (
	id serial primary key,
	name varchar NOT NULL,
	pseudo integer references interfaces(id) NOT NULL,
	firewall_id integer REFERENCES firewalls(id),
	is_bridged boolean NOT NULL DEFAULT FALSE
);

CREATE TABLE tables (
	id serial primary key,
	name varchar UNIQUE NOT NULL,
	description varchar
);

INSERT INTO tables( name ) VALUES ('filter'), ('nat'), ('mangle'), ('raw');

CREATE TABLE chains(
	id serial primary key,
	name varchar(30) NOT NULL,
	tbl integer references tables,
	builtin boolean DEFAULT FALSE NOT NULL,
	description varchar,
	UNIQUE(name,tbl)
);

INSERT INTO chains(name,tbl,builtin,description)
VALUES
	('ACCEPT', NULL, TRUE, NULL),
	('REJECT', NULL, TRUE, NULL),
	('DROP', NULL, TRUE, NULL),
	('LOG', NULL, TRUE, NULL),
	
	('INPUT', (SELECT id FROM tables WHERE name='filter'), TRUE, NULL),
	('FORWARD', (SELECT id FROM tables WHERE name='filter'), TRUE, NULL),
	('OUTPUT', (SELECT id FROM tables WHERE name='filter'), TRUE, NULL),
	
	('PREROUTING', (SELECT id FROM tables WHERE name='nat'), TRUE, NULL),
	('OUTPUT', (SELECT id FROM tables WHERE name='nat'), TRUE, NULL),
	('POSTROUTING', (SELECT id FROM tables WHERE name='nat'), TRUE, NULL),
	
	('PREROUTING', (SELECT id FROM tables WHERE name='mangle'), TRUE, NULL),
	('OUTPUT', (SELECT id FROM tables WHERE name='mangle'), TRUE, NULL),
	('INPUT', (SELECT id FROM tables WHERE name='mangle'), TRUE, NULL),
	('FORWARD', (SELECT id FROM tables WHERE name='mangle'), TRUE, NULL),
	('POSTROUTING', (SELECT id FROM tables WHERE name='mangle'), TRUE, NULL),

	('PREROUTING', (SELECT id FROM tables WHERE name='raw'), TRUE, NULL),
	('OUTPUT', (SELECT id FROM tables WHERE name='raw'), TRUE, NULL)
;

CREATE TABLE protos (
	id integer primary key,
	name varchar,
	description varchar
);

-- cat /etc/protocols | grep -v '^\#\|^$' | sed "s/[\`\'\"]//g;s/\(\S\+\)\s\+\([0-9]\+\)[^\#]*\# \(.*\)/(\2, '\1', '\3'),/g"
INSERT INTO protos(id,name,description) VALUES
	(0, 'ip', 'internet protocol, pseudo protocol number'),
	(1, 'icmp', 'internet control message protocol'),
	(2, 'igmp', 'Internet Group Management'),
	(3, 'ggp', 'gateway-gateway protocol'),
	(4, 'ipencap', 'IP encapsulated in IP (officially IP)'),
	(5, 'st', 'ST datagram mode'),
	(6, 'tcp', 'transmission control protocol'),
	(8, 'egp', 'exterior gateway protocol'),
	(9, 'igp', 'any private interior gateway (Cisco)'),
	(12, 'pup', 'PARC universal packet protocol'),
	(17, 'udp', 'user datagram protocol'),
	(20, 'hmp', 'host monitoring protocol'),
	(22, 'xns-idp', 'Xerox NS IDP'),
	(27, 'rdp', 'reliable datagram protocol'),
	(29, 'iso-tp4', 'ISO Transport Protocol class 4 [RFC905]'),
	(36, 'xtp', 'Xpress Transfer Protocol'),
	(37, 'ddp', 'Datagram Delivery Protocol'),
	(38, 'idpr-cmtp', 'IDPR Control Message Transport'),
	(41, 'ipv6', 'Internet Protocol, version 6'),
	(43, 'ipv6-route', 'Routing Header for IPv6'),
	(44, 'ipv6-frag', 'Fragment Header for IPv6'),
	(45, 'idrp', 'Inter-Domain Routing Protocol'),
	(46, 'rsvp', 'Reservation Protocol'),
	(47, 'gre', 'General Routing Encapsulation'),
	(50, 'esp', 'Encap Security Payload [RFC2406]'),
	(51, 'ah', 'Authentication Header [RFC2402]'),
	(57, 'skip', 'SKIP'),
	(58, 'ipv6-icmp', 'ICMP for IPv6'),
	(59, 'ipv6-nonxt', 'No Next Header for IPv6'),
	(60, 'ipv6-opts', 'Destination Options for IPv6'),
	(73, 'rspf', 'Radio Shortest Path First (officially CPHB)'),
	(81, 'vmtp', 'Versatile Message Transport'),
	(88, 'eigrp', 'Enhanced Interior Routing Protocol (Cisco)'),
	(89, 'ospf', 'Open Shortest Path First IGP'),
	(93, 'ax.25', 'AX.25 frames'),
	(94, 'ipip', 'IP-within-IP Encapsulation Protocol'),
	(97, 'etherip', 'Ethernet-within-IP Encapsulation [RFC3378]'),
	(98, 'encap', 'Yet Another IP encapsulation [RFC1241]'),
	(103, 'pim', 'Protocol Independent Multicast'),
	(108, 'ipcomp', 'IP Payload Compression Protocol'),
	(112, 'vrrp', 'Virtual Router Redundancy Protocol'),
	(115, 'l2tp', 'Layer Two Tunneling Protocol [RFC2661]'),
	(124, 'isis', 'IS-IS over IPv4'),
	(132, 'sctp', 'Stream Control Transmission Protocol'),
	(133, 'fc', 'Fibre Channel'),
	(136, 'udplite', 'UDP-Lite'),
	(137, 'mpls-in-ip', 'MPLS-in-IP [RFC4023]'),
	(138, 'manet', 'MANET Protocols'),
	(139, 'hip', 'Host Identity Protocol')
;

-- FIXME: empty groups will do bad things

CREATE TABLE hosts (
	id serial primary key,
	name varchar,
	host cidr,
	host_end cidr,
	owner integer REFERENCES users(id) NOT NULL,
	description varchar,
	is_group boolean default FALSE,
	CHECK ( ( (host IS NOT NULL AND host_end IS NULL )
		       	OR ( host IS NOT NULL AND masklen(host) = 32 AND masklen(host_end) = 32
			       	AND host < host_end ) AND is_group = FALSE )
       		OR ( host IS NULL AND host_end IS NULL AND is_group IS TRUE) ),
	UNIQUE (host,host_end)
);

CREATE UNIQUE INDEX hosts_host_key2 ON hosts(host) WHERE host_end IS NULL;

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

CREATE TABLE ports(
	id serial primary key,
	name varchar unique,
	port integer NOT NULL,
	endport integer,
	description varchar
);

CREATE TABLE rules (
	id serial primary key,
	-- What chain/table does this rule belong to (argument to -I or -A, also determines -t)?
	chain integer references chains(id) NOT NULL,
	if_in integer references interfaces(id),
	if_out integer references interfaces(id),
	proto integer references protos(id),
	src integer references hosts(id),
	sport integer references ports(id),
	dst integer references hosts(id),
	dport integer references ports(id),
	-- Note: this chain must belong to the same table as 'chain'
	-- (or table=NULL)
	target integer references chains(id) NOT NULL,
	-- Additional arguments to iptables
	additional varchar DEFAULT NULL,
	-- column used for rule ordering
	ord integer NOT NULL,
	enabled boolean NOT NULL DEFAULT TRUE,
	description varchar,
	expires timestamp default NULL,
	created_for integer REFERENCES users(id) NOT NULL
);

CREATE TABLE rule_stats (
	id bigserial primary key,
	rule integer REFERENCES rules(id) ON DELETE CASCADE NOT NULL,
	src integer REFERENCES hosts(id) ON DELETE CASCADE,
	dst integer REFERENCES hosts(id) ON DELETE CASCADE,
	packets bigint NOT NULL,
	bytes bigint NOT NULL,
	time timestamptz NOT NULL DEFAULT NOW()
);


