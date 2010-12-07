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
	pat integer references chain_patterns(id) NOT NULL,
	unique(fw,pat)
);

