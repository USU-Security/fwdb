import types
import psycopg2
import re

import datetime
import os

import IPy

import time

import subprocess
import shlex

# NOTE: endlines should never be allowed anywhere
valid = re.compile( r"^[a-zA-Z0-9 '!/@.,%\"=?\n<>()\\:#|_$\t-]+$" )
#address = re.compile( r"^([0-9]{1,3}\.){,3}[0-9]{1,3}(/[1-3]?[0-9])?$" )
address = re.compile( r"^(([0-9]{1,3}\.){3}[0-9]{1,3})|(([0-9]{1,3}\.){,3}[0-9]{1,3}/[1-3]?[0-9])$" )

table_re = re.compile(r"^[a-z_]+$")

numeric = re.compile( r"^[0-9]+$" )

_default = object()

IPSET_CMD = "ipset"

def get_output(cmd):
	return subprocess.check_output( shlex.split(cmd) )

def get_ipset_version():
	try:
		output = get_output(IPSET_CMD + ' -v')
		m = re.search(r'ipset v([0-9.]+)', output)
		if m:
			ver = m.group(1)
			major = int(ver.split('.')[0])
	except Exception,e:
		print e
		return "FAILED"
	return major

ipset_version = get_ipset_version()

if ipset_version == 6 or ipset_version == "FAILED":
	IPSET_ADD_OPT = "add"
	IPSET_DEL_OPT = "del"
	IPSET_CREATE_OPT = "create"
	IPSET_DESTROY_OPT = "destroy"
	IPSET_SAVE_OPT = "save"
	IPSET_IPHASH_TYPE = "hash:ip"
	IPSET_NETHASH_TYPE = "hash:net"
	IPSET_CREATE = "%s %s %%s %%s family inet" % ( IPSET_CMD, IPSET_CREATE_OPT )

elif ipset_version == 4:
	IPSET_ADD_OPT = "-A"
	IPSET_DEL_OPT = "-D"
	IPSET_CREATE_OPT = "-N"
	IPSET_DESTROY_OPT = "-X"
	IPSET_SAVE_OPT = "-S"
	IPSET_IPHASH_TYPE = "iphash"
	IPSET_NETHASH_TYPE = "nethash"
	IPSET_CREATE = "%s %s %%s %%s" % ( IPSET_CMD, IPSET_CREATE_OPT )

else:
	raise Exception("Unknown ipset version")

IPSET_ADD = "%s %s %%s %%s" % ( IPSET_CMD, IPSET_ADD_OPT )
IPSET_DEL = "%s %s %%s %%s" % ( IPSET_CMD, IPSET_DEL_OPT )

IPSET_DESTROY = "%s %s %%s" % ( IPSET_CMD, IPSET_DESTROY_OPT )

IPSET_SAVE_ALL = "%s %s" % ( IPSET_CMD, IPSET_SAVE_OPT )
IPSET_SAVE_SET = IPSET_SAVE_ALL + " %s"

def check_table_name(v):
	if table_re.match(v):
		return True
	raise Exception("Invalid table name: '%s'" % v)

def check_input(v):
	if type(v) is str:
		return check_input_str(v)
	if type(v) in (list, tuple, set):
		return check_input_list(v)
	if type(v) is dict:
		return check_input_dict(v)

def check_input_str(v):
	if type(v) == types.IntType:
		return str(v)
	if not valid.search(v):
		raise Exception( 'invalid input: %s' % repr(v) )
	if re.search( r"'", v ):
		v = re.sub(r"'",r"''",v)
	return v

def check_input_list(v):
	new_v = []
	for i in v:
		new_v.append(check_input_str(i))
	return new_v

def check_input_dict(d):
	for i in d.keys():
		v = d[i]
		if type(v) in(types.ListType, set, tuple):
			d[i] = check_input_list(v)
		elif v is None:
			pass
		else:
			v = str(v)
			try:
				d[i] = check_input_str(v)
			except:
				raise Exception("Invalid input for '%s': '%s'" % (i,v) )

def is_numeric(a):
	if numeric.match(a.strip()):
		return True
	return False

def is_address(a):
	if address.match(str(a)):
		return True
	return False

def has_wildcard(a):
	if re.search(r'%',a):
		return True
	return False

class NotFound(Exception):
	pass

class db(object):
	columns = {
			'users':['id','name','email','a_number',],
			'interfaces':['id','name','description',],
			'real_interfaces':None,
			'tables':['id','name','description',],
			'chains':['id','name','tbl','builtin','description',],
			'protos':None,
			'hosts':['id','name','host','host_end','owner','description',],
			'ports':None,
			'rules':['id','chain','if_in','if_out','proto','src','sport','dst','dport','target',
				'additional','ord','enabled','description','expires','created_for',],
		}
	show_sql = False

	rule_join="""rules LEFT OUTER JOIN chains AS chain ON chain.id=rules.chain
		LEFT OUTER JOIN users AS for_user ON rules.created_for = for_user.id
		LEFT OUTER JOIN tables AS tbl ON tbl.id = chain.tbl
		LEFT OUTER JOIN protos AS proto ON proto.id=rules.proto
		LEFT OUTER JOIN hosts AS src ON src.id = rules.src
		LEFT OUTER JOIN ports AS sport ON sport.id = rules.sport
		LEFT OUTER JOIN hosts AS dst ON dst.id = rules.dst
		LEFT OUTER JOIN ports AS dport ON dport.id=rules.dport
		LEFT OUTER JOIN chains AS target ON target.id = rules.target
		LEFT OUTER JOIN interfaces AS pseudo_if_in ON pseudo_if_in.id = rules.if_in
		LEFT OUTER JOIN interfaces AS pseudo_if_out ON pseudo_if_out.id = rules.if_out
		LEFT OUTER JOIN real_interfaces AS if_in ON if_in.pseudo = rules.if_in
		LEFT OUTER JOIN real_interfaces AS if_out ON if_out.pseudo = rules.if_out\n"""
	usage_subq="""(SELECT rule,
			SUM(CASE WHEN time > NOW() - INTERVAL '12 months' THEN packets ELSE 0 END) AS packets12,
			SUM(CASE WHEN time > NOW() - INTERVAL '6 months' THEN packets ELSE 0 END) AS packets6,
			SUM(CASE WHEN time > NOW() - INTERVAL '3 months' THEN packets ELSE 0 END) AS packets3,
			SUM(CASE WHEN time > NOW() - INTERVAL '1 months' THEN packets ELSE 0 END) AS packets1
			FROM rule_stats
			WHERE time > NOW() - INTERVAL '12 months' -- needed to allow us to use our time index
			--WHERE time > NOW() - INTERVAL '6 months' -- 6 months instead of 12 took the query from ~9 seconds to ~2 seconds...
			GROUP BY rule)"""
	rule_enabled_fmt="""CASE WHEN rules.enabled = FALSE THEN '#:disabled: ' ELSE '' END
			|| CASE WHEN rules.expires < NOW() then '#:expired: ' ELSE '' END\n"""
	rule_comment_fmt="""'# id:' || rules.id || ' ord:' || ord
		|| CASE WHEN src.name IS NOT NULL THEN CASE WHEN src.is_group THEN ' from group: ' ELSE ' from ' END || src.name ELSE '' END
		|| CASE WHEN dst.name IS NOT NULL THEN CASE WHEN dst.is_group THEN ' to group: ' ELSE ' to ' END || dst.name ELSE '' END
		|| CASE WHEN for_user.name IS NOT NULL then ' for ' || for_user.name ELSE '' END
		|| CASE WHEN rules.description IS NOT NULL then ' - ' || rules.description ELSE '' END 
		|| CASE WHEN rules.expires IS NOT NULL then ' -- EXP:' || to_char(rules.expires, 'YYYY-MM-DD') ELSE '' END || E'\\n'\n"""

	rule_base_fmt = """''
		%s
		||' -A '||chain.name

		|| CASE WHEN proto.name IS NOT NULL then ' -p ' || proto.name ELSE '' END
		|| CASE WHEN src.host_end IS NOT NULL OR dst.host_end IS NOT NULL THEN ' -m iprange' ELSE '' END
		|| CASE WHEN src.is_group IS NOT NULL AND src.is_group THEN ' -m set --match-set ' || src.name || ' src' ELSE '' END
		|| CASE WHEN src.host_end IS NOT NULL THEN ' --src-range ' || host(src.host) || '-' || host(src.host_end) WHEN src.host IS NOT NULL then ' -s ' || src.host ELSE '' END
		|| CASE WHEN sport.endport IS NOT NULL then ' --sport ' || sport.port||':'||sport.endport WHEN sport.port IS NOT NULL then ' --sport ' || sport.port ELSE '' END
		
		|| CASE WHEN dst.is_group IS NOT NULL AND dst.is_group THEN ' -m set --match-set ' || dst.name || ' dst' ELSE '' END
		|| CASE WHEN dst.host_end IS NOT NULL THEN ' --dst-range ' || host(dst.host) || '-' || host(dst.host_end) WHEN dst.host IS NOT NULL then ' -d '||dst.host ELSE '' END
		|| CASE WHEN dport.endport IS NOT NULL then ' --dport '||dport.port||':'||dport.endport WHEN dport.port IS NOT NULL then ' --dport '||dport.port ELSE '' END
		
		|| ' -j '||target.name
		|| CASE WHEN rules.additional IS NOT NULL THEN ' '||rules.additional ELSE '' END
		|| ' -m comment --comment "id:' || rules.id || ' src:' || COALESCE(src.id::VARCHAR,'NULL') || ' dst:' || COALESCE(dst.id::VARCHAR,'NULL') || '"'
		|| E'\\n'
	"""
	rule_args_fmt = rule_base_fmt % """
		|| CASE WHEN rules.if_in IS NOT NULL then
			CASE WHEN if_in.is_bridged THEN ' -m physdev --physdev-in ' || if_in.name
			ELSE ' -i '||if_in.name END
		ELSE '' END
		|| CASE WHEN rules.if_out IS NOT NULL then
			CASE WHEN if_out.is_bridged THEN ' -m physdev --physdev-out ' || if_out.name
			ELSE ' -o '||if_out.name END
		ELSE '' END
		"""
	rule_cmd_fmt="""'%s -t ' || tbl.name || ' ' ||\n""" + rule_args_fmt
	rule_noiface_fmt = rule_base_fmt % """
		|| CASE WHEN rules.if_in IS NOT NULL then
			'<iface_in:'||pseudo_if_in.name||'> '
		ELSE '' END
		|| CASE WHEN rules.if_out IS NOT NULL then
			'<iface_out:'||pseudo_if_out.name||'> '
		ELSE '' END
		|| '%s -t ' || tbl.name 
		"""
	rule_restore_fmt = ' || '.join([ rule_enabled_fmt, rule_comment_fmt, rule_enabled_fmt, rule_args_fmt ])
	rule_full_fmt = ' || '.join([ rule_enabled_fmt, rule_comment_fmt, rule_enabled_fmt, rule_cmd_fmt ])
	rule_display_fmt = ' || '.join([ rule_enabled_fmt, rule_comment_fmt, rule_enabled_fmt, rule_noiface_fmt ])
	rule_order = 'ORDER BY CASE WHEN chain.builtin = TRUE THEN 1 ELSE 0 END,chain.name,rules.ord,rules.id,src.host,dst.host'
	#rule_valid_where="""(if_in.firewall_id = '$firewall_id' OR if_in.firewall_id IS NULL) AND (if_out.firewall_id = '$firewall_id' OR if_out.firewall_id IS NULL )"""

	def __init__( self, db=None, fw=None, user=None):
		if not db:
			db="dbname='fwdb' user='esk'"
		self.__conn = psycopg2.connect(db)
		self.__curs = self.__conn.cursor()
		self.uid=1
		self.fw = None
		# FIXME!
		self.set_firewall(fwname=fw)
		self.user = None
		#maybe we will do permissions later
		#if user:
		#	r = self.execute_query("select id from users where name = %s or a_number = %s;", [user, user]);
		#	if r:
		#		self.user = r[0][0]
		self.user = user
		if fw and user:
			if not self.check_fw_permission():
				raise ValueError("%s does not have access to firewall %s"%(user, fw))
		self.last_usage_update = 0
		self.temp_usage_table_name = None
	def __del__( self ):
		self.__conn.close()

	def set_firewall( self, fwname=None, fwid=False ):
		if fwname:
			r = self.execute_query("select id from firewalls where name = %s;", [fwname])
			if r:
				self.fw = r[0][0]
		elif fwid is not False:
			self.fw = fwid

	def execute_insert(self, statement, values=None):
		try:
			if self.show_sql:
				print statement, values
			self.__curs.execute(statement, vars=values)
			self.__conn.commit()
		except:
			self.rollback()
			raise

	def execute_query(self, statement, values=None):
		try:
			if self.show_sql:
				print statement, values
			self.__curs.execute(statement, vars=values)
			self.__conn.commit()
			return self.__curs.fetchall()
		except:
			self.rollback()
			raise

	def del_table(self, name, whereclause):
		check_input_str(name)
		check_input_str(whereclause)
		sql = 'DELETE FROM %s WHERE %s' % ( name, whereclause)

		return self.execute_insert(sql)

	def get_last_id( self, table ):
		# Assumes table_seq exists
		check_table_name(table)
		sql = "SELECT currval('%s_id_seq')" % table

		return self.execute_query(sql)[0]

	def get_table(self, name, columns, whereclause=None, whereargs=None, og=None, distinct=True):
		check_input_str(name)
		for col in columns: check_input_str(col)
		distinct_str = ''
		if distinct:
			distinct_str='DISTINCT '

		sql = 'SELECT %s%s FROM %s' % ( distinct_str, ','.join(columns), name,)
		if whereclause:
			sql += ' WHERE %s' % whereclause
		if og:
			sql += ' %s' % og

		return self.execute_query(sql, values=whereargs)
	
	def host_ip_match( self, column, address, exact=False ):
		if not exact:
			return "(%s <<= '%s' OR %s >> '%s')" % (column,address,column,address,)
		else:
			return "%s = '%s'" % (column,address,)

	def get_where( self, d ):
		check_input_dict(d)
		where_items = []
		for i in d.keys():
			v = d[i]
			if type(v) == types.IntType:
				where_items.append('%s = %s' % (i,str(v)) )
			if type(v) in (types.ListType, set, tuple):
				where_items.append('%s IN %s' % (i, "(%s)" % ', '.join(v)) )
			elif is_address(v):
				exact=v[-3:] == '/32'
				where_items.append( self.host_ip_match(i,str(v), exact) )
			elif has_wildcard(v):
				where_items.append("%s like '%s'" % (i,str(v)) )
			else:
				v = str(v)
				comparison = '='
				if '%' in v:
					comparison = 'ILIKE'
				where_items.append("%s %s '%s'" % (i, comparison, v) )
		return where_items
	
	def get_dict( self, table, columns, d=None, conj = ' AND ', order_by=None, distinct = False):
		where_items=[]
		from_items = []
		from_keys = []
		for a in columns:
			if type(a) in (list, tuple):
				from_items.append(a[0])
				from_keys.append(a[1])
			else:
				from_items.append(a)
				from_keys.append(a)
		distinct = distinct and "DISTINCT " or ""
		if d:
			if type(d) is str:
				where = d
			elif type(d) is dict:
				where = conj.join(self.get_where(d))
			else:
				raise Exception("d should be dict or string, not %r"%d)
			sql = 'SELECT %s%s FROM %s WHERE %s' % (distinct, ','.join(from_items), table, where)
		else:
			sql = 'SELECT %s%s FROM %s' % (distinct, ','.join(from_items), table)

		if order_by is not None:
			sql = "%s ORDER BY %s" % (sql, order_by)

		data=self.execute_query( sql )

		final = []
		for d in data:
			item={}
			for i in range(len(from_keys)):
				item[from_keys[i]]=d[i]
			final.append(item)

		return final

	def get_host_clause( self, fields, host, nulls=False, exact=True ):
			if is_address( host ):
				host_ids = [ i[0] for i in self.get_table( 'hosts', ['id'], self.host_ip_match('host', host, exact=exact) ) ]
			elif type(host) is int:
				host_ids = [host]
			elif type(host) in (list, tuple, set):
				host_ids = list(host)
			else:
				host_ids = [ i[0] for i in self.get_table( 'hosts', ['id'], "name = '%s'" % host) ]
			
			if not host_ids:
				raise Exception('No matching hosts.')
			items = {}
			for f in fields:
				if len(host_ids) == 1:
					items[f]=host_ids[0]
				else:
					items[f]=host_ids

			if not host_ids:
				return []
			if nulls:
				return '(%s OR %s IS NULL)' % ( ' OR '.join( self.get_where( items )), ' IS NULL OR '.join(fields),)
			return '(%s)' % ( ' OR '.join( self.get_where( items )),)

	def get_host_id( self, identifier ):
		# identifier should either be a hostname or ip address
		if is_address( identifier ):
			id = self.get_id_byname('hosts',identifier,fieldname='host',andwhere='host_end IS NULL')
		else:
			id = self.get_id_byname('hosts',identifier)
		if id:
			print '\tid: %(id)s hostname: %(name)s address: %(host)s description: %(description)s' % self.get_dict('hosts',['name','host','description', 'id',], {'id': id} )[0]
			return id
		raise Exception('FIXME: Invalid host')

	def get_port_id( self, identifier ):
		if is_numeric( identifier ):
			port = int(identifier.strip())
			id = self.get_id_byname('ports',port,fieldname='port')
		else:
			id = self.get_id_byname('ports',identifier)
		if id:
			return id
		raise Exception('FIXME: Invalid port')
	def get_rules( self, host=None, port=None, src=None, sport=None, dst=None, dport=None, chain=None, id=None,
			iptables='iptables', ipt_restore=False, table=False, target=None, andwhere=None, columns=None,fw_id=None,
			expired=None, show_usage=False, enabled=None, append_default_columns=False, asdict=False):
		where_items = []
		if ipt_restore:
			use_fmt = self.rule_restore_fmt
		else:
			use_fmt = self.rule_display_fmt
		if expired is not None:
			if type(expired) == str:
				if expired.lower().strip() == 'false':
					expired = False
				elif expired.lower().strip() == 'true':
					expired = True
				else:
					expired = int(expired)
			if type(expired) == int:
				where_items.append('rules.expires < ( NOW() + interval \'%s days\')' % expired)
			elif expired:
				where_items.append('rules.expires < NOW()')
			else:
				where_items.append('rules.expires > NOW()')
		if host:
			where_items.append(self.get_host_clause(['src','dst',], check_input_str(host)))
		if port:
			port = self.get_port_id( port )
			where_items.append('(rules.sport = %d OR rules.dport = %d)' % (port,port))
		if src:
			where_items.append(self.get_host_clause(['src',], check_input(src), nulls=False))
		if sport:
			sport = self.get_port_id( sport )
			where_items.append( 'rules.sport = %d' % int(sport) )
		if dst:
			where_items.append(self.get_host_clause(['dst',], check_input(dst), nulls=False))
		if dport:
			dport = self.get_port_id( dport )
			where_items.append( 'rules.dport = %d' % int(dport) )
		if chain:
			where_items.extend( self.get_where({'chain.name':check_input_str(chain)}) )
		if target:
			where_items.extend( self.get_where({'target.name':check_input_str(target)}) )
		if enabled is not None:
			where_items.extend( self.get_where({'rules.enabled':enabled}) )
		if id:
			if type(id) == types.StringType:
				id = int(id)
			where_items.extend(self.get_where({'rules.id':id}))
		if table is not False:
			where_items.append( 'chain.tbl = %d' % int(table))
		if fw_id is None and self.fw:	
			fw_id = self.fw
		if fw_id:
			valid_chains = self.get_fw_chains(fw_id=fw_id)
			where_items.append( " (chain.id in ("+",".join(map(str, valid_chains)) + "))")
			if not ipt_restore:
				use_fmt = self.rule_full_fmt
			# FIXME: do we need to do more sanity checking on interfaces?
			where_items.append('(if_in.firewall_id = %s or rules.if_in is NULL)' % fw_id)
			where_items.append('(if_out.firewall_id = %s or rules.if_out is NULL)' % fw_id)
		if andwhere:
			where_items.append( andwhere )
			

		rule_join = self.rule_join
		if show_usage:
			age = time.time() - self.last_usage_update
			if age < 3600:
				print "Using usage statistics which were cached %d minutes ago" % (age/60+1)
			else:
				print "Updating usage statistics cache"
				t0 = time.time()
				if self.temp_usage_table_name is not None:
					self.execute_insert("DROP TABLE \"%s\";" % self.temp_usage_table_name)
				else:
					self.temp_usage_table_name = "usage_temp"
				self.execute_insert("CREATE TEMP TABLE \"%s\" AS " % self.temp_usage_table_name + self.usage_subq )
				self.last_usage_update=time.time()
				print "updated in %d sec" % (self.last_usage_update-t0)

			#rule_join = ' LEFT OUTER JOIN '.join([self.rule_join, self.usage_subq + ' AS usage ON rules.id = usage.rule'])
			rule_join = ' LEFT OUTER JOIN '.join([self.rule_join, ' "%s" as usage ON rules.id = usage.rule' % self.temp_usage_table_name])
			use_fmt = ' || '.join([use_fmt, self.rule_enabled_fmt, "CASE WHEN packets1 IS NOT NULL THEN '# USAGE -- packets in 12 mo: ' || packets12 ||', 6 mo: '|| packets6 || ', 3 mo: ' || packets3 || ', 1 mo: '||packets1 ELSE 'USAGE: nothing recorded' END || E'\\n'"])
			#use_fmt = ' || '.join([use_fmt, self.rule_enabled_fmt, "CASE WHEN packets1 IS NOT NULL THEN '# USAGE -- packets in 6 mo: '|| packets6 || ', 3 mo: ' || packets3 || ', 1 mo: '||packets1 ELSE 'USAGE: nothing recorded' END || E'\\n'"])
		if '%s' in use_fmt:
			use_fmt %= iptables

		if columns is None:
			columns = []
			append_default_columns=True
		if append_default_columns:
			columns.extend([ use_fmt, 'rules.id' ])
		if asdict:
			return self.get_dict( rule_join, columns, ' AND '.join(where_items), self.rule_order)
		else:
			return self.get_table( rule_join, columns, ' AND '.join(where_items), og=self.rule_order, distinct=False )

	def get_tables(self):
		return self.get_dict( 'tables', ('id','name','description',) )
	
	def get_chain_id(self, name, table_name=None, table_id=False):
		check_input_str( name )
		if table_name is not None:
			check_input_str( table_name )
		if table_id is not False:
			if table_id is None:
				table_spec = 'is NULL'
			else:
				table_id = int(table_id)
				table_spec = '= %d' % table_id
		else:
			if table_name is None:
				table_name='filter'
			table_id = self.get_id_byname('tables',table_name)
			table_spec = '= %d' % table_id

		sql='SELECT id FROM chains WHERE name=\'%s\' and tbl %s' % (name,table_spec)
		results = self.execute_query(sql)
		if not results:
			raise NotFound("Invalid chain specification: name=%s, tbl=%s" % (name,table_id) )
		if len(results) > 1:
			raise Exception("Database is inconsistent: more than one row returned for chain specification: name=%s, tbl=%s" % (name,table_id) )
		return results[0][0]

	def get_id_byname(self, table, name, fieldname='name', andwhere=None):
		check_input_str( name )
		sql='SELECT id FROM %s WHERE %s=%%s' % (table,fieldname)
		if andwhere:
			sql += ' AND %s' % andwhere
		results = self.execute_query(sql, (name,))
		if not results:
			raise NotFound("Invalid for table %s: %s=%s" % (table,fieldname,name))
		if len(results) > 1:
			raise Exception("Database is inconsistent: more than one row returned from table %s for %s=%s"%(table,fieldname,name))
		return results[0][0]

	def rollback(self):
		self.__conn.rollback()
		del self.__curs
		self.__curs = self.__conn.cursor()
		raise

	def add_dict( self, table, d, where=None, update=False ):
		fields=[]
		values=[]
		check_input_dict(d)
		for field in d.keys():
			fields.append(field)
			v = d[field]
			if v is None:
				values.append('NULL')
			elif type(v) == types.IntType:
				values.append(str(v))
			else:
				values.append("'%s'" % str(v))
		if update:
			sql = 'UPDATE %s SET %s WHERE %s RETURNING id;' % (table,', '.join(['%s = %s' % (fields[i],values[i]) for i in range(len(fields))]), where)
		else:
			sql = 'INSERT INTO %s(%s) VALUES (%s) RETURNING id;' % (table,','.join(fields),','.join(values))
		return self.execute_query(sql)

	def add_user(self,name,email=None,a_number=None):
		# FIXME: Add some validation here
		user_d = {}
		user_d['name'] = name
		if email: user_d['email'] = email
		if a_number: user_d['a_number'] = a_number
		return self.add_dict( 'users', user_d )

	def add_host(self,name,owner_name=None, owner_id=None,address=None,endaddress=None,description=None, is_group=False, update=False, id=None):
		host = {}
		host['name'] = name
		if address: host['host'] = address
		if endaddress: host['host_end'] = endaddress
		if owner_name:
			host['owner'] = self.get_id_byname('users',owner_name)
		elif owner_id:
			host['owner'] = owner_id
		else:
			raise Exception("Owner must be specified")
		host['is_group']=is_group
		if description: host['description'] = description
		if update:
			return self.add_dict( 'hosts', host, update=True, where='id = %s' % id )
		else:
			return self.add_dict( 'hosts', host )

	def get_host(self, host_id):
		return self.get_hosts(host_ids=host_id)[0]
	def get_hosts(self, host_ids=None, name=None, ip=None, is_group=None, gid=None):
		where = {}
		if host_ids:
			where['hosts.id'] = host_ids
		if name:
			where['name'] = name
		if ip:
			where['host'] = ip
		if is_group is not None:
			where['is_group'] = is_group
		if gid is not None:
			where['gid'] = gid
		return self.get_dict('hosts left join hosts_to_groups on hosts.id = hid', ['hosts.id', 'name', 'host', 'host_end', 'description', 'is_group', 'owner', 'last_check',], where, distinct=True)

	def get_hosts_to_groups( self, group_id=None, group_name=None, host_id=None, hostname=None, expired=None ):
		where = {}
		where_items = []
		if group_id and group_name:
			raise InvalidArgument("Must not specify both group_id and group_name: (id: %s, name: %s)" % (group_id,group_name))
		if host_id and hostname:
			raise InvalidArgument("Must not specify both host_id and hostname: (id: %s, name: %s)" % (host_id,hostname))
		if expired is not None:
			if expired:
				where_items.append( "hosts_to_groups.expires <= NOW()" )
			else:
				where_items.append( "hosts_to_groups.expires > NOW()" )
		if group_name:
			groups = self.get_groups( name=group_name )
			if len(groups) != 1:
				raise Exception("Invalid or duplicate group found: %s (%r)" % (group_name, groups))
			group_id = groups[0]['gid']
		if group_id:
			where['hosts_to_groups.gid'] = int(group_id)
		if hostname:
			hosts = get_hosts( name=hostname )
			if len(hosts) != 1:
				raise Exception("Invalid or duplicate host found: %s (%r)" % (hostname, hosts))
			host_id = hosts[0]['hosts.id']
		if host_id:
			where['hosts_to_groups.hid'] = host_id
		where_items.extend( self.get_where(where) )
		table = """hosts_to_groups join hosts on hosts_to_groups.hid = hosts.id and hosts.is_group = False
		join hosts groups on hosts_to_groups.gid = groups.id and groups.is_group = True"""
		columns = [ ("hosts_to_groups.id","id"), ("hosts_to_groups.expires","expires"), "hid", "gid", "hosts.name", "groups.name" ]

		d = ' AND '.join( where_items )

		return self.get_dict( table = table, columns = columns, d=d, order_by = "groups.name, hosts.name")

	def add_host_to_group( self, group_id, host_id=None, hostname=None, expires=None, update=False ):
		if expires is None:
			expires='+365'
		if expires[0] == '+':
			days = int(expires[1:])
			expires = (datetime.datetime.today() + datetime.timedelta(days)).strftime('%Y-%m-%d')
		else:
			expires = expires
		if not host_id:
			host_id = self.get_host_id(hostname = hostname)
		host = self.get_host(host_id)
		if IPy.IP(host['host']).len() == 1:
			d = self.get_table('hosts_to_groups as h2g join hosts on h2g.hid = hosts.id',['hosts.host','hosts.host_end'],
					'h2g.gid = %s and masklen(hosts.host) < 32' % int(group_id))
		else:
			d = self.get_table('hosts_to_groups as h2g join hosts on h2g.hid = hosts.id',['hosts.host','hosts.host_end'],
					'h2g.gid = %s and masklen(hosts.host) = 32' % int(group_id))
		if d:
			raise Exception("Cannot mix hosts and networks: gid: %s, host: %s, existing: %s" % (group_id, host, d) )

		if update:
			self.execute_insert( 'update hosts_to_groups set expires=%s where hid=%s and gid=%s', values=(expires,host_id,group_id) )
		else:
			self.add_dict( 'hosts_to_groups', {'hid':host_id,'gid':group_id,'expires':expires} )
			
		"""# I decided to put this off until someone actually needs it; will need to fix del_h2g, too
		self.begin_transaction()
		try:
			group = self.get_dict( 'hosts', ['id','is_host'], whereclause={'id': group_id} )
			if len(group) != 1:
				raise Exception('non-unique or non-existent group: %s' % group_id)
			group = group[0]
			if not host_id:
				host_id = self.get_id_byname( 'hosts', hostname )
			
			host = self.get_table( 'hosts', ['id','host'], whereclause='id = %d' % host_id )
			is_net = IPy.IP(host[0][1]).len() > 1

			if is_net and not group['is_host'] & NET_BIT:
				group['is_host'] &= NET_BIT
				self.add_dict('hosts', group, update=True)
			elif not is_net and not group['is_host'] & HOST_BIT:
				group['is_host'] &= HOST_BIT
				self.add_dict('hosts', group, update=True)

			self.add_dict( 'hosts_to_groups', {'hid':host_id,'gid':group_id,} )
		finally:
			self.end_transaction()
		"""

	def del_host_to_group( self, group_id, host_id=None, hostname=None ):
		if not host_id:
			host_id = self.get_host_id( hostname )
		#def del_table(self, name, whereclause):
		self.del_table('hosts_to_groups', 'hid = %d AND gid = %d' % (host_id,group_id) )

	def add_port(self,name,port,endport=None,description=None):
		port_dict={}
		port_dict['name']=name
		port_dict['port']=port
		if endport: port_dict['endport'] = endport
		if description: port_dict['description'] = description

		self.add_dict('ports',port_dict)

	def add_chain(self,name,table_name=None,table_id=None,builtin=False,description=None):
		chain = {}
		chain['name'] = name
		if table_id and table_name:
			raise Exception('must not specify both table_id and table_name')
		if table_name:
			table_id = self.get_id_byname('tables',table_name)
		if table_id: chain['tbl'] = table_id
		chain['builtin']=builtin
		if description: chain['description'] = description

		self.add_dict('chains',chain)

	def disable_rule(self, ids):
		if type(ids) == types.IntType:
			ids=[ids,]
		for id in ids:
			self.execute_insert("UPDATE rules SET enabled=FALSE where id=%s", (id,) )

	def enable_rule(self, ids):
		if type(ids) == types.IntType:
			ids=[ids,]
		for id in ids:
			self.execute_insert("UPDATE rules SET enabled=TRUE where id=%s", (id,) )
	def extend_rule(self, ids, days=365):
		self.execute_insert("UPDATE rules SET expires = now() + interval '%s days' where %s"%(int(days), " and ".join(self.get_where({'id':ids}))))

	def add_rule(self,update=False,id=_default,created_for_name=_default,chain_name=_default,table_name=_default,chain_id=_default,if_in=_default,if_out=_default,proto=_default,src=_default,sport=_default,
			dst=_default,dport=_default,target_id=_default,target_name=_default,additional=_default,ord=_default,description=_default,expires=_default):
		rule = {}
		if id is not _default and id:
			id = int(id)
		if update == True and type(id) != types.IntType:
			raise Exception('id must be an integer for update=True (id = %s)' % repr(id))
		#print locals()
		if chain_name is not _default and chain_id is not _default:
			raise Exception('must not specify both chain_name and chain_id')
		if chain_name:
			chain_id = self.get_chain_id(chain_name,table_name)
		rule['chain']=chain_id

		if if_in is None: rule['if_in'] = None
		elif if_in is not _default: rule['if_in'] = self.get_id_byname('interfaces',if_in)

		if if_out is None: rule['if_out'] = None
		elif if_out is not _default: rule['if_out'] = self.get_id_byname('interfaces',if_out)

		if src is None: rule['src'] = None
		elif src is not _default: rule['src'] = self.get_host_id(src)
		
		if sport is None: rule['sport'] = None
		elif sport is not _default: rule['sport'] = self.get_port_id(sport)
		
		if dst is None: rule['dst'] = None
		elif dst is not _default: rule['dst'] = self.get_host_id(dst)
		
		if dport is None: rule['dport'] = None
		elif dport is not _default: rule['dport'] = self.get_port_id(dport)
		
		if created_for_name is None: rule['created_for'] = None
		elif created_for_name is not _default: rule['created_for'] = self.get_id_byname('users',created_for_name)

		if proto is None: rule['proto'] = None
		elif proto is not _default: rule['proto'] = self.get_id_byname('protos',proto)

		if target_name is not _default:
			try:
				target_id = self.get_chain_id(name=target_name,table_name=table_name)
			except:
				target_id = self.get_chain_id(name=target_name,table_id=None)

		if target_id is not _default: rule['target'] = target_id

		if additional is not _default: rule['additional'] = additional

		if ord is _default and not update:
			raise Exception('Must specify ord')
		if ord is not _default:
			rule['ord'] = ord

		if description is not _default: rule['description'] = description
		#if expires is not _default: rule['expires'] = parse_expires(expires)
		if expires is not _default: rule['expires'] = expires

		if update:
			self.add_dict( 'rules', rule, update=True, where="id=%s"%id )
		else:
			self.add_dict( 'rules', rule )

	def get_matching(self, tblname, columns, values):
		value_lst = []
		check_input_dict(values)
		for i in values.keys():
			v = str(values[i])
			if type(v) == types.IntType:
				v = str(v)
			else:
				v = "'%s'" % str(v)
			if re.search(r'%',v):
				value_lst.append('%s like %s' % (i,v) )
			else:
				value_lst.append('%s = %s' % (i,v) )
		value_stmt = ' AND '.join(value_lst)
		sql = 'SELECT %s FROM %s WHERE %s' % (','.join(columns),tblname,value_stmt)
	def get_ipset(self, group=None, allow_expired=False):
		expired_records = False
		from_def = """hosts_to_groups as h2g
				join hosts as groups on groups.id = h2g.gid
				join hosts on h2g.hid = hosts.id"""
		whereclause = None
		sets = ipset_list()
		whereclause = {'groups.is_group': True}
		if self.fw:
			valid_chains = self.get_fw_chains()
			chain_patterns_where = " (chain in ("+",".join(map(str, valid_chains))+")) "
			valid_hosts = set()
			for src, dst in self.execute_query("select src, dst from rules where %s"%chain_patterns_where):
				if src:
					valid_hosts.add(src)
				if dst:
					valid_hosts.add(dst)
			whereclause['groups.id'] = list(valid_hosts)
		if group:
			whereclause['h2g.gid'] = int(group)
		data = self.get_dict( from_def, ['groups.name', 'groups.id', 'hosts.name', 'hosts.id', 'hosts.host', 'hosts.host_end',('h2g.expires < now() as expired','expired',)],
				whereclause, order_by='groups.name, hosts.id' )
		for d in data:
			if d['expired']:
				print 'WARNING: host %s has expired from group %s' % (d['hosts.name'],d['groups.name'],)
				expired_records=True
			sets.add(d['groups.name'],d['hosts.host'],d['hosts.host_end'])
		if expired_records and not allow_expired:
			raise Exception("Please update or delete expired host to group entries")
		return sets
	def get_chains(self, builtin=None, name=None, cid=None):
		where = {}
		if builtin is not None:
			where['builtin'] = builtin
		if name is not None:
			where['name'] = name
		if cid is not None:
			where['id'] = cid
		else:
			where['id'] = self.get_fw_chains()
		return self.get_dict('chains', ['id', 'name', 'builtin', 'description'], where)

	def get_fw_chains(self, fw_id = None):
		if fw_id is None:
			fw_id = self.fw
		patterns = self.execute_query("select c.pattern from chain_patterns as c JOIN firewalls_to_chain_patterns AS f2c ON f2c.pat = c.id WHERE f2c.fw = %s;", [fw_id])
		if patterns:
			chain_patterns_where = "(chain.builtin=true OR "+" OR ".join(["chain.name LIKE '%s'"%i[0] for i in patterns])+")"
		else:
			raise Exception("No patterns found for this firewall.")
		rule_tree = {}
		#get a list of all the rules that could apply to us
		for c, t in self.execute_query("select r.chain,r.target from rules as r left join real_interfaces as i on r.if_in=i.pseudo left join real_interfaces as i2 on r.if_out=i2.pseudo where i.firewall_id is null and i2.firewall_id is null or (i.firewall_id = %s or i2.firewall_id=%s) group by chain, target;", [fw_id, fw_id]):
			if c not in rule_tree:
				rule_tree[c] = set()
			rule_tree[c].add(t)
		ret = set()
		def walkrules(r):
			for i in rule_tree.get(r, set()).difference(ret):
				ret.add(i)
				walkrules(i)
		for i, in self.execute_query("select id from chains as chain where %s"%chain_patterns_where):
			if i not in ret:
				walkrules(i)
				ret.add(i)
		return ret
	def get_fw_groups(self, fw_id=None, is_group=True):
		if is_group:
			src_where = "src.is_group=true"
			dst_where = "dst.is_group=true"
		else:
			src_where = None
			dst_where = None
		ret = set()
		for r in self.get_rules(andwhere=src_where, columns=['src.id'], fw_id=fw_id):
			ret.add(r[0])
		for r in self.get_rules(andwhere=dst_where, columns=['dst.id'], fw_id=fw_id):
			ret.add(r[0])
		return ret
	def get_groups(self, host_id = None, columns = None, name=None):
		where = {'is_group': True}
		if name:
			where['hosts.name'] = name
		if host_id: where['hosts_to_groups.hid'] = host_id
		if not columns:
			columns = [('hosts.id', 'gid'), 'name', 'owner', 'description']

		return self.get_dict("hosts_to_groups join hosts on hosts_to_groups.gid  = hosts.id", columns, where, distinct=True)

	def get_firewalls(self, name=None, columns = None):
		# Not used if 'columns' are specified
		q = "select f.name from firewalls as f"
		where = {}
		if name:
			where['name'] = name
		if columns is None:
			columns = ['name',]
		return self.get_dict(table='firewalls as f', columns = columns, d=where)

	def check_fw_permission(self):
		if self.fw and self.user:
			return True
			r = self.execute_query("select id from permissions where user_id = %s and fw_id = %s;", [self.user, self.fw]);
			if r:
				return True
		return False
	def get_user(self, uid = None, name = None, email = None, a_number = None):
		where = {}
		if uid: where['id'] = uid
		if name: where['name'] = name
		if email: where['email'] = email
		if a_number: where['a_number'] = a_number
		return self.get_dict('users', ['id', 'name', 'email', 'a_number'], where)
	def get_firewalls_by_group(self, gid):
		# FIXME: holy inefficiency, batman! (although, there shouldn't be much data here)
		ret = []
		for f in self.get_firewalls(columns=('id','name')):
			if gid in self.get_fw_groups(f['id'], is_group=False):
				ret.append(f)
		return ret









class ipset(object):
	def __init__(self, name, set_type=None):
		self.name = name
		self.set_type = set_type
		self.hosts = set()
		self.nets = set()
	def diff(self, s):
		# return (remove, add) to turn self into s
		if (self.hosts and  s.nets) or (self.nets and s.hosts):
			raise Exception("Cannot mix hosts and networks, sorry.")
		if (self.set_type and s.set_type and self.set_type != s.set_type):
			raise Exception("Cannot change set types: %s -> %s." % (self.set_type, s.set_type))

		if self.hosts:
			remove = self.hosts.difference(s.hosts)
			add = s.hosts.difference(self.hosts)
		elif self.nets:
			remove = self.nets.difference(s.nets)
			add = s.nets.difference(self.nets)
		else:
			remove = set()
			if s.hosts:
				add = s.hosts.copy()
			else:
				add = s.nets.copy()
		return (remove, add)
	def add(self, address):
		address = IPy.IP(address)
		if address.len() == 1:
			if self.nets:
				raise Exception("Cannot mix hosts and networks! ipset: %s, adding: %s" % (self.name,address))
			self.hosts.add(address)
		else:
			if self.hosts:
				raise Exception("Cannot mix hosts and networks! ipset: %s, adding: %s" % (self.name,address))
			self.nets.add(address)
	def __str__(self):
		return self.as_string()
	def as_string(self, name_suffix=None):
		name = self.name
		if name_suffix:
			name += name_suffix
		if self.hosts and self.nets:
			print "WARNING: set: %s hosts: %s nets: %s" % (self.name,self.hosts,self.nets)
			raise Exception("""You did something naughty -- you shouldn't be
				able to get hosts and networks in the same set (%s)""" % self.name)

		result = []

		if self.hosts:
			result.append("%s %s %s" % (IPSET_CREATE_OPT, name, IPSET_IPHASH_TYPE))
			for host in self.hosts:
				result.append("%s %s %s" % (IPSET_ADD_OPT, name,str(host)))
		if self.nets:
			result.append("%s %s %s" % (IPSET_CREATE_OPT, name, IPSET_NETHASH_TYPE))
			for net in self.nets:
				result.append("%s %s %s" % (IPSET_ADD_OPT,name,str(net)))
		return '\n'.join(result)

class ipset_list(object):
	def __init__(self, load_file=False):
		self.sets = []
		self.set_members = {}
		if load_file != False:
			self.load_file(load_file)
	def __getitem__(self, k):
		return self.set_members[k]
	def load_file(self, filename=None, chain=None):
		if filename:
			infile = open(filename)
		else:
			cmd = IPSET_SAVE_ALL
			if chain:
				cmd = IPSET_SAVE_SET % chain
			infile = os.popen(cmd)

		for line in infile:
			if line[0] == '#':
				continue
			options = line.split()
			if options[0] in [ '-N', 'create' ]:
				assert len(options) >= 3
				self.add_chain(name=options[1], set_type=options[2])
			elif options[0] in [ '-A', 'add' ]:
				assert len(options) == 3
				self.add(options[1], options[2])
	
	def add_chain(self, name, set_type=None):
		if name in self.set_members:
			raise Exception("Chain %s already created: %s" % (name,self.set_members[name]))
		self.set_members[name] = ipset(name, set_type)
		self.sets.append(name)

	def add(self, set_name, address, end_address=None):
		address = IPy.IP(address)
		if set_name not in self.set_members:
			set_type = IPSET_IPHASH_TYPE
			if len(address) > 1: # FIXME: technically, an IP object can hold a range
				set_type = IPSET_NETHASH_TYPE
			self.add_chain(set_name, set_type)
			
		if address.len() == 1:
			if end_address is None:
				end_address = address
			end_address = IPy.IP(end_address)
			a = IPy.IP(address)
			self.set_members[set_name].add(a)
			while a < end_address:
				a = IPy.IP(a.int() + 1)
				self.set_members[set_name].add(a)
		else:
			if end_address:
				raise Exception("Range containing a network? %s %s %s" % (set_name, address, end_address))
			self.set_members[set_name].add(address)
	def __str__(self):
		return self.as_string()
	def as_string(self, name_suffix = None):
		set_strs = []
		for k in self.sets:
			set_strs.append( self.set_members[k].as_string(name_suffix) )
		set_strs.append("COMMIT\n") # trailing \n is important...
		return '\n\n'.join(set_strs)

