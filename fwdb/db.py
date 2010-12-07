import types
import psycopg2
import re

# NOTE: endlines should never be allowed anywhere
valid = re.compile( r"^[a-zA-Z0-9 '!/@.,%\"=?\n<>()\\:#|_$\t-]+$" )
#address = re.compile( r"^([0-9]{1,3}\.){,3}[0-9]{1,3}(/[1-3]?[0-9])?$" )
address = re.compile( r"^(([0-9]{1,3}\.){3}[0-9]{1,3})|(([0-9]{1,3}\.){,3}[0-9]{1,3}/[1-3]?[0-9])$" )

table_re = re.compile(r"^[a-z_]+$")

numeric = re.compile( r"^[0-9]+$" )

_default = object()

def check_table_name(v):
	if table_re.match(v):
		return True
	raise Exception("Invalid table name: '%s'" % v)


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
		if type(v) == types.ListType:
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
		LEFT OUTER JOIN hosts_to_groups AS sh2g ON sh2g.gid = rules.src
		LEFT OUTER JOIN hosts AS src ON src.id = sh2g.hid
		LEFT OUTER JOIN ports AS sport ON sport.id = rules.sport
		LEFT OUTER JOIN hosts_to_groups AS dh2g ON dh2g.gid = rules.dst
		LEFT OUTER JOIN hosts AS dst ON dst.id = dh2g.hid
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
			FROM rule_stats GROUP BY rule) AS usage"""
	rule_enabled_fmt="""CASE WHEN rules.enabled = FALSE THEN '#:disabled: ' ELSE '' END
			|| CASE WHEN rules.expires < NOW() then '#:expired: ' ELSE '' END
			|| CASE WHEN rules.src IS NOT NULL and sh2g.gid IS NULL OR
			             rules.dst IS NOT NULL and dh2g.gid IS NULL THEN '#:broken_group: ' ELSE '' END\n"""
	rule_comment_fmt="""'# id:' || rules.id || ' ord:' || ord
		|| CASE WHEN sh2g.gid != sh2g.hid then ' from group:' || (SELECT name FROM hosts WHERE id=sh2g.gid) ELSE '' END
		|| CASE WHEN src.name IS NOT NULL then ' from ' || src.name ELSE '' END
		|| CASE WHEN dh2g.gid != dh2g.hid then ' to group:' || (SELECT name FROM hosts WHERE id=dh2g.gid) ELSE '' END
		|| CASE WHEN dst.name IS NOT NULL then ' to ' || dst.name ELSE '' END
		|| CASE WHEN for_user.name IS NOT NULL then ' for ' || for_user.name ELSE '' END
		|| CASE WHEN rules.description IS NOT NULL then ' - ' || rules.description ELSE '' END 
		|| CASE WHEN rules.expires IS NOT NULL then ' -- EXP:' || to_char(rules.expires, 'YYYY-MM-DD') ELSE '' END || E'\\n'\n"""
	rule_args_fmt = """'-A '||chain.name
		|| CASE WHEN rules.if_in IS NOT NULL then
			CASE WHEN if_in.is_bridged THEN ' -m physdev --physdev-in ' || if_in.name
			ELSE ' -i '||if_in.name END
		ELSE '' END
		|| CASE WHEN rules.if_out IS NOT NULL then
			CASE WHEN if_out.is_bridged THEN ' -m physdev --physdev-out ' || if_out.name
			ELSE ' -o '||if_out.name END
		ELSE '' END
		|| CASE WHEN proto.name IS NOT NULL then ' -p ' || proto.name ELSE '' END
		|| CASE WHEN src.host_end IS NOT NULL OR dst.host_end IS NOT NULL THEN ' -m iprange ' ELSE '' END
		|| CASE WHEN src.host_end IS NOT NULL THEN ' --src-range ' || host(src.host) || '-' || host(src.host_end) WHEN src.host IS NOT NULL then ' -s ' || src.host ELSE '' END
		|| CASE WHEN sport.endport IS NOT NULL then ' --sport ' || sport.port||':'||sport.endport WHEN sport.port IS NOT NULL then ' --sport ' || sport.port ELSE '' END
		|| CASE WHEN dst.host_end IS NOT NULL THEN ' --dst-range ' || host(dst.host) || '-' || host(dst.host_end) WHEN dst.host IS NOT NULL then ' -d '||dst.host ELSE '' END
		|| CASE WHEN dport.endport IS NOT NULL then ' --dport '||dport.port||':'||dport.endport WHEN dport.port IS NOT NULL then ' --dport '||dport.port ELSE '' END
		|| ' -j '||target.name
		|| CASE WHEN rules.additional IS NOT NULL THEN ' '||rules.additional ELSE '' END
		|| ' -m comment --comment "id:' || rules.id || ' src:' || COALESCE(src.id::VARCHAR,'NULL') || ' dst:' || COALESCE(dst.id::VARCHAR,'NULL') || '"'
		|| E'\\n'
		"""
	rule_cmd_fmt="""'%s -t ' || tbl.name || ' ' ||\n""" + rule_args_fmt
	rule_noiface_fmt="""''
		|| CASE WHEN rules.if_in IS NOT NULL then
			'<iface_in:'||pseudo_if_in.name||'> '
		ELSE '' END
		|| CASE WHEN rules.if_out IS NOT NULL then
			'<iface_out:'||pseudo_if_out.name||'> '
		ELSE '' END
		|| '%s -t ' || tbl.name 
		|| ' -A '||chain.name
		|| CASE WHEN proto.name IS NOT NULL then ' -p ' || proto.name ELSE '' END
		|| CASE WHEN src.host_end IS NOT NULL OR dst.host_end IS NOT NULL THEN ' -m iprange ' ELSE '' END
		|| CASE WHEN src.host_end IS NOT NULL THEN ' --src-range ' || host(src.host) || '-' || host(src.host_end) WHEN src.host IS NOT NULL then ' -s ' || src.host ELSE '' END
		|| CASE WHEN sport.endport IS NOT NULL then ' --sport ' || sport.port||':'||sport.endport WHEN sport.port IS NOT NULL then ' --sport ' || sport.port ELSE '' END
		|| CASE WHEN dst.host_end IS NOT NULL THEN ' --dst-range ' || host(dst.host) || '-' || host(dst.host_end) WHEN dst.host IS NOT NULL then ' -d '||dst.host ELSE '' END
		|| CASE WHEN dport.endport IS NOT NULL then ' --dport '||dport.port||':'||dport.endport WHEN dport.port IS NOT NULL then ' --dport '||dport.port ELSE '' END
		|| ' -j '||target.name
		|| CASE WHEN rules.additional IS NOT NULL THEN ' '||rules.additional ELSE '' END
		|| E'\\n'
		"""
	rule_restore_fmt = ' || '.join([ rule_enabled_fmt, rule_comment_fmt, rule_enabled_fmt, rule_args_fmt ])
	rule_full_fmt = ' || '.join([ rule_enabled_fmt, rule_comment_fmt, rule_enabled_fmt, rule_cmd_fmt ])
	rule_display_fmt = ' || '.join([ rule_enabled_fmt, rule_comment_fmt, rule_enabled_fmt, rule_noiface_fmt ])
	rule_order = 'ORDER BY CASE WHEN chain.builtin = TRUE THEN 1 ELSE 0 END,chain.name,rules.ord,rules.id,src.host,dst.host'
	#rule_valid_where="""(if_in.firewall_id = '$firewall_id' OR if_in.firewall_id IS NULL) AND (if_out.firewall_id = '$firewall_id' OR if_out.firewall_id IS NULL )"""

	def __init__( self, db=None ):
		if not db:
			db="dbname='fwdb' user='esk'"
		self.__conn = psycopg2.connect(db)
		self.__curs = self.__conn.cursor()
		# FIXME!
		self.uid=1
	def __del__( self ):
		self.__conn.close()

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

	def get_table(self, name, columns, whereclause=None, og=None, distinct=True):
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

		return self.execute_query(sql)
	
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
			if type(v) == types.ListType:
				where_items.append('%s IN %s' % (i, "(%s)" % ', '.join(v)) )
			elif is_address(v):
				where_items.append( self.host_ip_match(i,str(v)) )
			elif has_wildcard(v):
				where_items.append("%s like '%s'" % (i,str(v)) )
			else:
				where_items.append("%s = '%s'" % (i,str(v)) )
		return where_items
	
	def get_dict( self, table, columns, d=None, conj = ' AND ' ):
		where_items=[]
		if d:
			sql = 'SELECT %s FROM %s WHERE %s;' % (','.join(columns), table, conj.join(self.get_where(d)))
		else:
			sql = 'SELECT %s FROM %s;' % (','.join(columns), table)

		data=self.execute_query( sql )
		final = []
		for d in data:
			item={}
			for i in range(len(columns)):
				item[columns[i]]=d[i]
			final.append(item)

		return final

	def get_host_clause( self, fields, host, nulls=False, exact=True ):
			if is_address( host ):
				host_ids = [ i[0] for i in self.get_table( 'hosts', ['id'], self.host_ip_match('host', host, exact=exact) ) ]
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
			iptables='iptables', ipt_restore=False, table=False, target=None, fw_id=None, andwhere=None,
			expired=None, show_usage=False ):
		where_items = []
		if ipt_restore:
			use_fmt = self.rule_restore_fmt
		else:
			use_fmt = self.rule_display_fmt
		if expired is not None:
			if expired:
				where_items.append('rules.expires < NOW()')
			else:
				where_items.append('rules.expires > NOW()')
		if host:
			where_items.append(self.get_host_clause(['src','dst',], check_input_str(host)))
		if port:
			port = self.get_port_id( port )
			where_items.append('(rules.sport = %d OR rules.dport = %d)' % (port,port))
		if src:
			where_items.append(self.get_host_clause(['src',], check_input_str(src), nulls=False))
		if sport:
			sport = self.get_port_id( sport )
			where_items.append( 'rules.sport = %d' % int(sport) )
		if dst:
			where_items.append(self.get_host_clause(['dst',], dst, nulls=False))
		if dport:
			dport = self.get_port_id( dport )
			where_items.append( 'rules.dport = %d' % int(dport) )
		if chain:
			where_items.extend( self.get_where({'chain.name':check_input_str(chain)}) )
		if target:
			where_items.extend( self.get_where({'target.name':check_input_str(target)}) )
		if id:
			if type(id) == types.StringType:
				id = int(id)
			where_items.extend(self.get_where({'rules.id':id}))
		if table is not False:
			where_items.append( 'chain.tbl = %d' % int(table))
		if fw_id:
			if not ipt_restore:
				use_fmt = self.rule_full_fmt
			# FIXME: do we need to do more sanity checking on interfaces?
			where_items.append('(if_in.firewall_id = (SELECT id FROM firewalls WHERE name=\'%s\') or rules.if_in is NULL)' % fw_id)
			where_items.append('(if_out.firewall_id = (SELECT id FROM firewalls WHERE name=\'%s\') or rules.if_out is NULL)' % fw_id)
		if andwhere:
			where_items.append( andwhere )

		rule_join = self.rule_join

		if show_usage:
			rule_join = ' LEFT OUTER JOIN '.join([self.rule_join, self.usage_subq + ' ON rules.id = usage.rule'])
			use_fmt = ' || '.join([use_fmt, self.rule_enabled_fmt, "CASE WHEN packets1 IS NOT NULL THEN '# USAGE -- packets in 12 mo: ' || packets12 ||', 6 mo: '|| packets6 || ', 3 mo: ' || packets3 || ', 1 mo: '||packets1 || E'\\n' ELSE 'USAGE: nothing recorded' END"])

		if '%s' in use_fmt:
			use_fmt %= iptables

		return self.get_table( rule_join, [ use_fmt,], ' AND '.join(where_items), self.rule_order, distinct=False )
	
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
			sql = 'UPDATE %s SET %s WHERE %s;' % (table,', '.join(['%s = %s' % (fields[i],values[i]) for i in range(len(fields))]), where)
		else:
			sql = 'INSERT INTO %s(%s) VALUES (%s);' % (table,','.join(fields),','.join(values))
		self.execute_insert(sql)

	def add_user(self,name,email=None,a_number=None):
		# FIXME: Add some validation here
		user_d = {}
		user_d['name'] = name
		if email: user_d['email'] = email
		if a_number: user_d['a_number'] = a_number
		self.add_dict( 'users', user_d )

	def add_host(self,name,owner_name,address=None,endaddress=None,description=None, is_group=False, update=False, id=None):
		host = {}
		host['name'] = name
		if address: host['host'] = address
		if endaddress: host['host_end'] = endaddress
		host['owner'] = self.get_id_byname('users',owner_name)
		host['is_group']=is_group
		if description: host['description'] = description
		if update:
			self.add_dict( 'hosts', host, update=True, where='id = %s' % id )
		else:
			self.add_dict( 'hosts', host )

	def add_host_to_group( self, group_id, host_id=None, hostname=None ):
		if not host_id:
			host_id = self.get_id_byname( 'hosts', hostname )
		self.add_dict( 'hosts_to_groups', {'hid':host_id,'gid':group_id,} )

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


