#!/usr/bin/python

# arguments?
'''NOTICE: This code is not thread-safe.'''

# Import the XMLRPC Library for consuming the webservices
import sys
import os
import getpass
import cmd
import readline
import atexit
import datetime
import IPy

import db
import re

try:
	import DNS
	DNS.ParseResolvConf()
	have_dns = True
except:
	print "Failed to import DNS resolving library.  You may want to install python-dns."
	have_dns = False



if os.environ.has_key('USER'):
	my_username = os.environ['USER']
else:
	raise Exception("Need USER environment variable set.")

histfile = os.path.join( os.environ['HOME'], '.fwdb_history' )

class db_wrapper( object ):
	def __init__(self, db_str):
		import psycopg2
		self.__conn = psycopg2.connect(db_str)
		self.__curs = self.__conn.cursor()
	def execute_query(self, stmt):
		self.__curs.execute(stmt)
		return self.__curs.fetchall()

class FirewallCmd( cmd.Cmd ):	
	def __init__( self, dbname='testfwdb', ipam_interface=None ):
		self.field_checks = { 'src':self.check_host,
				'dst':self.check_host,
				'sport':self.check_port,
				'dport':self.check_port,
				'expires':self.check_None,
				}
		self.ipam = ipam_interface
		if have_dns:
			# We only want A records
			self.resolver = DNS.Request(qtype='A')

		if ipam_interface:
			try:
				self.ipamdb = db_wrapper("host='newdb1.ipam.usu.edu' dbname='prod_openipam'")
			except:
				print "You do not have direct access to the IPAM database."
				self.ipamdb = None
		self.prompt = '%s > ' % dbname
		# FIXME: we should catch ^C
		self.iface = db.db("dbname=%s host=newdb1.ipam.usu.edu" % dbname)
		cmd.Cmd.__init__( self )

		try:
			readline.read_history_file(histfile)
		except IOError:
			pass

		atexit.register(self.save_history, histfile)

	def save_history(self, histfile):
		readline.write_history_file(histfile)
	
	def resolve_name(self, name):
		if not have_dns:
			raise Exception('This feature requires the DNS module.')
		rslt = self.resolver.req(name)
		num = len(rslt.answers)
		if num < 1:
			raise Exception('%s did not resolve' % name)
		if num > 1:
			raise Exception('Multiple records for %s: %s'% (name,','.join([i['data'] for i in rslt.answers]),) )
		return rslt.answers[0]['data']

	def resolve_address(self, address):
		if not have_dns:
			raise Exception('This feature requires the DNS module.')
		address = IPy.IP(address)
		rslt = self.resolver.req(address.reverseName()[:-1], qtype='PTR')
		num = len(rslt.answers)
		if num < 1:
			raise Exception('%s did not resolve (no PTR)' % address)
		if num > 1:
			raise Exception('Multiple PTR records for %s: %s'% (address,','.join([i['data'] for i in rslt.answers]),) )
		return rslt.answers[0]['data']

	def ptr_match(self, name, address):
		ptr_name = self.resolve_address(address)
		a_address = self.resolve_name(name)
		if a_address != str(address):
			raise Exception('A record does not match (%s - %s != %s)' % (name, address, a_address) )
		if ptr_name != name:
			raise Exception('PTR record does not match (%s - %s != %s)' % (address, name, ptr_name) )
		return None

	def do_sql(self, arg):
		if arg.lower() in ['on','true']:
			self.iface.show_sql = True
		elif arg:
			self.iface.show_sql = False
		print self.iface.show_sql

	def do_check(self, arg):
		if not self.ipam: raise Exception('This feature requires ipam support and direct access to the ipam database.')
		if not self.ipamdb: raise Exception('This feature requires direct access to the openipam database.')

		hosts = self.iface.execute_query('SELECT id, name, host, host_end FROM hosts WHERE host IS NOT NULL AND masklen(host) > 25;')
		addr_list = []
		__one = IPy.IP('0.0.0.1')
		for i in hosts:
			id,name,host,host_end = i
			host = IPy.IP(host)
			if host.prefixlen() == 32:
				# do a reverse lookup, just for fun
				try:
					self.ptr_match(name, host)
				except Exception,e:
					print e, name, host
			if host_end:
				host_end = IPy.IP(host_end)
				while host <= host_end:
					addr_list.append(str(host))
					host += __one
				del host
			else:
				for i in host:
					addr_list.append(str(i))
		print addr_list
		bad_addresses = self.ipamdb.execute_query('SELECT address FROM addresses WHERE address in (\'%s\') AND mac IS NULL AND reserved IS FALSE ORDER BY address;' % ("', '".join(addr_list),) )
		# FIXME: show the 'bad' addresses and the hosts that they belong to in a pretty fashion
		#print bad_addresses
		final_addresses = []
		for address in bad_addresses:
			final_addresses.append( address[0] )
		print final_addresses
		for address in final_addresses:
			hosts = self.iface.execute_query("SELECT id, name, host, host_end, description FROM hosts WHERE ( host_end IS NOT NULL AND host <= '%s'::inet AND host_end >= '%s'::inet)" % (address,address))
			print 'address: %s, hosts: %s' % (address, hosts)

		where = [ "host <<= '%s' OR ( host_end IS NOT NULL AND host <= '%s' AND host_end >= '%s')" % (address,address,address,) for address in final_addresses ]
		hosts = self.iface.execute_query('SELECT id, name, host, host_end, description FROM hosts WHERE %s;' % ' OR '.join(where))
		for h in hosts:
			print h


	def do_EOF( self, arg ):
		sys.stdout.write('\nExiting on EOF\n\n')
		sys.exit()

	def do_save( self, arg ):
		( filename, cmd ) = arg.split(' ',1)
		output = open( filename.strip(), 'w' )
		old_stdout = os.dup(sys.stdout.fileno())
		os.dup2( output.fileno(), sys.stdout.fileno() )
		try:
			self.onecmd( cmd )
			os.dup2( old_stdout, sys.stdout.fileno() )
			output.close()
		except:
			os.dup2( old_stdout, sys.stdout.fileno() )
			output.close()
			raise


	def mkdict( self, line ):
		args = line.split()
		arg_len = len(args)
		if arg_len % 2:
			raise Exception('command requires an even number of arguments, got "%s" which has %s' % ( line, arg_len ) )
		filter = {}
		for i in range(arg_len/2):
			base=2*i
			filter[args[base]]=args[base+1]
		return filter

	def show_dicts( self, dicts, fields=None, prefix='', separator='\n' ):
		if not fields and dicts:
			fields = []
			for k in dicts[0].keys():
				fields.append( (k,k,) )
		maxlen=0
		for name,label in fields:
			if len(label) > maxlen:
				maxlen = len(label)
		fmt_str = '%%s%%%ds:\t%%s\n' % maxlen

		sys.stdout.write( separator )
		for dict in dicts:
			for name, label in fields:
				sys.stdout.write( fmt_str % ( prefix, label, dict[name] ) )
			sys.stdout.write( separator )
	
	def show_vals( self, fields, vals ):
		lines = []
		num_fields = len(fields)
		maxlen = [0 for i in range(num_fields)]
		for j in vals:
			for i in range(num_fields):
				jlen = len(str(j[i]))
				if jlen > maxlen[i]: maxlen[i] = jlen
		for val in vals:
			line = []
			for i in range(num_fields):
				line.append( '%%%ds: %%%ds' % (len(fields[i]),maxlen[i],) % (fields[i],val[i],) )
			lines.append( '   '.join(line ) )

		print '\n'.join(lines)

	def mkdict_completion( self, completion_list, text, line, begidx, endidx ):
		possible = []
		text_len = len(text)
		l = len(line[:begidx].split())
		if not l%2:
			return []
		for i in completion_list:
			if i[:text_len] == text:
				possible.append( i + ' ' )
		return possible

	def list_completer( self, completion_list, text, state ):
		possible = []
		text_len = len(text)

		for i in completion_list:
			if i[:text_len] == text:
				possible.append( i )
		if len(possible) > state:
			return possible[state]
		return None

	def emptyline( self ):
		pass

	def complete_update( self, *args, **kwargs ):
		return self.mkdict_completion( ['rule','chain','host','port','user',], *args, **kwargs )

	def complete_add( self, *args, **kwargs ):
		return self.mkdict_completion( ['rule','chain','host','port','user','group'], *args, **kwargs )

	def _complete_show( self, cmd, text, line, begidx, endidx ):
		subcmds = { 
				'rule':None,
				'chain':('chains',['name',]),
				'host':('hosts',['name',]),
				'port':('ports',['name',]),
				'user':('users',['name',]),
				'interface':('interfaces',['name',]),
				'real_interface':('real_interfaces',['name',]),
				'group':('hosts',['name',]),
			}
		rule_fields = [ 'id', 'src', 'sport', 'dst', 'dport', 'host', 'chain', ]
		cmd_len = len(cmd)+1
		new = line[cmd_len:].lstrip()
		args = new.split()
		if len(args) > 1 or (new and new[-1] == ' '):
			subcmd = args[0].strip()
			if subcmds.has_key(subcmd):
				strip = len(subcmd)
				new = new[strip:].lstrip()
				new_pos = line.rfind(new)
				match_strip = begidx - new_pos
				complete_info = subcmds[ subcmd ]
				if complete_info:
					complete_list = [ i[0] for i in self.iface.get_table(*complete_info) ]
					# find the ones that match
					match_list = []
					new_len = len(new)
					for i in complete_list:
						if new == i[:new_len]:
							match_list.append( i[match_strip:] )
					return match_list
				else:
					# This is the 'rule' case
					if cmd == 'del':
						return []
					return self.mkdict_completion( rule_fields, text, line[cmd_len:], begidx-cmd_len, endidx-cmd_len )
		else:
			matches = []
			tlen = len(text)
			for i in subcmds.keys():
				if i[:tlen] == text:
					matches.append(i + ' ')
			return matches
	def complete_show( self, *args, **kw):
		return self._complete_show( 'show', *args, **kw )

	def complete_del(self, *args, **kw):
		return self._complete_show( 'del', *args, **kw )
	
	def do_del( self, arg ):
		(subcmd, subarg) = arg.split(' ',1)
		if subcmd == 'user':
			fields = ['id','name','a_number','email',]
			where = "users.name = '%s'" % db.check_input_str( subarg )
			vals = self.iface.get_table('users',fields,where)
			self.show_vals(fields, vals)
			if not vals:
				print 'No match'
				return
			if self.get_bool_from_user('Delete this user'):
				self.iface.del_table('users',where)

		if subcmd == 'chain':
			fields = ['chains.id','chains.name','tables.name','chains.builtin','chains.description',]
			frm = 'chains LEFT OUTER JOIN tables ON chains.tbl = tables.id'
			where = None
			where = "chains.name = '%s'" % db.check_input_str( subarg )
			vals = self.iface.get_table(frm,fields,where)
			self.show_vals(fields, vals)
			if not vals:
				print 'No match'
				return
			if self.get_bool_from_user('Delete chain(s)'):
				self.iface.del_table('chains',where)
		if subcmd == 'host':
			fields = ['hosts.id','hosts.name','hosts.host','users.name','hosts.description',]
			frm = 'hosts LEFT OUTER JOIN users ON hosts.owner = users.id'
			where = False
			if subarg: where = "hosts.name = '%s'" % db.check_input_str( subarg )
			vals = self.iface.get_table(frm,fields,where)
			self.show_vals(fields, vals)
			if not vals:
				print 'No match'
				return
			id_list = [ v[0] for v in vals ]
			if len(id_list) == 1:
				h2g_where = "hosts_to_groups.gid = '%s'" % id_list[0]
			else:
				raise Exception('delete them one at a time, please')
			if self.get_bool_from_user('Delete host'):
				self.iface.del_table('hosts_to_groups',h2g_where )
				self.iface.del_table('hosts',where)

		if subcmd == 'port':
			fields = ['id','name','port','endport','description',]
			if not subarg:
				raise Exception('must specify port name')
			id = self.iface.get_port_id(subarg.strip())
			where = 'id = %s' % id
			vals = self.iface.get_table('ports',fields,where)
			self.show_vals(fields, vals)
			if not vals:
				print 'No match'
				return
			if self.get_bool_from_user('Delete port'):
				self.iface.del_table('ports',where)

		if subcmd == 'rule':
			subarg = map(int, subarg.split())
			#subarg = int(subarg)
			rules = self.iface.get_rules( id=subarg, show_usage=True )
			if not rules:
				print 'No match'
				return
			print '\n'.join( [i[0] for i in rules] )
			if self.get_bool_from_user('Delete rule'):
				where = ' AND '.join(self.iface.get_where({ 'rules.id': subarg }))
				self.iface.del_table('rules',where)
		
	def do_disable( self, arg ):
		ids = arg.strip().split()
		self.iface.disable_rule(ids)
	
	def do_enable( self, arg ):
		ids = arg.strip().split()
		self.iface.enable_rule(ids)
	
	def do_add( self, arg ):
		self.add_record( arg, update=False )

	def do_copy( self, arg ):
		args = arg.split()
		if len(args) != 2:
			print "expected 2 arguments, got %s" % args
			return
		type,id = args
		if type == 'rule':
			columns = [
					('rules.description','description',),
					('for_user.name','created_for_name',),
					('tbl.name','table_name',),
					('chain.name','chain_name',),
					('pseudo_if_in.name','if_in',),
					('pseudo_if_out.name','if_out',),
					('proto.name','proto',),
					('(SELECT name FROM hosts WHERE id=rules.src)','src',),
					('sport.name','sport',),
					('(SELECT name FROM hosts WHERE id=rules.dst)','dst',),
					('dport.name','dport',),
					('target.name','target_name',),
					('rules.ord','ord',),
					('rules.additional','additional',),
				]

			rule = self.iface.get_table(self.iface.rule_join, [i[0] for i in columns], 'rules.id = %s' % int(id))
			if len(rule) > 1:
				raise Exception('rule id %s is not unique' % id)
			if not rule:
				raise Exception('rule id %s not found' % id)
			rule = rule[0]
			defaults = { 'expires':(datetime.datetime.today() + datetime.timedelta(365)).strftime('%Y-%m-%d'), }
			for i in range(len(columns)):
				defaults[columns[i][1]] = rule[i]

			self.add_rule(defaults=defaults,extended=True)

	def do_update( self, arg ):
		self.add_record( arg, update=True )
	
	def do_extend( self, arg ):
		args = arg.split()
		if len(args) < 2:
			print "expected 2 or more arguments, got %s" % args
			return
		_type = args[0]

		if _type == 'rule':
			set_to = "expires + interval '1 year'"
			if args[1].strip()[0] not in '1234567890':
				time_arg = args[1].strip()
				del args[1]
				if time_arg[0] in '+-':
					set_to = "expires + interval '%s days'" % int(time_arg) # should be safe
				elif time_arg[0] == '=':
					set_to = time_arg[1:]
					if re.search(r'[^0-9-]',set_to):
						raise Exception("Invalid time argument: %s" % set_to)
					set_to = "'%s'" % set_to
				else:
					print 'Bad argument: %s' % time_arg
					return
			ids = map(int,args[1:])
			where = self.iface.get_where({'id':ids})
			sql = 'UPDATE rules SET expires = %s WHERE %s' % (set_to,' AND '.join(where))
			self.show_rules(ids=ids)
			print '\nChange: %s' % set_to
			if self.get_bool_from_user('Update these rules', False):
				self.iface.execute_insert(sql)
	
	def show_rules( self, ids ):
		rules = self.iface.get_rules(show_usage=True, id=ids)
		print '\n'.join( [i[0] for i in rules] )

	def check_host( self, name ):
		if name=='':
			return name
		if name=='None':
			return None
		id = None
		try:
			id = self.iface.get_host_id(name)
		except:
			print '\tHost not found.'
			if not self.get_bool_from_user('\tadd new host', True):
				return name
			else:
				if db.address.match(name):
					dflt = {'address':name}
				else:
					dflt = {'name':name}
				host = self.add_host(defaults=dflt)
				name = host['name']
		return name

	def check_port( self, port ):
		if port == '':
			return port
		if port == 'None':
			return None
		id = None
		try:
			id = self.iface.get_port_id(port)
		except:
			print '\tPort not found.'
			if not self.get_bool_from_user('\tadd new port', True):
				return name
			else:
				port = self.add_port()
				port = port['name']
		return port

	def check_user( self, name ):
		try:
			self.iface.get_id_byname('users',vals[i])
		except:
			if self.get_bool_from_user('add user', True):
				user = self.add_user(defaults={'name':name})
				return user['name']
		return name

	def check_None( self, value ):
		if value == 'None':
			return None
		return value

	def add_record( self, arg, update ):
		args = arg.strip().split(' ',2)
		#if ( len(args) != 1 and update == False ) or ( len(args) != 2 and update == True ):
		#	print 'invalid syntax (arg: %s, len %s)'% (arg,len(args))
		#	return
		if len(args) == 2:
			id_arg = args[1].strip()
		if args[0] == 'rule':
			#if update: raise Exception("Not implemented.")

			if update:
				self.add_rule(args, update=id_arg, extended=True)
			elif self.get_bool_from_user('Use extended format'):
				self.add_rule(args, extended=True)
			else:
				self.add_rule(args)
		if args[0] == 'chain':
			fields = [
					('name',),
					('table_name','table',),
					('description',),
				]
			if update: raise Exception('Not implemented.')
			else:
				defaults = { 'table_name':'filter', }
			complete_vals = { 'table_name': [i[0] for i in self.iface.get_table( 'tables',['name',] )] }
			if len(args) == 2:
				defaults['name'] = args[1].strip()
			if len(args) > 2:
				raise Exception('* chain: chould not parse args: %s' % args)
			vals = self.get_from_user( fields, defaults=defaults, complete=complete_vals )
			if vals:
				self.iface.add_chain( **vals )

		if args[0] == 'interface':
			fields = [
					('name',),
					('description',),
				]
			if update: raise Exception('Not implemented.')
			vals = self.get_from_user( fields )
			if vals:
				self.iface.add_dict( 'interfaces', vals )

		if args[0] == 'real_interface':
			fields = [
					('name',),
					('pseudo','pseudo interface name',),
					('is_bridged','interface is a bridge member',),
					('firewall',),
					('description',),
				]
			defaults = { 'is_bridged':True }
			complete_vals = {
					'pseudo': [i[0] for i in self.iface.get_table( 'interfaces',['name',] )],
					'firewall': [i[0] for i in self.iface.get_table( 'firewalls',['name',] )],
					}
			if update: raise Exception('Not implemented.')
			vals = self.get_from_user( fields, defaults=defaults, complete=complete_vals )
			if vals['is_pridged'][0] in ['f','F','n','N']:
				vals['is_bridged'] = False
			else:
				vals['is_bridged'] = True
			vals['pseudo'] = self.iface.get_id_byname('interfaces',vals['pseudo'])
			if vals:
				self.iface.add_dict( 'real_interfaces', vals )

		if args[0] == 'firewall':
			if update: raise Exception('Not implemented.')
			fields = [
					('name',),
				]
			if vals:
				self.iface.add_dict( 'firewalls', vals )

		if args[0] == 'pattern':
			pass

		if args[0] == 'host':
			if update:
				self.add_host(update=id_arg)
			else:
				dflt = {}
				if len(args) == 2:
					arg=args[1].strip()
					if db.address.match(arg):
						dflt['address'] = arg
					else:
						dflt['name'] = arg
				elif len(args) > 2:
					raise Exception("add_host() could not handle args: %s" % args )
				self.add_host( defaults = dflt )

		if args[0] == 'group':
			fields = [
					('name',),
					('owner_name','Name of owner',),
					('description',),
				]
			if update:
				current = self.iface.get_dict( 'hosts', self.iface.columns['hosts'], {'name':id_arg} )
				if len(current) < 1:
					raise Exception('No rule with name %s found.' % str(id_arg))
				assert len(current) == 1
				current=current[0]
				defaults['name'] = current['name']
				defaults['owner_name'] = self.iface.get_table( 'users', ['name',], 'id = %s' % current['owner'] )[0][0]
				defaults['description'] = current['description']
				# FIXME - handle group membership elsewhere?

			else:
				defaults={'address':None,'endaddress':None,}
			complete_vals = { 'owner_name': [i[0] for i in self.iface.get_table( 'users',['name',] )] }
			vals = self.get_from_user( fields, complete=complete_vals, defaults=defaults )
			if vals:
				if update:
					self.iface.add_host( update=True, is_group=True, id=id_arg, **vals )
				else:
					self.iface.add_host( is_group=True, **vals )


		if args[0] == 'port':
			self.add_port()

		if args[0] == 'user':
			if update: raise Exception('Not implemented.')
			fields = [
					('name',),
					('a_number','A-Number of user',),
					('email','email address',),
				]
			vals = self.get_from_user( fields )
			if vals:
				self.iface.add_user( **vals )

	def add_rule( self, args=None, defaults=None, update=None, extended=False ):
		if defaults is None:
			defaults = {
					'table_name':'filter',
					'if_in':None, 'if_out':None,
					'created_for_name':None,
					'proto':None,
					'src':None, 'sport':None,
					'dst':None, 'dport':None,
					'target_name':'ACCEPT',	'ord':5000,
					'expires':(datetime.datetime.today() + datetime.timedelta(365)).strftime('%Y-%m-%d'),
					'additional':None,
					#'created_for': 'admin',
					}
		if update is not None:
			id_arg = update
			update=True

		if extended:
			fields = [
					('description',),
					('created_for_name','Person rule is for',),
					('table_name','table (-t)',),
					('chain_name','chain (-A, -I)',),
					('if_in','in interface (-i)',),
					('if_out','out interface (-o)',),
					('proto','proto (-p)',),
					('src','source host (-s)',),
					('sport','source port (--sport)',),
					('dst','dest host (-d)',),
					('dport','dest port (--dport)',),
					('target_name','target (-j)',),
					('ord','ordering value (I recommend 0-9999)',),
					('expires','expiration date (YYYY-MM-DD)',),
					('additional','additional iptables arguments',),
				]
		else:
			fields = [
					('description',),
					('created_for_name','Person rule is for',),
					('chain_name','chain (-A, -I)',),
					('src','source host (-s)',),
					('dst','dest host (-d)',),
					('target_name','target (-j)',),
					('ord','ordering value (I recommend 0-9999)',),
					('expires','expiration date (YYYY-MM-DD)',),
				]
		if update:
			defaults = {}
			current = self.iface.get_dict( 'rules', self.iface.columns['rules'], {'id':id_arg,} )
			if len(current) < 1:
				raise Exception('No rule with id %s found.' % int(args[1].strip()))
			assert len(current) == 1
			current=current[0]
			defaults['created_for_name'] = self.iface.get_table( 'users', ['name',], 'id = %s' % current['created_for'] )[0][0]
			if current['chain']:
				chain = self.iface.get_table( 'chains LEFT OUTER JOIN tables ON chains.tbl=tables.id', ['chains.name','tables.name',], 'chains.id = %s' % current['chain'] )[0]
				defaults['chain_name'] = chain[0]
				defaults['table_name'] = chain[1]
			if current['if_in']: defaults['if_in'] = self.iface.get_table( 'interfaces', ['name',], 'id = %s' % current['if_in'] )[0][0]
			if current['if_out']: defaults['if_out'] = self.iface.get_table( 'interfaces', ['name',], 'id = %s' % current['if_out'] )[0][0]
			if current['proto']: defaults['proto'] = self.iface.get_table( 'protos', ['name',], 'id = %s' % current['proto'] )[0][0]
			if current['src']: defaults['src'] = self.iface.get_table( 'hosts', ['name',], 'id = %s' % current['src'] )[0][0]
			if current['sport']: defaults['sport'] = self.iface.get_table( 'ports', ['name',], 'id = %s' % current['sport'] )[0][0]
			if current['dst']: defaults['dst'] = self.iface.get_table( 'hosts', ['name',], 'id = %s' % current['dst'] )[0][0]
			if current['dport']: defaults['dport'] = self.iface.get_table( 'ports', ['name',], 'id = %s' % current['dport'] )[0][0]
			if current['target']: defaults['target_name'] = self.iface.get_table( 'chains', ['name',], 'id = %s' % current['target'] )[0][0]
			if current['description']: defaults['description'] = current['description']
			if current['ord']: defaults['ord'] = current['ord']
			if current['expires']: defaults['expires'] = current['expires']
			if current['additional']: defaults['additional'] = current['additional']

		interfaces = [i[0] for i in self.iface.get_table( 'interfaces',['name',] )]
		chains = [i[0] for i in self.iface.get_table( 'chains',['name',] )]
		hosts = [i[0] for i in self.iface.get_table( 'hosts',['name',] )]
		ports = [i[0] for i in self.iface.get_table( 'ports',['name',] )]
		complete_vals = { 'table_name': [i[0] for i in self.iface.get_table( 'tables',['name',] )],
				  'chain_name': chains,
				  'if_in': interfaces, 'if_out': interfaces,
				  'proto': [i[0] for i in self.iface.get_table( 'protos',['name',] )],
				  'src': hosts, 'dst': hosts,
				  'sport': ports, 'dport': ports,
				  'target_name': chains,
				  'created_for_name': [i[0] for i in self.iface.get_table( 'users',['name',] )],
				  }
		vals = self.get_from_user( fields, defaults=defaults, complete=complete_vals, check_fields=True )
		if vals:
			if update:
				id = int(args[1])
				self.iface.add_rule( update=True, id=id, **vals )
			else:
				self.iface.add_rule( **vals )
				id = self.iface.get_last_id('rules')
			self.onecmd( "show rule id %s" % id )


	def add_host( self, args=None, defaults=None, update=None ):
		if update is not None:
			id_arg = update
			update=True
		fields = [
				('name',),
				('address','Address or CIDR',),
				('endaddress','End address (if range)',),
				('owner_name','Name of owner',),
				('description',),
			]
		if not defaults:
			defaults = {}
		if have_dns and (defaults.has_key('name')) and defaults['name'].find('.') >= 0:
			try:
				addr = self.resolve_name(defaults['name'])
				self.ptr_match(defaults['name'], addr)
				if not defaults.has_key('address'): defaults['address'] = addr
				else:
					if not defaults['address'] == addr:
						raise Exception('default address given (%s) does not match A record (%s)'% (defaults['address'],addr,) )
			except Exception,e:
				print e
		if have_dns and defaults.has_key('address') and not defaults.has_key('name'):
			try:
				hostname = self.resolve_address(defaults['address'])
				self.ptr_match(hostname,defaults['address'])
				defaults['name'] = hostname
			except Exception,e:
				print e
		if self.ipam and self.get_bool_from_user('get data from ipam', True):
			if defaults.has_key('name'):
				name = defaults['name']
			else:
				name = raw_input('hostname in ipam: ')
			hosts = self.ipam.get_hosts(hostname=name)
			assert len(hosts) == 1
			host = hosts[0]
			addresses = self.ipam.get_addresses(mac=host['mac'])
			if not addresses:
				raise Exception('host is not static')
			if len(addresses) > 1:
				address = self.get_choice_from_user( 'which address', [ i['address'] for i in addresses ] )
			else:
				address = addresses[0]['address']
			if not address:
				raise Exception('invalid address')
			defaults['name'] = host['hostname']
			defaults['address'] = address

		if update is not None:
			current = self.iface.get_dict( 'hosts', self.iface.columns['hosts'], {'id':id_arg} )
			if len(current) < 1:
				raise Exception('No rule with id %s found.' % int(args[1].strip()))
			assert len(current) == 1
			current=current[0]
			defaults['name'] = current['name']
			defaults['owner_name'] = self.iface.get_table( 'users', ['name',], 'id = %s' % current['owner'] )[0][0]
			defaults['address'] = current['host']
			defaults['endaddress'] = current['host_end']
			defaults['description'] = current['description']
		else:
			if not defaults.has_key('endaddress'):
				defaults['endaddress'] = None
		complete_vals = { 'owner_name': [i[0] for i in self.iface.get_table( 'users',['name',] )] }
		vals = self.get_from_user( fields, complete=complete_vals, defaults=defaults )
		if vals:
			if update:
				self.iface.add_host( update=True, id=id_arg, **vals )
			else:
				self.iface.add_host( **vals )
		# FIXME: we should query for the new host and return the full record
		#id = self.iface.get_host_id( vals['host']) ...
		return vals

	def add_port( self, defaults=None, update=None ):
		fields = [
				('name',),
				('port','port',),
				('endport','end port (if range)',),
				('description',),
			]
		if not defaults:
			defaults = {}
		if not defaults.has_key('endport'):
			defaults['endport'] = None
		vals = self.get_from_user( fields, defaults=defaults )
		if vals:
			self.iface.add_port( **vals )
		return vals

	def do_group( self, arg ):
		current = self.iface.get_dict( 'hosts', self.iface.columns['hosts'], {'name':arg.strip()} )
		self.show_dicts(current,[('id','id',),('name','name',),('description','description',),] )
		current_name = current[0]['name']
		current_id = current[0]['id']
		prompt = '  group:%s> ' % current_name
		# FIXME: set autocomplete fcn

		completion_list = []

		def _completer( *args, **kw ):
			if not completion_list:
				return []
			return self.list_completer(completion_list, *args, **kw)

		old_completer = readline.get_completer()
		old_delims = readline.get_completer_delims()
		readline.set_completer( _completer )
		readline.set_completer_delims( '' )

		valid_hostnames = [ i[0] for i in self.iface.get_table('hosts',['name'],whereclause='is_group=FALSE') ]

		next = '?___'
		while next.strip():
			try:
				if next[0] == '?':
					hosts = self.iface.get_dict( 'hosts_to_groups join hosts on hosts_to_groups.hid = hosts.id',
						['hosts.name','hosts.host','hosts.host_end',],
						{'hosts_to_groups.gid':current_id,}
						)
					self.show_dicts(hosts,[('hosts.name','name',),('hosts.host','address',),('hosts.host_end','end address (if range)',),] )
					sys.stdout.write('Enter hostname to add or -hostname to remove, ? to list, or a blank line when finished.\n')
					completion_list = [ '-' + h['hosts.name'] for h in hosts ]
					completion_list.extend(valid_hostnames)
					completion_list.append('?')
				elif next[0] == '-':
					self.iface.del_host_to_group( host_id=self.iface.get_host_id(next[1:]), group_id=current_id )
				else:
					id = self.iface.get_host_id(self.check_host(next))
					self.iface.add_host_to_group( host_id=id, group_id=current_id )

			except db.NotFound,e:
				print repr(e)
			try:
				next = raw_input(prompt)
				if next.strip():
					self.remove_last()
			except EOFError,e:
				print '^D'
				break

		readline.set_completer_delims( old_delims )
		readline.set_completer(old_completer)

	def do_show( self, arg ):
		args = arg.strip().split(' ',1)
		subcmd = args[0]
		subarg = None
		if len(args) > 1:
			subarg = args[1]

		argc = len(args)

		if subcmd == 'user':
			fields = ['id','name','a_number','email',]
			where = None
			if subarg: where = "users.name = '%s'" % db.check_input_str( subarg )
			vals = self.iface.get_table('users',fields,where)
			self.show_vals(fields, vals)
		if subcmd == 'chain':
			fields = ['chains.id','chains.name','tables.name','chains.builtin','chains.description',]
			frm = 'chains LEFT OUTER JOIN tables ON chains.tbl = tables.id'
			where = None
			if subarg: where = "chains.name like '%s'" % db.check_input_str( subarg )
			vals = self.iface.get_table(frm,fields,where)
			self.show_vals(fields, vals)
		if subcmd == 'host':
			fields = ['hosts.id','hosts.name','hosts.host','hosts.host_end','users.name','hosts.description',]
			groupfields = ['hosts.id','hosts.name','users.name','hosts.description','hosts_to_groups.hid']
			grouplabels = ['id','name','users.name','description','member id']
			frm = 'hosts LEFT OUTER JOIN users ON hosts.owner = users.id'
			where = 'hosts.is_group = FALSE'
			if subarg:
				if db.is_address(subarg):
					address = db.check_input_str( subarg )
					where += " AND ((hosts.host >>= '%(address)s' AND hosts.host_end IS NULL) OR (hosts.host <= '%(address)s' AND hosts.host_end >= '%(address)s'))" % locals()
				else:
					where += " AND hosts.name like '%s'" % db.check_input_str( subarg )
			vals = self.iface.get_table(frm,fields,where)
			ids = [ i[0] for i in vals ]
			groupvals = None
			if ids:
				groupvals = self.iface.get_table(frm + ' JOIN hosts_to_groups ON hosts.id = hosts_to_groups.gid AND hosts.is_group=TRUE', groupfields, ' AND '.join(self.iface.get_where({'hosts_to_groups.hid':ids,})) )
			print "Host entries:"
			self.show_vals(fields, vals)
			if groupvals:
				print "\nGroup entries:"
				self.show_vals(grouplabels, groupvals)

		if subcmd == 'group':
			fields = ['hosts.id','hosts.name','hosts.host','hosts.host_end','users.name','hosts.description',]
			frm = 'hosts LEFT OUTER JOIN users ON hosts.owner = users.id'
			where = 'hosts.is_group = TRUE'
			if subarg: where += " AND hosts.name like '%s'" % db.check_input_str( subarg )
			vals = self.iface.get_table(frm,fields,where)
			self.show_vals(fields, vals)
		if subcmd == 'port':
			fields = ['id','name','port','endport','description',]
			where = None
			if subarg:
				id = int(self.iface.get_port_id(subarg))
				where = "ports.id = %s" % id
			vals = self.iface.get_table('ports',fields,where)
			self.show_vals(fields, vals)
		if subcmd == 'interface':
			fields = ['id','name','description',]
			where = None
			#if subarg: where = "ports.name = '%s'" % db.check_input_str( subarg )
			vals = self.iface.get_table('interfaces',fields,where)
			self.show_vals(fields, vals)
		if subcmd == 'real_interface':
			fields = ['real.id','pseudo.name','real.name','pseudo.description','real.firewall_id',]
			where = None
			#if subarg: where = "ports.name = '%s'" % db.check_input_str( subarg )
			vals = self.iface.get_table('real_interfaces as real join interfaces as pseudo on real.pseudo = pseudo.id',fields,where)
			self.show_vals(fields, vals)
		if subcmd == 'rule':
			if subarg:
				args = self.mkdict(arg[5:])
				rules = self.iface.get_rules(show_usage=True, **args)
			else:
				rules = self.iface.get_rules(show_usage=True)

			print '\n'.join( [i[0] for i in rules] )

	def do_sync( self, arg ):
		firewall_hosts = self.iface.get_dict('firewalls',['id', 'name',])
		command = "ssh -t root@%(firewall)s /root/fwdb/update.py -u '%(username)s' -f '%(firewall)s'"
		cmd_values = {'username': my_username}
		if arg.strip():
			specific = arg.strip()
			cmd_values['firewall'] = specific
			os.system( command % cmd_values )
			return
			
		for i in firewall_hosts:
			if self.get_bool_from_user('sync %s' % i['name'], False):
				cmd_values['firewall'] = i['name']
				cmd = command % cmd_values
				print cmd
				os.system( cmd)

	def get_choice_from_user( self, prompt, list ):
		fmt = '%s: '
		for i in range(len(list)):
			print '\t%3s: %s' % ( i, list[i] )

		response = raw_input( fmt % prompt )
		r = response.strip().lower()
		if response:
			self.remove_last()
		if r:
			return list[int(r)]
		return None

	def get_bool_from_user( self, prompt, default=False ):
		if default:
			fmt = '%s [Y/n]: '
		else:
			fmt = '%s [y/N]: '
		response = raw_input( fmt % prompt )
		r = response.strip().lower()
		if response:
			self.remove_last()
		if r == 'y':
			return True
		if r == 'n':
			return False
		return default

	def remove_last( self ):
		readline.remove_history_item(readline.get_current_history_length() - 1)

	def get_from_user( self, input_fields, defaults = None, complete = None, check_fields = False ):
		completion_list = None

		if not complete:
			complete={}

		def _completer( *args, **kw ):
			if not completion_list:
				return []
			return self.list_completer(completion_list, *args, **kw)
		
		if defaults:
			input = defaults.copy()
		else:
			input = {}
		maxlen = 0
		fields = []
		for i in input_fields:
			if len(i) == 1:
				fields.append( ( i[0], i[0] ) )
			elif len(i) == 2:
				fields.append( ( i[0], i[1] ) )
			else:
				raise Exception( 'Invalid input_fields: %s' % str(i) )

		old_completer = readline.get_completer()
		old_delims = readline.get_completer_delims()
		readline.set_completer( _completer )
		readline.set_completer_delims( '' )

		for name, prompt in fields:
			if len(prompt) > maxlen:
				maxlen = len(prompt)
		#fmt = '%%%ds: ' % maxlen # this is going to be too much work, since the length will change below
		fmt = '%s [%s]: '
		accept = False
		while not accept:
			for name, prompt in fields:
				default = ''
				if complete.has_key(name):
					completion_list = complete[name]
				else:
					completion_list = None
				if input.has_key(name):
					default=input[name]

				i = raw_input( fmt % (prompt,default) )
				if i:
					self.remove_last()
				if i.strip():
					value=i.strip()
					if check_fields and self.field_checks.has_key(name):
						value = self.field_checks[name](value)
					input[name] = value
			sys.stdout.write('\n*********\nPlease check your values:\n')
			for name, prompt in fields:
				if input.has_key(name):
					sys.stdout.write('\t%s: %s\n' % (prompt , input[name] ) )
			v = self.get_bool_from_user( 'verify change', default=False )
			if v:
				accept = True
			else:
				sys.stdout.write('Change not accepted.\n')
			if not accept:
				c = self.get_bool_from_user( 'Try again', default=True )
				if not c:
					sys.stdout.write('Change aborted.\n')
					readline.set_completer_delims( old_delims )
					readline.set_completer(old_completer)
					return None
		readline.set_completer_delims( old_delims )
		readline.set_completer(old_completer)
		return input
	
def print_error():
	import traceback
	traceback.print_exc()

if __name__ == '__main__':
	#if len( sys.argv ) != 2:
	#	print "Usage:\n\t %s URL\n\t\t where URL is of the form https://url.of.server:8443/api/" % sys.argv[0]
	#	exit( 1 )
	#url = str( sys.argv[1] )
	#print 'Connecting to url %s' % url

	#sys.stdout.write('\nUsername: ')
	#username = sys.stdin.readline().strip()
	#passwd = getpass.getpass('Password: ')
	#sys.stdout.write('\n')
	
	if len(sys.argv) > 1:
		dbname = sys.argv[1]
	else:
		raise Exception('Usage: %s <dbname> [non-interactive command]' % sys.argv[0])

	ipam_interface = None

	disabled_foo="""x = raw_input('use ipam support [y/N]: ')
	if x and ( x[0] in ['y','Y'] ):
		from openipam_xmlrpcclient import CookieAuthXMLRPCSafeTransport
		import xmlrpclib
		class XMLRPCInterface(object):
			def __init__( self, username, password, url='https://127.0.0.1:8443/api/' ):
				# We don't want to store username/password here...
				self.__url = url
				self.__user = username
				self.__pass = password
				ssl = True
				if url[:5] == 'http:':
					ssl = False
				self.ipam = xmlrpclib.ServerProxy(self.__url,
						transport=CookieAuthXMLRPCSafeTransport(ssl=ssl),
						allow_none=True)
				#self.ipam.login( self.__user, self.__pass )

			def __getattr__( self, name ):
				# need a lock to be thread-safe
				self.__called_fcn = name
				return self.make_call

			def make_call( self, *args, **kwargs ):
				try:
					if not self.ipam.have_session():
						print 'Logging in'
						self.ipam.login( self.__user, self.__pass )

				except Exception, e:
					print e
					print 'Something went wrong, logging in again'
					self.ipam.login( self.__user, self.__pass )
				if self.__called_fcn[:2] == '__':
					raise AttributeError()
				fcn = getattr( self.ipam, self.__called_fcn )
				del self.__called_fcn
				if args:
					raise Exception('Fix XMLRPCInterface.make_call')
				val = fcn( kwargs )
				return val

		username = raw_input('username: ')
		password = getpass.getpass('password: ')
		ipam_interface = XMLRPCInterface( username=username, password=password, url='https://xmlrpc.ipam.usu.edu:8443/api/' )
	"""

	cli = FirewallCmd( dbname=dbname, ipam_interface = ipam_interface )

	if len(sys.argv) > 2:
		cli.onecmd(' '.join(sys.argv[2:]))
		sys.exit()

	while True:
		try:
			cli.cmdloop()
		except KeyboardInterrupt:
			print
		except SystemExit:
			del cli
			raise
		except Exception, e:
			print_error()

	del cli


