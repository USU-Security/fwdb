#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import os
import sys
sys.path.append("/home/rian/projects/svn/fwdb/")
import db
import json
import re
from db import is_address
import base64

debug = True

class db_gw:
	def __init__(self, fw=None):
		#self.iface = db.db("dbname=testfwdb_rian host=newdb1.ipam.usu.edu user=testfwdb password='XUU2Hq7IkGpPMFTkOPCu32ELtLYThQwp'", user=os.environ['REMOTE_USER'], fw=fw)
		auth_type, auth = os.environ['HTTP_AUTHORIZATION'].split()
		if auth_type != "Basic":
			raise Exception("Only basic auth is supported at this time")
		user, password = base64.b64decode(auth).split(":")
		self.user = user
		self.iface = db.db("dbname=fwdb host=newdb1.ipam.usu.edu user=%s password='%s'"%(user, password), user=os.environ['REMOTE_USER'], fw=fw)
		self.fw = fw
	#default to eldon's code. 
	def __getattr__(self, a):
		#if no firewall is set, restrict the allowed methods
		#if not self.iface.fw:
		#	if a not in ('get_firewalls'):
		#		raise Exception("Invalid permissions: Unable to access restricted function")
		return self.iface.__getattribute__(a)
	def get_chain_graph(self):
		"""
		get a dict of all the chains, and the chains they refer to
		"""
		valid_chains = self.iface.get_fw_chains()
		chain_where = [ " (c.id in ("+",".join(map(str,  valid_chains))+")) "]
		chain_where.append("(if_in.firewall_id = %s or r.if_in is NULL)"%self.iface.fw)
		chain_where.append("(if_out.firewall_id = %s or r.if_in is NULL)"%self.iface.fw)

		chain = self.iface.get_table('rules as r join chains as c on r.chain = c.id join chains as h on r.target = h.id LEFT OUTER JOIN interfaces AS pseudo_if_in ON pseudo_if_in.id = r.if_in	LEFT OUTER JOIN interfaces AS pseudo_if_out ON pseudo_if_out.id = r.if_out LEFT OUTER JOIN real_interfaces AS if_in ON if_in.pseudo = r.if_in LEFT OUTER JOIN real_interfaces AS if_out ON if_out.pseudo = r.if_out', ('c.id', 'c.name', 'h.id','h.name'), ' and '.join(chain_where))
		ret = {}
		for ci, c, ti, t in chain:
			if ti in valid_chains:
				if (ci, c) not in ret:
					ret[(ci, c)] = []
				ret[(ci, c)].append((ti, t))
		return ret
	def getgroup(self, name = None, gid = None):
		fields = ['hosts.id','hosts.name','hosts.host','hosts.host_end','users.name','hosts.description',]
		frm = 'hosts LEFT OUTER JOIN users ON hosts.owner = users.id'
		where = "hosts.is_group = TRUE"
		if gid:
			where += " and hosts.id = %s"%int(gid)
		elif name:
			where += " and hosts.name = '%s'"%db.check_input_str(name)
		vals = iface.get_table(frm,fields,where)
		ret = maketable(fields, vals)
		if not (gid or name):
			return ret
		ret = ret[0]
		frm = 'hosts LEFT OUTER JOIN users ON hosts.owner = users.id LEFT OUTER JOIN hosts_to_groups as h2g on h2g.hid = hosts.id'
		where = "h2g.gid = %s"%ret['hosts.id']
		vals = iface.get_table(frm, fields, where)
		ret['hosts'] = maketable(fields, vals)
		return ret


def getchainlist():
	fields = ['chains.id','chains.name','tables.name','chains.builtin','chains.description',]
	frm = 'chains LEFT OUTER JOIN tables ON chains.tbl = tables.id'
	where = None
	vals = iface.get_table(frm, fields, where)
	return maketable(fields, vals)

def maketable(fields, vals):
	ret = []
	#fields = [i.split(".")[-1] for i in fields] #need a check for redundant fields
	for row in vals:
		r = {}
		for i in range(len(fields)):
			r[fields[i]] = row[i]
		ret.append(r)
	return ret

def getgrouplist():
	return getgroup()


def getuserlist():
	fields = ['id','name','email','a_number']
	return iface.get_dict('users', fields)

def getperm(uid, ptype):
	where = 'permissions.user_id = %s and permissions.%s_id is not null'%(
		uid, ptype)
	fields = ['permissions.id', 'permissions.user_id', 'permissions.'+ptype+'_id',ptype+'.name']
	table = 'permissions left outer join '+ptype+' on permissions.users_id = '+ptype+'.id'
	return maketable(fields, iface.get_table(table, fields, where))
	

def getuser(uid):
	fields = ['id','name','email','a_number']
	ret = iface.get_table('users', fields, "id = %s"%uid)
	if not ret:
		return {}
	ret = maketable(fields, ret)[0]
	for ptype in ('users','hosts','chains'):
		ret[ptype+'_perms'] = getperm(uid, ptype)
	return ret	

def gethostlist():
	fields = ['hosts.id','hosts.name','hosts.host','users.name','hosts.description']
	q = iface.get_table('hosts left outer join users ON hosts.owner = users.id', fields, "hosts.is_group=false")
	return maketable(fields, q)

def gethost(hid):
	fields = ['hosts.id','hosts.name','hosts.host','users.name','hosts.description']
	q = iface.get_table('hosts left outer join users ON hosts.owner = users.id', fields, "hosts.is_group=false and hosts.id=%s"%hid)
	if not q:
		return {}
	ret = maketable(fields, q)[0]
	fields = ['groups.id', 'groups.name', 'groups.description', 'users.name', 'users.id']
	table = "hosts_to_groups as h2g left join hosts as groups on h2g.gid = groups.id left join users on groups.owner = users.id"
	where = "is_group = true and h2g.hid = %s"%hid
	q = iface.get_table(table, fields, where)
	if q:
		ret['groups'] = maketable(fields, q)
	#fields = ['chain', 'if_in', 'if_out','proto','src','sport','dst','dport','target','additional','ord','enabled','description','expires']
	#table = "rules"
	#where = "src = %s or dst = %s"%(hid, hid)
	#q = iface.get_table(table, fields, where)
	table = """
		rules LEFT OUTER JOIN chains AS chain ON chain.id=rules.chain
        LEFT OUTER JOIN users AS for_user ON rules.created_for = for_user.id
        LEFT OUTER JOIN tables AS tbl ON tbl.id = chain.tbl
        LEFT OUTER JOIN protos AS proto ON proto.id=rules.proto
        LEFT OUTER JOIN hosts_to_groups AS sh2g ON sh2g.gid = rules.src
        LEFT OUTER JOIN hosts AS src ON src.id = rules.src
        LEFT OUTER JOIN ports AS sport ON sport.id = rules.sport
        LEFT OUTER JOIN hosts_to_groups AS dh2g ON dh2g.gid = rules.dst
        LEFT OUTER JOIN hosts AS dst ON dst.id = rules.dst
        LEFT OUTER JOIN ports AS dport ON dport.id=rules.dport
        LEFT OUTER JOIN chains AS target ON target.id = rules.target
        LEFT OUTER JOIN interfaces AS pseudo_if_in ON pseudo_if_in.id = rules.if_in
        LEFT OUTER JOIN interfaces AS pseudo_if_out ON pseudo_if_out.id = rules.if_out
        LEFT OUTER JOIN real_interfaces AS if_in ON if_in.pseudo = rules.if_in
        LEFT OUTER JOIN real_interfaces AS if_out ON if_out.pseudo = rules.if_out\n"""
	fields = [
		'for_user.name', 
		'for_user.id',
		'rules.expires', 
		'rules.description',
		'rules.id',
		'tbl.name',
		'chain.name',
		'proto.name',
		'src.name',
		'dst.name',
		'sport.port',
		'dport.port',
		'target.name',
		'if_in.name',
		'if_out.name'
	]
	farg = ['-t', '-A', '-p', '-s', '-d', '--sport','--dport', '-j', '-m physdev --physdev-in', '-m physdev --physdev-out']
	where = "src.id = %s or dst.id = %s or dh2g.hid = %s or sh2g.hid = %s"%(hid, hid, hid, hid)
	q = iface.get_table(table, fields, where) 
	if q:
		rules = []
		for rule in q:
			user, uid, expires, description, rid = rule[:5]
			rulestr = ""
			if rule[5] == 'filter': #if its the default, dont bother
				rule = rule[:5]+(None,)+rule[6:]
			for i in xrange(len(rule[5:])):
				if rule[5+i]:
					rulestr += " " + farg[i] +" %s"%rule[5+i]
			rules.append({
				'user':user,
				'uid':uid,
				'expires':expires,
				'description':description,
				'rid':rid,
				'rulestr':rulestr
			})
		ret['rules'] = rules
	return ret

def add_host_to_group(hid, gid):
	iface.add_host_to_group(gid, hid)

def del_host_from_group(hid, gid):
	iface.del_host_to_group(gid, hid)
	


if __name__ == "__main__":
		
	if 'PATH_INFO' in os.environ:
		path = os.environ['PATH_INFO'].split('/')
		if path[1] == 'chain':
			if len(path) == 2:
				ret = getchainlist()		
			else:
				ret = []
		elif path[1] == 'group':
			if len(path) == 2:
				ret = getgrouplist()
			else:
				if re.match('\d+', path[2]):
					ret = getgroup(gid = int(path[2]))
				else:
					ret = getgroup(name = path[2])
		else:
			ret = []
	else:
		ret = []
	print 'content-type: text/plain\n'
	if debug:
		indent = 2
	else:
		indent = None
	print json.dumps(ret, indent=indent)



