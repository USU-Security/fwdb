#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import os
import sys
sys.path.append("/home/rian/projects/svn/fwdb")
import db
import json
import re

debug = True

iface = db.db("dbname=testfwdb_rian host=newdb1.ipam.usu.edu user=testfwdb password='XUU2Hq7IkGpPMFTkOPCu32ELtLYThQwp'")
args = cgi.FieldStorage()

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

def getgroup(name = None, gid = None):
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



