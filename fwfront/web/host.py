#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import sys
sys.path.append("..")
from data import db_gw
from data import is_address
from fmt import fmt_rule

print """content-type: text/html\n\n
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
 <head>
  <link type="text/css" href="css/custom-theme/jquery-ui-1.8.4.custom.css" rel="stylesheet" />
  <link type="text/css" href="css/jquery.jnotify.css" rel="stylesheet" />
  <link type="text/css" href="css/jsfront.css" rel="stylesheet" />
 </head>
 <body>
"""
args = cgi.FieldStorage()
if 'fw' not in args:
	raise Exception("Need a firewall to edit")
fw = args['fw'].value


db = db_gw(fw)
if 'id' not in args:
	print "  <table class='ui-widget' cellspacing='0px' cellpadding='2px'><tr class='ui-widget-header'><th>Name</th><th>Description</th></tr>"
	for g in sorted(db.get_hosts(host_ids=db.get_fw_groups()), cmp=lambda a,b: cmp(a['name'].lower(), b['name'].lower())):
		g['fw'] = fw
		print "    <tr><td><a href='host.py?id=%(hosts.id)s&fw=%(fw)s'>%(name)s</a></td><td>%(description)s</td></tr>"%g
	print "  </table>"
else:
	gid = int(args['id'].value)
	gids = []
	if 'remove' in args:
		rid = int(args['remove'].value)
		db.del_host_to_group(group_id = gid, host_id = rid)
		
	hosts = db.get_hosts(gid = gid)
	if len(hosts) == 1 and hosts[0]['hosts.id'] == gid:
		host = hosts[0]
		print "<h1>%(name)s</h1>"%host
		print "  <table>"
		if host['host_end']:
			print "   <tr><td class='key'>IPS</td><td class='value'>%(host)s - %(host_end)</td></tr>"%host
		else:
			print "   <tr><td class='key'>IP</td><td class='value'>%(host)s</td></tr>"%host
		user = db.get_user(uid=host['owner'])[0]
		print "   <tr><td class='key'>Name</td><td class='value'>%(name)s</td></tr>"%user
		print "   <tr><td class='key'>A Number</td><td class='value'>%(a_number)s</td></tr>"%user
		print "   <tr><td class='key'>Contact</td><td class='value'>%(email)s</td></tr>"%user
		print "   <tr><td class='key'>Description</td><td class='value'>%(description)s</td></tr>"%host
		print "  </table>"
		groups = db.get_groups(host_id = host['hosts.id'])
		print "  <h3>Member of %s groups:</h3>"%len(groups)
		if groups:
			print "  <table><tr><th>Name</th><th>Description</th></tr>"
			for g in groups:
				print "   <tr><td><a href='host.py?fw="+fw+"&id=%(gid)s'>%(name)s</a></td><td>%(description)s</td></tr>"%g
				gids.append(g['gid'])
			print "  </table>"
		gids.append(host['hosts.id'])
		
		
	else:

		gids = [gid]
		print "  <table class='ui-widget' cellspacing='0px' cellpadding='2px'><tr class='ui-widget-header'><th>Name</th><th>IP</th><th>Description</th></tr>"
		for g in sorted(hosts, cmp=lambda a,b: cmp(a['name'].lower(), b['name'].lower())):
			g['fw'] = fw
			g['gid'] = gid
			print "    <tr><td><a href='host.py?fw=%(fw)s&id=%(hosts.id)s'>%(name)s</a></td><td>%(host)s</td><td>%(description)s</td><td><a href='host.py?fw=%(fw)s&id=%(gid)s&remove=%(hosts.id)s'>Remove</a></tr>"%g
		print "  </table>"
		print "  <form action='addhost.py'>"
		print "   <input type='hidden' name='fw' value='%s'></input>"%fw
		print "   <input type='hidden' name='gid' value='%s'></input>"%gid
		print "   <input type='text' name='add'></input>"
		print "   <input type='submit' value='Add Host'></input>"
		print "  </form>"

	
	cols = ['chain.id', 'chain.name', 'for_user.name', 'proto.name', 'src.id', 'src.name', 'sport.port', 'sport.endport', 'dst.id', 'dst.name','dport.port', 'dport.endport', 'target.name', 'rules.additional', 'target.id']
	src_ref = db.get_rules(src = gids, columns=cols, asdict=True)
	dst_ref = db.get_rules(dst = gids, columns=cols, asdict=True)

	print "  <h3>Referenced as source from %s rules:</h3>"%len(src_ref)
	print "  <ul>"
	for r in src_ref:
		print "   <li>%s</li>"%fmt_rule(r)
	print "  </ul>"
	print "  <h3>Referenced as destination from %s rules:</h3>"%len(dst_ref)
	print "  <ul>"
	for r in dst_ref:
		print "   <li>%s</li>"%fmt_rule(r)
	print "  </ul>"
		



print """
 </body>
</html>
"""
