#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import sys
sys.path.append("..")
from data import db_gw
from data import is_address
from fmt import fmt_rule
import web

print web.head()
body = []

args = cgi.FieldStorage()
if 'fw' not in args:
	raise Exception("Need a firewall to edit")
fw = args['fw'].value


db = db_gw(fw)
if 'id' not in args:
	body.append("  <table class='ui-widget' cellspacing='0px' cellpadding='2px'><tr class='ui-widget-header'><th>Name</th><th>Description</th></tr>")
	for g in sorted(db.get_hosts(host_ids=db.get_fw_groups()), cmp=lambda a,b: cmp(a['name'].lower(), b['name'].lower())):
		g['fw'] = fw
		body.append("    <tr><td><a href='host.py?id=%(hosts.id)s&fw=%(fw)s'>%(name)s</a></td><td>%(description)s</td></tr>"%g)
	body.append("  </table>")
else:
	gid = int(args['id'].value)
	gids = []
	if 'remove' in args:
		rid = int(args['remove'].value)
		db.del_host_to_group(group_id = gid, host_id = rid)
		
	hosts = db.get_hosts(gid = gid)
	if len(hosts) == 1 and hosts[0]['hosts.id'] == gid:
		host = hosts[0]
		body.append("<h1>%(name)s</h1>"%host)
		body.append("  <table>")
		if host['host_end']:
			body.append("   <tr><td class='key'>IPS</td><td class='value'>%(host)s - %(host_end)</td></tr>"%host)
		else:
			body.append("   <tr><td class='key'>IP</td><td class='value'>%(host)s</td></tr>"%host)
		user = db.get_user(uid=host['owner'])[0]
		body.append("   <tr><td class='key'>Name</td><td class='value'>%(name)s</td></tr>"%user)
		body.append("   <tr><td class='key'>A Number</td><td class='value'>%(a_number)s</td></tr>"%user)
		body.append("   <tr><td class='key'>Contact</td><td class='value'>%(email)s</td></tr>"%user)
		body.append("   <tr><td class='key'>Description</td><td class='value'>%(description)s</td></tr>"%host)
		body.append("  </table>")
		groups = db.get_groups(host_id = host['hosts.id'])
		body.append("  <h3>Member of %s groups:</h3>"%len(groups))
		if groups:
			body.append("  <table><tr><th>Name</th><th>Description</th></tr>")
			for g in groups:
				body.append("   <tr><td><a href='host.py?fw="+fw+"&id=%(gid)s'>%(name)s</a></td><td>%(description)s</td></tr>"%g)
				gids.append(g['gid'])
			body.append("  </table>")
		gids.append(host['hosts.id'])
		
		
	else:

		gids = [gid]
		body.append("  <table class='ui-widget' cellspacing='0px' cellpadding='2px'><tr class='ui-widget-header'><th>Name</th><th>IP</th><th>Description</th></tr>")
		for g in sorted(hosts, cmp=lambda a,b: cmp(a['name'].lower(), b['name'].lower())):
			g['fw'] = fw
			g['gid'] = gid
			body.append("    <tr><td><a href='host.py?fw=%(fw)s&id=%(hosts.id)s'>%(name)s</a></td><td>%(host)s</td><td>%(description)s</td><td><a href='host.py?fw=%(fw)s&id=%(gid)s&remove=%(hosts.id)s' class='verify ui-state-default ui-corner-all'>Remove</a></tr>"%g)
		body.append("  </table>")
		body.append("  <form action='addhost.py'>")
		body.append("   <input type='hidden' name='fw' value='%s'></input>"%fw)
		body.append("   <input type='hidden' name='gid' value='%s'></input>"%gid)
		body.append("   <input type='text' name='add'></input>")
		body.append("   <input type='submit' value='Add Host' class='ui-state-default ui-corner-all aspopup'></input>")
		body.append("  </form>")

	
	cols = ['chain.id', 'chain.name', 'for_user.name', 'proto.name', 'src.id', 'src.name', 'sport.port', 'sport.endport', 'dst.id', 'dst.name','dport.port', 'dport.endport', 'target.name', 'rules.additional', 'target.id']
	src_ref = db.get_rules(src = gids, columns=cols, asdict=True)
	dst_ref = db.get_rules(dst = gids, columns=cols, asdict=True)

	body.append("  <h3>Referenced as source from %s rules:</h3>"%len(src_ref))
	body.append("  <ul>")
	for r in src_ref:
		body.append("   <li>%s</li>"%fmt_rule(r))
	body.append("  </ul>")
	body.append("  <h3>Referenced as destination from %s rules:</h3>"%len(dst_ref))
	body.append("  <ul>")
	for r in dst_ref:
		body.append("   <li>%s</li>"%fmt_rule(r))
	body.append("  </ul>")
	other_firewalls = db.get_firewalls_by_group(gid=gid)
	body.append("<h3>Referenced by %s firewalls:</h3><ul>"%len(other_firewalls))
	for f in other_firewalls:
		body.append("<li><a href='host.py?fw=%s&id=%s'>%s</a></li>"%(f['name'],gid, f['name']))
	body.append("</ul>")
	
		


print web.body("".join(body), db)
print web.footer()
