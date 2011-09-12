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
"""
args = cgi.FieldStorage()
if 'fw' not in args:
	raise Exception("Need a firewall to edit")
fw = args['fw'].value


db = db_gw(fw)
if 'gid' not in args:
	raise Exception("Need a group id")

gid = int(args['gid'].value)
gids = []
if 'addnew' in args:
	host = args['host'].value
	name = args['name'].value
	owner = int(args['owner'].value)
	description = args['description'].value
	nid = db.add_host(name= name, owner_id=owner, address=host, description=description)
	db.add_host_to_group(group_id=gid, host_id=nid[0][0])
	print "<script type='text/javscript'>location='host.py?fw=%s&id=%s';</script>"%(fw, gid)
	print '<meta http-equiv="Refresh" content="0; url=host.py?fw=%s&id=%s" /></head>'%(fw, gid)
	print "<body>Successfully added host. Click <a href='host.py?fw=%s&id=%s'>here</a> to continue</body>"%(fw, gid)
elif 'add' in args:
	add = args['add'].value
	if is_address(add):
		if "/" not in add:
			add += "/32"
		h = db.get_hosts(ip=add)
	else:
		h = db.get_hosts(name=add)
	if len(h) > 1:
		raise Exception("Uh oh, too many matching hosts. slap eldon accross the back of the head and tell him to fix it: %r"%h)
	elif len(h) == 1:
		db.add_host_to_group(group_id = gid, host_id = h[0]['hosts.id'])
		print '<meta http-equiv="Refresh" content="0; url=host.py?fw=%s&id=%s" /></head>'%(fw, gid)
		print "<body><script type='text/javscript'>window.location='host.py?fw=%s&id=%s';</script>"%(fw, gid)
		print "Successfully added host. Click <a href='host.py?fw=%s&id=%s'>here</a> to continue</body>"%(fw, gid)
	else:
		print "</head><body>"
		print "<form action='addhost.py'>"
		print "<input type='hidden' name='fw' value='%s'></input>"%fw
		print "<input type='hidden' name='gid' value='%s'></input>"%gid
		ip = name = ""
		if is_address(add):
			ip = add
		else:
			name = add
		print "<table>"
		print "<tr><td class='key'>IP</td><td class='value'><input type='text' name='host' value='%s'></input></td></tr>"%ip
		print "<tr><td class='key'>Hostname</td><td class='value'><input type='text' name='name' value='%s'></input></td></tr>"%name

		optlist = []
		for u in sorted(db.get_user(), cmp = lambda a, b: cmp(list(reversed(a['name'].lower().split())), list(reversed(b['name'].lower().split())))):
			optlist.append("<option value='%(id)s'>%(name)s</option>"%u)

			

		print "<tr><td class='key'>Owner</td><td class='value'><select name='owner'>"+"".join(optlist) + "</select></td></tr>"
		print "<tr><td class='key'>Description</td><td class='value'><textarea name='description'></textarea></td></tr>"
		print "</table>"
		print "<input type='submit' name='addnew' value='Add Host' class='ui-state-default ui-corner-all'></input>"
		print "</form>"
		print "</body>"
			

print """
</html>
"""
