#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import sys
sys.path.append("..")
from data import db_gw
import web

print web.head()
args = cgi.FieldStorage()

body = []
if 'fw' not in args:
	db = db_gw()
	body.append("<h3>Please select a firewall</h3><table>")
	for f in db.get_firewalls():
		body.append("<tr><td><a href='sync.py?fw=%s' class='ui-state-default ui-corner-all'>Sync</a></td><td><a href='?fw=%s'>%s</a></td></tr>"%(f,f, f))
	body.append("</table>")
else:
	fw = fw=args['fw'].value
	db = db_gw(fw=fw)
	body.append("<h1>%s</h1>"%fw)
	body.append("<ul>")
	body.append("<li><a href='host.py?fw=%s'>Groups</a></li>"%fw)
	#body.append("<li><a href='host.py?fw=%s'>Hosts</a></li>"%fw)
	body.append("<li><a href='rules.py?fw=%s'>Rules</a></li>"%fw)
	body.append("</ul")

print web.body("".join(body), db=db)
print web.footer()
