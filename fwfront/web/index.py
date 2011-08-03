#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import sys
sys.path.append("..")
from data import db_gw

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
	db = db_gw()
	print "<h3>Please select a firewall</h3><ul>"
	for f in db.get_firewalls():
		print "<li><a href='?fw=%s'>%s</a></li>"%(f,f)
	print "</ul>"
else:
	fw = fw=args['fw'].value
	db = db_gw(fw=fw)
	print "<h1>%s</h1>"%fw
	print "<ul>"
	print "<li><a href='host.py?fw=%s'>Groups</a></li>"%fw
	#print "<li><a href='host.py?fw=%s'>Hosts</a></li>"%fw
	print "<li><a href='rules.py?fw=%s'>Rules</a></li>"%fw
	print "</ul"

print """
 </body>
</html>
"""
