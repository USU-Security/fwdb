#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import sys
sys.path.append("..")
from data import getgroup
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
if 'gid' not in args:
	print "  <table class='ui-widget' cellspacing='0px' cellpadding='2px'><tr class='ui-widget-header'><th>Name</th><th>Owner</th><th>Description</th></tr>"
	for g in sorted(getgroup(), cmp=lambda a,b: cmp(a['hosts.name'].lower(), b['hosts.name'].lower())):
		print "    <tr><td><a href='group.py?gid=%s'>%s</a></td><td>%s</td><td>%s</td></tr>"%(
			g['hosts.id'],g['hosts.name'], g['users.name'], g['hosts.description']
		)
	print "  </table>"
else:
	gid = int(args['gid'].value)
	print "  <table class='ui-widget' cellspacing='0px' cellpadding='2px'><tr class='ui-widget-header'><th>Name</th><th>IP</th><th>Owner</th><th>Description</th></tr>"
	for g in sorted(getgroup(gid = gid)['hosts'], cmp=lambda a,b: cmp(a['hosts.name'].lower(), b['hosts.name'].lower())):
		print "    <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"%(
			g['hosts.name'], g['hosts.host'], g['users.name'], g['hosts.description']
		)
	print "  </table>"



print """
 </body>
</html>
"""
