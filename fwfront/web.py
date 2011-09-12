#!/usr/bin/env python

# not sure why this was here, delete it if you get a chance...

def head(css = (
		"css/custom-theme/jquery-ui-1.8.4.custom.css", 
		"css/jquery.jnotify.css",
		"css/jsfront.css"
	), cssextra = (
	), cssexec = (
	), js = (
		'js/jquery-1.4.2.min.js',
		'js/jquery.jnotify.js',
		'js/fwfront.js'
	), jsextra = (
	), jsexec = (
	), 
	title = None,
	):
	ret = []
	ret.append("content-type: text/html\n\n")
	ret.append('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">')
	ret.append("<html><head>")
	for s in css + cssextra:
		ret.append("<link type='text/css' href='%s' rel='stylesheet' />"%s)
	if cssexec:
		ret.append("<style type='text/css'>%s</style>"%cssexec)
	for j in js + jsextra:
		ret.append("<script type='text/javascript' src='%s'></script>"%j)
	if jsexec:
		ret.append("<script type='text/javascript'>$(document).ready(function(){%s});</script>"%jsexec)
	if title:
		ret.append("<title>%s</title>"%title)
	return "".join(ret)


def _portlet(name, content):
	return "<div class='portlet ui-widget ui-widget-content ui-helper-clearfix ui-corner-all'><div class='portlet-header ui-widget-header ui-corner-all'>%s</div><div class='portlet-content'>%s</div></div>"%(name, content)

def body(content, db=None, heading=None):
	if not db:
		import data
		import cgi
		args = cgi.FieldStorage()
		if "fw" in args:
			fw = args['fw'].value
		else:
			fw = None
		db = data.db_gw(fw = fw)
	fwlinks = []
	for f in db.get_firewalls():
		if f == db.fw:
			fwlinks.append("<a href='index.py?fw=%s' class='selected ui-corner-all'>%s</a></br>"%(f, f))
		else:
			fwlinks.append("<a href='index.py?fw=%s'>%s</a></br>"%(f, f))
	menu = _portlet("Firewall", "".join(fwlinks))
	if db.fw:
		menu += _portlet("Links", "<a href='host.py?fw=%s'>Groups</a><br><a href='rules.py?fw=%s'>Rules</a>"%(db.fw, db.fw))
	if heading is None:
		if db.fw:
			heading = db.fw
		else:
			heading="Firewall Management"
	
	return "<body><br><h1 class='heading'>%s</h1><table><tr><td>%s</td><td style='padding-left:20px;'>%s</td></tr></table</body>"%(heading,menu, content)
	

def footer():
	return "</html>"


