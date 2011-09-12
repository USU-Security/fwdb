#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import sys
sys.path.append("..")
from data import db_gw
import subprocess
import os
import re
import web
db = db_gw()


def fw_run(*a):
	for i in a:
		if not re.match(r'[a-zA-Z0-9\-,+_\s./]+', i):
			raise Exception("Unsafe character in command:"+i)
	args = ['sudo', '-u', 'firewall']
	args.append("/home/firewall/bin/"+a[0])
	args.extend(a[1:])
			
	proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate()
	if "Permission denied" in err:
		raise Exception("Unable to log into "+fw)
	return out, err

def fw_status(fw):
	global db
	out, err = fw_run("fw_status", fw, db.user) 
	m = re.search(r"updating configuration\.\.\.(.+)======Hash: ([a-fA-F0-9]+)======", out, re.S)
	if m:
		return m.group(1), m.group(2)
	if "configuration unchanged" in out:
		return None, None
	m = re.search(r"expiring rules need to be handled: ([\s\d]+)", err, re.S)
	if m:
		return map(int, m.group(1).split()), None
	raise Exception("I don't understand the firewall output: " + out + err)

def fw_push(fw, checksum, description):
	global db
	out, err = fw_run('fw_push', fw, db.user, checksum, description)
	#body.append("out:%r<br>err:%r</br>"%(out, err))
	if "Exception" in out:
		return out
	if "configuration unchaged" in out:
		return out
	return None
	


print web.head()
args = cgi.FieldStorage()

body = []
if 'renewrule' in args:
	renewids = args.getvalue('renewrule')
	if not isinstance(renewids, list):
		renewids = [renewids]
	db.extend_rule(map(int, renewids))
	body.append("renewed %s rules</body></html>"%len(renewids))
	sys.exit(0)
if 'disablerule' in args:
	disableids = args.getvalue('disablerule')
	if not isinstance(disableids, list):
		disableids = [disableids]
	db.disable_rule(map(int, disableids))
	body.append("disabled %s rules</body></html>"%len(disableids))
	sys.exit(0)




if 'fw' not in args:
	raise Exception("Need a firewall to edit")
fws = args.getvalue('fw')
if type(fws) is str:
	fws = [fws]

validfw = db.get_firewalls()

if "push" in args:
	if "description" not in args:
		body.append("<div style='color:red;'>Please fill out a description before committing changes to the firewalls</div>")
	else:
		for fw in fws:
			if "hash_"+fw in args:
				checksum = args['hash_'+fw].value
				body.append("Applying changes for %s: "%fw)
				o = fw_push(fw, checksum, args['description'].value)
				if o:
					body.append("<pre>%s</pre>"%o)
				else:
					body.append("Success</br>")


topush = {}
expiredrules = set()
for fw in fws:
	if fw in validfw:
		body.append("<div class='firewallstatus'>")
		body.append("<h1>%s</h1>"%fw)
		msg, checksum = fw_status(fw)
		if msg:
			if type(msg) is list:
				body.append("The following rules have expired: %s") %msg
				expiredrules.update(msg)
			else:
				body.append("These are the changes that are going to be made:<pre>%s</pre>"%msg)
				topush[fw] = checksum
		else:
			body.append("Up to date")
		body.append("</div>")

if expiredrules:
	body.append("The following expired rules need to be dealt with before a commit can be made:")
	rules = db.get_rules(id=expiredrules)
	body.append("<table>")
	url = 'sync.py?'+"&".join(["fw=%s"%i for i in fws])
	for r in rules:
		body.append("<tr><td><a href='%s&renewrule=%s' class='ui-state-default ui-corner-all async'>Renew</a>&nbsp;<a href='%s&disablerule=%s' class='ui-state-default ui-corner-all async'>Disable</a></td><td><pre>%s</pre></td></tr>"%(url, r[1], url, r[1], r[0]))
	body.append("</table>")
	body.append("<a href='%s' class='ui-state-default ui-corner-all'>Refresh</a>"%url)
elif topush:
	body.append("The following firewalls are ready to be updated:")
	body.append("<form action='sync.py'>")
	body.append("<ul>")
	for fw,checksum in sorted(topush.iteritems()):
		body.append("<input type='hidden' name='hash_%s' value='%s'></input>"%(fw, checksum))
		body.append("<input type='hidden' name='fw' value='%s'></input>"%(fw))
		body.append("<li>%s</li>"%fw)
	body.append("</ul>")
	body.append("<span class='key'>Description of changes</span><span class='value'><input type='text' name='description'></input></span><br>")
	body.append("<input type='submit' name='push' value='Commit Changes' class='ui-state-default ui-corner-all'></input>")
else:
	body.append("<br>All Firewalls are up to date.")

print web.body("".join(body))

print web.footer()
