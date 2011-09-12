#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import sys
sys.path.append("..")
from data import db_gw 
from fmt import fmt_rule
import web

print web.head(jsextra = ("js/jquery.treeview.js",), jsexec="$('#ruletree').treeview();", cssextra=("css/jquery.treeview.css",))
body = []
args = cgi.FieldStorage()
if 'fw' not in args:
	raise ValueError("Missing fw parameter")
fw = args['fw'].value
db = db_gw(fw = fw)
body.append("<h1>%s</h1>"%fw)

term_targets = set(['ACCEPT', 'REJECT', 'DROP', 'LOG'])

rules = {}
columns = ['chain.id', 'chain.name', 'for_user.name', 'proto.name', 'src.id', 'src.name', 'sport.port', 'sport.endport', 'dst.id', 'dst.name','dport.port', 'dport.endport', 'target.name', 'rules.additional', 'target.id']
for row in db.get_rules(columns = columns):
	r = {}
	for i in range(len(columns)):
		r[columns[i]] = row[i]
	r['formatted_rule'] = row[-2]
	if r['chain.id'] not in rules:
		rules[r['chain.id']] = []
	rules[r['chain.id']].append(r)

def sub_rules(cid, tabs=0):
	if cid in rules:
		ret = ["","<ul>"]
		for r in rules.get(cid, ()):
			expandable = r['target.name'] not in term_targets and "expandable" or ""
			ret.append("\t<li class='closed %s'>%s %s</li>"%(expandable, fmt_rule(r), sub_rules(r['target.id'], tabs + 1)))
		ret.append("</ul>")
	else:
		ret = []
	return ("\n" + "\t"*tabs).join(ret)
	
builtins = db.get_chains(builtin=True)

body.append("<ul id='ruletree' class='treeview-grey'>")
for c in builtins:
	if c['name'] in term_targets:
		continue
	body.append("\t<li>%s %s</li>"%(c['name'], sub_rules(c['id'], 1)))
body.append("</ul>")


print web.body("".join(body), db)
print web.footer()
