import cgi
form = cgi.FieldStorage()

fw = form['fw'].value 



def fmt_ip_port(name, start, end, rid):
	if not name:
		name = 'any'
	else:
		name = "<a href=host.py?fw=%s&id=%s>%s</a>"%(fw, rid, name)
	if start:
		port = ":%s"%start
		if end:
			port += "-%s"%end
	else:
		port = ""
	return name + port

def fmt_rule(r):
	ret = []
	ret.append("<div class='fixed-proto'>")
	if r['proto.name']:
		ret.append(r['proto.name'])
	ret.append("</div>")
	src = fmt_ip_port(r['src.name'], r['sport.port'], r['sport.endport'], r['src.id'])
	dst = fmt_ip_port(r['dst.name'], r['dport.port'], r['dport.endport'], r['dst.id'])
	ret.extend(("<div class='fixed-ips'>", src, "->", dst, "</div>"))
	ret.append(r['target.name'])
	if r['rules.additional']:
		ret.extend(("(", r['rules.additional'], ")"))

	return " ".join(ret)

