#!/usr/bin/env python
# WARNING: These scripts assume you have a default of ACCEPT for your chains.
#  In the case of a catastrophic failure, we flush all rules as a last-ditch effort

import time
import db
import re
import sys

import os

import subprocess
import tempfile

import readline

datefmt='%Y%m%d-%H%M%S'

DATE=time.strftime(datefmt)

iptables = '/sbin/iptables'
firewall_id = 'fwser1.oob.usu.edu'

if len(sys.argv) == 2:
	username = sys.argv[1]
else:
	username = 'USERNAME_NOT_GIVEN'

if os.environ.has_key('SSH_CLIENT'):
	ssh_client=os.environ['SSH_CLIENT'].split()[0]
else:
	ssh_client='[local]'

user_string = '%s@%s' % (username, ssh_client)

#scriptdir='/var/lib/iptables'
recipient='firewall-admins@lists.usu.edu'
scriptdir='/root/firewall_scripts'
backupdir="%s/backups" % scriptdir
tmpdir="%s/temp" % scriptdir

iface = db.db("host='newdb1.ipam.usu.edu' dbname='fwdb' user='banfw'", fw = firewall_id)

def write_stats( iptables_save_file ):
	print "\t\tgathering statistics..."
	global iface
	ipt = open(iptables_save_file)
	comment_arg='--comment '
	counts = []
	valid_ids = [ i[0] for i in iface.execute_query('SELECT id FROM rules') ]
	valid_host_ids = [ i[0] for i in iface.execute_query('SELECT id FROM hosts') ]

	for line in ipt:
		start = line.find(comment_arg)
		if start < 0:
			continue
		start += len(comment_arg)
		if line[start] == '"':
			start+=1
			end = line.find('"',start)
		else:
			end = line.find(' ',start)
		comment = line[start:end]
		
		info = {}
		for i in comment.split(' '):
			name, val = i.split(':')
			info[name.strip()] = val.strip()

		id = info['id']

		src = info['src']
		if src != 'NULL': src = int(src)
		
		dst = info['dst']
		if dst != 'NULL': dst = int(dst)
		
		start=line.find('[')+1
		end=line.find(']')
		(packets,bytes) = line[start:end].split(':')
		if ( int(id) in valid_ids
				and (src == 'NULL' or src in valid_host_ids)
				and (dst == 'NULL' or dst in valid_host_ids)):
			# don't append this count if there is no such rule
			counts.append( (int(id),src,dst,int(packets),int(bytes),) )
		else:
			print """Ignoring statistics for non-existent rule --
			id: %s, src: %s, dst: %s, packets: %s, bytes: %s""" % (int(id),
					src,dst,int(packets),int(bytes))
	print "\t\tstoring statistics..."
	counts = [ '(%s, %s, %s, %s, %s)' % count for count in counts ]
	iface.execute_insert("INSERT INTO rule_stats(rule,src,dst,packets,bytes) VALUES %s;" % ', '.join(counts) )
	print "\t\tdone."

def runcmd(s):
	print s
	ret = os.system(s)
	if ret != 0:
		raise Exception( "command FAILED: %s" % s )

def update_set(old,new, outfile=None):
	(remove,add) = old.diff(new)
	for a in add:
		cmd = db.IPSET_ADD % (new.name, a)
		if not outfile:
			runcmd(cmd)
		else:
			outfile.write(cmd)
			outfile.write('\n')

	for r in remove:
		cmd = db.IPSET_DEL % (new.name, r)
		if not outfile:
			runcmd(cmd)
		else:
			outfile.write(cmd)
			outfile.write('\n')

def update_sets( delete=False, oldcfg=None, newcfg=None, outfile=None ):
	global iface
	if oldcfg is None: oldcfg = db.ipset_list(load_file=None)
	if newcfg is None: newcfg = iface.get_ipset()

	old_set_names = set(oldcfg.sets)
	new_set_names = set(newcfg.sets)

	add_set_names = new_set_names.difference(old_set_names)
	
	for i in add_set_names:
		print "creating %s" % i
		cmd = db.IPSET_CREATE % (i,newcfg.set_members[i].set_type)
		if not outfile:
			runcmd(cmd)
		else:
			outfile.write(cmd)
			outfile.write('\n')
	del_set_names = old_set_names.difference(new_set_names)
	
	if delete:
		for i in del_sets:
			cmd = db.IPSET_DESTROY % i
			if not outfile:
				runcmd(cmd)
			else:
				outfile.write(cmd)
				outfile.write('\n')
	
	for name in new_sets:
		if name in old_sets:
			update_set(oldcfg[name], newcfg[name], outfile)
		else:
			update_set(db.ipset(name), newcfg[name], outfile)
	
	return oldcfg, newcfg

def check_dirs( dirs ):
	for d in dirs:
		if not os.path.isdir(d):
			os.makedirs(d)

def main():
	global iface
	for i in [scriptdir, backupdir, tmpdir,]:
		pass
		#[ -f "$i" ] || mkdir -p $i

	suffix = "%s-%s" % (username,DATE)

	scriptname="%s/current/iptables" % scriptdir
	olddir="%s/pre-%s" % (backupdir,suffix)
	faileddir="%s/failed-%s" % (backupdir, suffix)
	tmpfile="%s/temp-%s" % (tmpdir, suffix)
	tmpset="%s/ipset-changes-%s" % (tmpdir, suffix)
	ipt_tmp_store="%s/iptables-store_%s" % (tmpdir, suffix)

	set_store = "%s/ipset_save" % current_dir
	ipt_store = "%s/iptables_save" % current_dir

	check_dirs( [ current_dir, backupdir, scriptdir, tmpdir ] )

	print "calculating set changes:"
	tmpset_f = open(tmpset)
	oldcfg, newcfg = update_sets( outfile=tmpset_f )
	tmpset_f.close()

	print "generating ruleset:"
	new = open(tmpfile,'w')

	valid_chains = iface.get_fw_chains()
	chain_patterns_where = " (chain.id in ("+",".join(map(str, valid_chains))+")) "

	tables_q = '''SELECT tables.name,tables.id FROM tables;'''
	tables = iface.execute_query(tables_q)

	for tbl in tables:
		tbl_name = tbl[0]
		tbl_id = tbl[1]
		new.write("*%s\n"%tbl_name)

		chains_q = '''SELECT 
		':' || chain.name || ' ACCEPT ' || E'[0:0]' ||
		CASE WHEN chain.description IS NOT NULL THEN ' # ' || chain.description ELSE '' END || E'\n'
		FROM chains AS chain JOIN tables ON chain.tbl=tables.id
		WHERE chain.tbl = %s AND chain.builtin = TRUE ORDER BY chain.name;''' % tbl_id

		for line in iface.execute_query(chains_q):
			new.write(line[0])

		chains_q = '''SELECT
		':' || chain.name || ' - ' || E'[0:0]' ||
		CASE WHEN chain.description IS NOT NULL THEN ' # ' || chain.description ELSE '' END || E'\n'
		FROM chains AS chain JOIN tables ON chain.tbl=tables.id
		WHERE chain.tbl = %s AND chain.builtin = FALSE AND %s ORDER BY chain.name;''' % (tbl_id, chain_patterns_where)

		for line in iface.execute_query(chains_q):
			new.write(line[0])

		quote_foo = re.compile(r'([^"]*)"([^"]*)"')
		for line in iface.get_rules(ipt_restore=True, table=tbl_id, fw_id=firewall_id, andwhere=chain_patterns_where):
			if not line:
				raise Exception("Database inconsistency found!")
			new.write(line[0])

		new.write("""COMMIT\n""")

	#new.write("\nEND_OF_IPTABLES_RULES\n")
	new.close()
	print "\tdone.\ncomparing to current ruleset:"

	tmpdiff_fd,tmpdiff_name = tempfile.mkstemp()
	os.close(tmpdiff_fd)

	tmpdiff = open(tmpdiff_name,'w')

	# FIXME: this is probably bad form
	#changed = os.system("diff -u '%s' '%s'" % (scriptname, tmpfile))
	changed = subprocess.call(["/usr/bin/diff", '-u', scriptname, tmpfile,], stdout=tmpdiff)

	tmpdiff.close()

	#tmpdiff = open(tmpdiff_name,'r')
	#for l in tmpdiff:
	#	sys.stdout.write(l)
	#tmpdiff.close()

	if not changed:
		print '\tconfiguration unchanged.'
		os.unlink(tmpfile)
	else:
		print '\tchanges detected\npdating configuration...'
		# FIXME: this would be a better way, but there is no way to see
		# if the rules are expiring with this run, or had expired
		# before
		# New approach... You may not update rules if some are expired; you must handle all of the rules externally
		expired_rules = iface.get_rules( fw_id=firewall_id, andwhere=chain_patterns_where, expired=True, enabled=True )

		if expired_rules:
			expired_rules = [ i[0] for i in expired_rules ]
			print '\n'.join(expired_rules)
			raise Exception("The following expiring rules need to be handled: %s" % " ".join([str(i[1]) for i in expired_rules])) 

		os.system('[ -x /usr/bin/colordiff ] && CAT=colordiff || CAT=cat; $CAT %s %s | less -XF -R' % (tmpset, tmpdiff_name,) )
		x = raw_input('Load new configuration [y/N]: ')
		if x != '' and ( x[0]=='y' or x[0]=='Y' ):
			description = raw_input('Please enter a description of your change: ')
			print '\tsending diff:'
			msg = [
					"Change by: ", user_string, '\n',
					"Firewall: ", firewall_id, '\n',
					"Reason given for change:\n\t",
					description,
					'\n\nHere is the diff:\n\n',
				]
			
			tmpset_f = open(tmpset)
			msg.extend(tmpset_f.readlines())
			tmpset_f.close()

			tmpdiff = open(tmpdiff_name,'r+')
			msg.extend(tmpdiff.readlines())
			
			tmpdiff.seek(0)
			tmpdiff.writelines( msg )

			tmpdiff.seek(0)
			r = subprocess.call(["mail", '-s', 'Change on %s' % firewall_id, recipient,], stdin=tmpdiff)
			tmpdiff.close()

			if r == 0: print "\t\tdone."
			else: print "\t\tfailed."

			print '\tloading new rules:'
			save = os.system( 'iptables-save -c > %s' % ipt_tmp_store )
			status = os.system( 'iptables-restore < %s' % tmpfile )
			if status:
				print '\t\tFAILED! -- loading last working ruleset (storing failed set in %s)' % failedname
				if save:
					# Save failed! Bad!
					status = os.system( 'iptables-restore < %s' % scriptname )
				else:
					status = os.system( 'iptables-restore -c < %s' % ipt_tmp_store )
				os.rename(tmpfile, failedname)
				if status:
					print '\t\tFAILED! -- Firewall is hosed, someone really needs to fix it'
					print '\t\t!!! flushing all rules !!!'
					os.system('iptables -F')
				sys.exit(1)
			else:
				if not save:
					try:
						write_stats(ipt_tmp_store)
					except Exception, e:
						# We don't want this to cause
						#the update to fail
						print e
						print '\t\tFailed to store statistics.'
				else:
					print "\t\tiptables-save failed, unable to collect statistics"
				os.system( 'iptables-save > %s' % ipt_store )
				print scriptname, oldscript
				os.rename(scriptname, oldscript)
				os.rename(tmpfile, scriptname)
				print '\tdone.'
		else:
			print 'NOT updating!'
			exit(1)


	print "Final ipset update:"
	update_sets(newcfg = newcfg, delete=True)
	print "done."
	
	del iface

if __name__ == '__main__':
	main()

