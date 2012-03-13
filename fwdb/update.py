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
import argparse
import socket
import hashlib

import shlex
import shutil

options = argparse.ArgumentParser(description="Synchronize the firewall to the database")
options.add_argument('-f', '--firewall', help="The firewall in the database to sync rules to (defaults to this host)")
options.add_argument('-m', '--mailto', help="Send a notification to this email address", default='firewall-admins@lists.usu.edu')
options.add_argument('-n', '--dry-run', help="Generate the rules, and return the diff, but do not activate them", action='store_true')
options.add_argument('-p', '--push', help="Activate the current rules. Requires a hash argument to verify they are the rules you are thinking of")
options.add_argument('-u', '--user', help="Who to log did the changes. Defaults to USERNAME_NOT_GIVEN")
options.add_argument('-d', '--description', help='The description of the update. Asks user if not given')
options.add_argument('-s', '--only-sets', help='Only update sets, not rules', action='store_true')
options.add_argument('-e', '--allow-expired', help='Allow expired sets', action='store_true')
options.add_argument('--scriptdir', help='The directory to put scripts in.', default='/root/firewall_scripts')
options.add_argument('--dbuser', help='The database user')
args = options.parse_args()

ssh_orig_cmd = ''
if os.environ.has_key('SSH_ORIGINAL_COMMAND'):
	ssh_orig_cmd = os.environ['SSH_ORIGINAL_COMMAND']
unsafe_args = options.parse_args( shlex.split(ssh_orig_cmd)[1:] )

only_sets = args.only_sets

allow_expired = args.allow_expired

mailto = args.mailto
if '@' not in mailto:
	raise Exception("Invalid mailto address")

if args.user:
	username = args.user
elif unsafe_args.user:
	username = "[%s]"%unsafe_args.user
else:
	username = "USERNAME_NOT_GIVEN"

if args.firewall:
	firewall_id = args.firewall
else:
	firewall_id = socket.gethostname()

description = args.description
if unsafe_args.description:
	if not description:
		description = ''
	description += unsafe_args.description

dry_run = args.dry_run
push = args.push
scriptdir=args.scriptdir

if args.dbuser:
	dbuser = args.dbuser
else:
	dbuser = 'banfw' #legacy, don't ask why

if push and not description:
	raise Exception("A push also requires a description")

datefmt='%Y%m%d-%H%M%S'

DATE=time.strftime(datefmt)

iptables = '/sbin/iptables'
#firewall_id = 'fwser1.oob.usu.edu'

#if len(sys.argv) == 2:
#	username = sys.argv[1]
#else:
#	username = 'USERNAME_NOT_GIVEN'

if os.environ.has_key('SSH_CLIENT'):
	ssh_client=os.environ['SSH_CLIENT'].split()[0]
else:
	ssh_client='[local]'

user_string = '%s@%s' % (username, ssh_client)

#scriptdir='/var/lib/iptables'
if not scriptdir: scriptdir='/root/firewall_scripts'

iface = db.db("host='newdb1.ipam.usu.edu' dbname='fwdb' user='%s'"%dbuser, fw = firewall_id)

valid_chains = iface.get_fw_chains()
chain_patterns_where = " (chain.id in ("+",".join(map(str, valid_chains))+")) "

suffix = "%s-%s" % (DATE, username)

backupdir="%s/backups" % scriptdir

currdir = "%s/current" % scriptdir
newdir = "%s/new-%s" % (scriptdir,suffix)
olddir="%s/pre-%s" % (backupdir,suffix)
faileddir="%s/failed-%s" % (backupdir, suffix)

iptname="%s/iptables.fwdb" % newdir
ipsname="%s/ipsets.fwdb" % newdir

curriptname="%s/iptables.fwdb" % currdir
curripsname="%s/ipsets.fwdb" % currdir

mailname="%s/message" % newdir

tmpiptname="%s/tempipt" % (newdir)
tmpsetname="%s/tempset" % (newdir)

setstore = "%s/ipset.save" % newdir
iptstore = "%s/iptables.save" % newdir

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

def update_set(old, new, outfile=None):
	(remove,add) = old.diff(new)
	changed = False
	for a in add:
		changed = True
		cmd = db.IPSET_ADD % (new.name, a)
		if not outfile:
			runcmd(cmd)
		else:
			outfile.write(cmd)
			outfile.write('\n')

	for r in remove:
		changed = True
		cmd = db.IPSET_DEL % (new.name, r)
		if not outfile:
			runcmd(cmd)
		else:
			outfile.write(cmd)
			outfile.write('\n')
	
	return changed

def update_sets( delete=False, oldcfg=None, newcfg=None, outfile=None ):
	global iface
	if oldcfg is None: oldcfg = db.ipset_list(load_file=None)
	if newcfg is None: newcfg = iface.get_ipset(allow_expired=allow_expired)

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

	changed = add_set_names or del_set_names
	
	if delete:
		for i in del_set_names:
			cmd = db.IPSET_DESTROY % i
			if not outfile:
				runcmd(cmd)
			else:
				outfile.write(cmd)
				outfile.write('\n')
	for name in new_set_names:
		if name in old_set_names:
			if update_set(oldcfg[name], newcfg[name], outfile):
				changed=True
		else:
			update_set(db.ipset(name), newcfg[name], outfile)
			changed=True
	
	return oldcfg, newcfg, changed

def check_dirs( dirs ):
	for d in dirs:
		if not os.path.isdir(d):
			os.makedirs(d)

def generate_ruleset():
	global iface
	new = open(iptname,'w')

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
		for line in iface.get_rules(ipt_restore=True, table=tbl_id):
			if not line:
				raise Exception("Database inconsistency found!")
			new.write(line[0])

		new.write("""COMMIT\n""")

	#new.write("\nEND_OF_IPTABLES_RULES\n")
	new.close()

def genhash(*args):
	# hash the files represented by the given filenames
	h = hashlib.sha512()
	for filename in args:
		f = open(filename)
		h.update(f.read())
		f.close()
	return h.hexdigest()

if __name__ == '__main__':

	if only_sets:
		print "copying current ruleset:"
		shutil.copytree(currdir,newdir)
		print "\tdone."

	check_dirs( [ currdir, backupdir, scriptdir, newdir, ] )

	print "calculating set changes:"
	tmpset = open(tmpsetname, 'w')
	oldcfg, newcfg, sets_changed = update_sets( outfile=tmpset )
	tmpset.close()
	ipsfile = open(ipsname, "w")
	ipsfile.write(str(newcfg))
	ipsfile.close()

	changed = False

	if not only_sets:
		print "generating ruleset:"
		generate_ruleset()

		#generate hash
		rule_hash = genhash(iptname, ipsname)
	
		print "\tdone.\ncomparing to current ruleset:"

		tmpdiff_fd,tmpdiff_name = tempfile.mkstemp()
		os.close(tmpdiff_fd)

		tmpdiff = open(tmpdiff_name,'w')

		# FIXME: this is probably bad form
		#changed = os.system("diff -u '%s' '%s'" % (scriptname, tmpfile))
		changed = subprocess.call(["/usr/bin/diff", '-u', curriptname, iptname,], stdout=tmpdiff)

		tmpdiff.close()

		#tmpdiff = open(tmpdiff_name,'r')
		#for l in tmpdiff:
		#	sys.stdout.write(l)
		#tmpdiff.close()

	if not (changed or sets_changed):
		print '\tconfiguration unchanged.'
		#os.unlink(newdir)
	else:
		print '\tchanges detected\nupdating configuration...'
		# FIXME: this would be a better way, but there is no way to see
		# if the rules are expiring with this run, or had expired
		# before
		# New approach... You may not update rules if some are expired; you must handle all of the rules externally
		if not only_sets:
			expired_rules = iface.get_rules( andwhere=chain_patterns_where, expired=True, enabled=True )

			if expired_rules:
				print "----EXPIRED RULES----"
				for r in expired_rules:
					print r[0]
				print "---------------------"
				expired_rules = [ i[1] for i in expired_rules ]
				expired_rules = sorted(list(set(expired_rules)))
				print '\n'.join(map(str,expired_rules))
				raise Exception("The following expiring rules need to be handled: %s" % " ".join(map(str,expired_rules)))
		if dry_run:
			print open(tmpsetname).read()
			if not only_sets:
				print open(tmpdiff_name).read()
				print "======Hash: %s======"%rule_hash
		else:
			if only_sets:
				x = 'y'
			elif push is None:
				os.system('[ -x /usr/bin/colordiff.disabled ] && CAT=colordiff || CAT=cat; $CAT %s %s | less -XF -R' % (tmpsetname, tmpdiff_name,) )
				x = raw_input('Load new configuration [y/N]: ')
			elif push == rule_hash:
				x = 'y'
			else:
				raise Exception("The configuration has changed since it was last viewed")
			if x != '' and ( x[0]=='y' or x[0]=='Y' ):
				if not description: description = raw_input('Please enter a description of your change: ')
				print '\tsending diff:'
				msg = [
						"Change by: ", user_string, '\n',
						"Firewall: ", firewall_id, '\n',
						"Reason given for change:\n\t",
						description,
						'\n\nHere is the diff:\n\n',
					]
				
				tmpset = open(tmpsetname)
				msg.extend(tmpset.readlines())
				tmpset.close()

				if not only_sets:
					tmpdiff = open(tmpdiff_name,'r+')
					msg.extend(tmpdiff.readlines())
					
				message = open(mailname,'w+')
				message.writelines( msg )

				message.seek(0)
				r = subprocess.call(["mail", '-s', 'Change on %s' % firewall_id, mailto,], stdin=message)
				message.close()

				if r == 0: print "\t\tdone."
				else: print "\t\tfailed."

				print "ipset update:"
				update_sets(newcfg = newcfg)

				status = False
				if not only_sets:
					save = os.system( 'iptables-save -c > %s' % tmpiptname )
					print '\tloading new rules:'
					status = os.system( 'iptables-restore < %s' % iptname )
				if status:
					print '\t\tFAILED! -- loading last working ruleset (storing failed set in %s)' % failedname
					if save:
						# Save failed! Bad!
						status = os.system( 'iptables-restore < %s' % previptname )
					else:
						status = os.system( 'iptables-restore -c < %s' % tmpiptname )
					os.rename(newdir, faileddir)
					if status:
						print '\t\tFAILED! -- Firewall is hosed, someone really needs to fix it'
						print '\t\t!!! flushing all rules !!!'
						os.system('iptables -F')
					sys.exit(1)
				else:
					if not only_sets and not save:
						try:
							write_stats(tmpiptname)
						except Exception, e:
							# We don't want this to cause
							#the update to fail
							print e
							print '\t\tFailed to store statistics.'
					elif not only_sets:
						print "\t\tiptables-save failed, unable to collect statistics"

					if not only_sets:
						print "Final ipset update:"
						update_sets(newcfg = newcfg, delete=True)
						print "done."
				
					os.system( 'iptables-save > %s' % iptstore )
					os.system( 'ipset --save > %s' % setstore )
					print newdir, olddir
					os.rename(currdir, olddir)
					os.rename(newdir, currdir)
					print '\tdone.'

			else:
				print 'NOT updating!'
				exit(1)


	del iface

