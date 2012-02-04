#!/usr/bin/env python

import IPy
import db
import os
import sys

import re

import datetime

import cjson

dbname='fwdb'

if os.environ.has_key('USER'):
	my_username = os.environ['USER']
else:
	raise Exception("Need USER environment variable set.")

def do_sync(fw):
	if not re.match('^[0-9a-zA-Z.-]+$',fw):
		raise Exception("Got invalid firewall: %s" % fw)
	ret = os.system('ssh root@%s /bin/false' % fw)
	if ret:
		print 'Error updating firewall %s: returned %s' % (fw, ret)

DEFAULT_BLOCK_DAYS=30

if __name__ == '__main__':
	iface = db.db("dbname=%s host=newdb1.ipam.usu.edu" % dbname)

	data = sys.stdin.readline()
	args = cjson.decode(data)

	try:
		addresses = [IPy.IP(a) for a in args['addresses']]
	except:
		print "Bad input. No donut."
		raise

	to_add = []

	SET_NAME = args['set_name']
	BLOCK_DAYS = int(args['block_days']) if args.has_key('block_days') else DEFAULT_BLOCK_DAYS
	OWNER = args['owner']
	DESCRIPTION = args['description']
	os.environ['DESCRIPTION'] = DESCRIPTION


	group = iface.get_hosts( name=SET_NAME, is_group=True )
	if len(group) != 1:
		raise Exception("Invalid group specified: %s (got: %r)" % (SET_NAME,group))
	group = group[0]

	expires=(datetime.datetime.today() + datetime.timedelta(BLOCK_DAYS)).strftime('%Y-%m-%d')

	HOST_PREFIX=SET_NAME+'_'
	for address in addresses:
		host = iface.get_hosts(ip='%s/%s' % (address,address.prefixlen()))
		if len(host) == 0:
			host_id = iface.add_host(name=HOST_PREFIX+str(address),
					address=address,
					endaddress=None,
					owner_name=OWNER,
					description=DESCRIPTION
					)
			print host_id
			assert len(host_id) == 1
			host_id = host_id[0]
			host = iface.get_hosts(host_ids=host_id)
		elif len(host) == 1:
			host = host[0]
			# do we like this guy or not?
			if SET_NAME not in host['name']:
				print "You really need to look at %r" % host
				raise Exception("Cowardly refusing to add host %r to set %s" % (host,SET_NAME))
		else:
			raise Exception("Multiple hosts returned for %s: %r" % (address, host))
		to_add.append(host)
	changed = False
	for host in to_add:
		groups = iface.get_groups(host_id=host['hosts.id'], columns=['hosts.id'])
		for g in groups:
			if g['hosts.id'] == group['hosts.id']:
				print 'Host is already in group %s, ignoring: %r' % (SET_NAME,host['name'])
				break
		else:
			iface.add_host_to_group( host_id=host['hosts.id'], group_id = group['hosts.id'], expires = expires )
			changed = True
	
	if not changed:
		print 'No changes made.  Not syncing firewalls.'
		exit(1)

	# If you made it this far, your chances are pretty good
	firewalls = iface.get_firewalls(name='fwborder%')
	for fw in firewalls:
		do_sync(fw['name'])


