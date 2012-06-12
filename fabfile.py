# a fabfile for prototyping a grid engine cluster in amazon ec2
#
# Copyright (C) 2011-2012 Gavin Burris
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm
import os
import boto
import time
import socket
import subprocess

env.disable_known_hosts=True
env.user = 'root'
user = os.getenv("USER")
home = os.getenv("HOME")
env.key_filename = home+'/.ssh/ec2-fab00-key.pem'

def find_node(node):
    """
    Return the instance object of a given node hostname.
    """
    grid = boto.connect_ec2()
    instances = grid.get_all_instances()
    for reservation in instances:
	for inst in reservation.instances:
	    if inst.tags.get('Name') == node and inst.state == 'running':
		print 'found', inst.tags.get('Name'), inst.dns_name
		return inst

#qmaster=find_node('fabnode0')
#env.host_string=qmaster.dns_name
#grid = boto.connect_ec2()
#run('hostname')


def gridinit(cn='fab'):
    """
    Initialize the security settings required for cluster creation.
    """
    # connect to amazon
    grid = boto.connect_ec2()

    # generate ssh keys for remote access
    key_pair = grid.create_key_pair('ec2-'+cn+'00-key')
    key_pair.save(home+'/.ssh')

    # define security group and firewall rules
    fabsec = grid.create_security_group(cn+'sec', 'Fabric Cluster '+cn)
    fabsec.authorize('tcp', 22, 22, '0.0.0.0/0')
    fabsec.authorize(src_group=fabsec)

    # define placement group for common virtual network
    fabcluster = grid.create_placement_group(cn+'cluster', strategy='cluster')


def gridlist():
    """
    List all active ec2 instances and volumes.
    """
    grid = boto.connect_ec2()

    # get all instances
    instances = grid.get_all_instances()
    for reservation in instances:
	for inst in reservation.instances:
	    if inst.tags.get('state') == 'active':
		print inst.id, inst.image_id, inst.instance_type, inst.tags.get('Name'), inst.state, inst.dns_name
    
    # get all volumes
    volumes = grid.get_all_volumes()
    for vol in volumes:
	if vol.tags.get('state') == 'active':
	    print vol.id, vol.tags.get('Name'), vol.size, vol.status


def amzn_fix(cn,host):
    """
    Amazon's image has some quirks as compared to vanilla CentOS.
    """
    env.host_string = host
    env.user = 'ec2-user'
    env.key_filename = home+'/.ssh/ec2-'+cn+'00-key.pem'

    # modify sshd config and root key to allow root login
    run('sudo sed -i.bak -e\'s/PermitRootLogin\ forced-commands-only/PermitRootLogin\ without-password/g\' /etc/ssh/sshd_config', shell=True, pty=True)
    run('sudo cp -f /home/ec2-user/.ssh/authorized_keys /root/.ssh/authorized_keys', shell=True, pty=True)
    with hide('stdout'):
	run('sudo service sshd reload', shell=True, pty=True)

    # enable nfs server
    run('sudo yum -q -y install nfs-utils', shell=True, pty=True)
    run('sudo sed -i.bak -e\'s/\#Domain\ =\ local\.domain\.edu/Domain\ =\ ec2\.internal/g\' /etc/idmapd.conf', shell=True, pty=True)
    with settings(warn_only=True):
	with hide('stdout'):
	   run('sudo service rpcbind start', shell=True, pty=True)
	   run('sudo service rpcidmapd start', shell=True, pty=True)
	   run('sudo service nfslock start', shell=True, pty=True)
	   run('sudo service nfs start', shell=True, pty=True)
    

def gridmake(cn='fab',howmany=0,ami='ami-e565ba8c',itype='t1.micro'):
    """
    Create the cluster head node.
    """
    # connect
    grid = boto.connect_ec2()

    # US East N. Virginia EBS-Backed 64-bit 
    # amazon/amzn-ami-pv-2012.03.1.x86_64-ebs 
    # Amazon Linux AMI release 2012.03
    ami = 'ami-e565ba8c'
    itype = 't1.micro'

    # US East N. Virginia Cluster Compute EBS-Backed 64-bit 
    # amazon/amzn-ami-hvm-2012.03.1.x86_64-ebs
    # Amazon Linux AMI release 2012.03
    #ami = 'ami-e965ba80'
    #itype = 'cc1.4xlarge'

    aminfo = grid.get_image(ami)

    # set placement group for HPC networking
    if itype == 'cc1.4xlarge':
    	pgroup = cn+'cluster'
    else:
    	pgroup = None

    # set ssh key and disable prompting for unkown hosts
    env.disable_known_hosts=True
    env.user = 'root'
    env.key_filename = home+'/.ssh/ec2-'+cn+'00-key.pem'

    # create a reservation with our qmaster instance
    print 'Reserving', int(howmany)+1, 'instances of', aminfo.id, itype, aminfo.name, aminfo.region, 'for', cn+'node cluster.'
    reservation = grid.run_instances(image_id=ami, key_name='ec2-'+cn+'00-key', instance_type=itype, security_groups=['default',cn+'sec'], placement_group=pgroup)
    qmaster = reservation.instances[0]
    time.sleep(10)
    while not qmaster.update() == 'running':
	print 'waiting for '+cn+'node0 boot...'
        time.sleep(15)

    # tag instance for organization
    qmaster.add_tag('Name', cn+'node0')
    qmaster.add_tag('type', cn+'node')
    qmaster.add_tag('state', 'active')
    print qmaster.id, qmaster.tags.get('Name'), qmaster.state, qmaster.dns_name

    # test socket connect to ssh service
    while True:
	try:
	    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    sock.settimeout(1)
	    sock.connect((qmaster.dns_name, 22))
	    break
	except:
	    print 'waiting for '+cn+'node0 ssh daemon...'
	    time.sleep(15)
	finally:
	    sock.close()
    print 'connecting to', qmaster.dns_name
    time.sleep(15)
    env.host_string=qmaster.dns_name

    # enable root login on Amazon Linux
    if 'amzn' in aminfo.name:
	amzn_fix(cn,qmaster.dns_name)

    # set hostname to something usable
    env.user = 'root'
    run('hostname '+cn+'node0')
    run('echo "HOSTNAME='+cn+'node0" >> /etc/sysconfig/network')
    run('echo "`ifconfig | grep \'\\<inet\\>\' | sed -n \'1p\' | tr -s \' \' | cut -d \' \' -f3 | cut -d \':\' -f2` '+cn+'node0" >>/etc/hosts')

    # generate root keys for cluster
    run('ssh-keygen -q -f /root/.ssh/id_rsa -N ""')
    run('mkdir -p /usr/global/tmp')
    run('cp /root/.ssh/id_rsa.pub /usr/global/id_rsa.pub.'+cn+'node0')
    run('cat /usr/global/id_rsa.pub.'+cn+'node0 >> /root/.ssh/authorized_keys')

    ## create a 4x25G striped EBS volume
    #raid_size = 25
    #print "creating RAID for /home"
    #raid_count = 105+4
    #for i in map(chr, range(105, raid_count)):
    #    r0 = grid.create_volume(raid_size, qmaster.placement)
    #    r0.attach(qmaster.id, '/dev/sd'+i)
    #    r0.add_tag('Name', cn+'node0-sd'+i)
    #    r0.add_tag('type', cn+'raid')
    #    r0.add_tag('state', 'active')
    #time.sleep(30)

    ## set IO scheduler
    #for i in map(chr, range(105, raid_count)):
    #	run('echo "echo deadline > /sys/block/sd'+i+'/queue/scheduler" >> /etc/init.d/deadline')
    #run('chmod +x /etc/init.d/deadline')
    #run('/etc/init.d/deadline > /dev/null 2>&1')
    #run('ln -s /etc/init.d/deadline /etc/rc5.d/S99deadline')

    ## format lvm & ext3, mount as home
    #sdx = ''
    #for i in map(chr, range(105, raid_count)):
    #    sdx = sdx + ' /dev/sd' + i 	
    #run('pvcreate ' + sdx)
    #run('vgcreate EBSVolGroup00 ' + sdx)
    #run('lvcreate -i 4 -I 1024 --extents 100%VG --name EBSLogVol00 EBSVolGroup00')
    #run('mkfs -t ext3 -q -m 0 -L '+cn+'00 -O dir_index,filetype,has_journal,sparse_super /dev/EBSVolGroup00/EBSLogVol00')
    #run('echo "/dev/EBSVolGroup00/EBSLogVol00 /home ext3 defaults,noatime 0 0" >>/etc/fstab')
    #run('mount /home')

    # install grid engine master
    run('mkdir -p /usr/global')
    put('ge2011.11.tar.gz', '/usr/global/')
    put('fabgrid.conf', '/usr/global/')
    run('adduser -u 186 sgeadmin')
    run('sed -i.bak -e\'s/FAB/'+cn+'/g\' /usr/global/fabgrid.conf')
    with cd('/usr/global'):
        run('tar xzf ge2011.11.tar.gz')
	run('ln -s ge2011.11 sge')
        run('chown -R sgeadmin.sgeadmin /usr/global/sge/')
    with cd('/usr/global/sge'):
	with settings(warn_only=True):
	    run('./inst_sge -m -x -noremote -auto /usr/global/fabgrid.conf >/usr/global/tmp/inst_sge.'+cn+'node0.out 2>&1')
    run('echo ". /usr/global/sge/default/common/settings.sh" >> /root/.bashrc')

    # enable network filesystem
    #run('ifconfig eth0 mtu 9000')
    #run('echo "MTU=9000" >> /etc/sysconfig/network-scripts/ifcfg-eth0')
    run('echo "RPCNFSDCOUNT=32" >>/etc/sysconfig/nfs')
    run('chkconfig nfs on')
    with hide('stdout'):
        with settings(warn_only=True):
	   run('if [ -f /sbin/portmap ] ; then service portmap restart ; fi', shell=True, pty=True)
    	   run('if [ -f /sbin/rpcbind ] ; then service rpcbind restart ; fi', shell=True, pty=True)
    	   run('service nfslock restart', shell=True, pty=True)
    	   run('service nfs restart', shell=True, pty=True)

    # add user account with keys
    run('adduser -u 1000 '+user)
    run('echo ". /usr/global/sge/default/common/settings.sh" >> /home/'+user+'/.bashrc')
    run('su - '+user+' -c \'ssh-keygen -q -f ~/.ssh/id_rsa -N ""\'')
    put('/home/'+user+'/.ssh/authorized_keys.shadow', '/home/'+user+'/.ssh/')
    run('su - '+user+' -c "cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys"')
    run('su - '+user+' -c "cat ~/.ssh/authorized_keys.shadow >> ~/.ssh/authorized_keys"')
    run('cat ~'+user+'/.ssh/authorized_keys.shadow >> /root/.ssh/authorized_keys')
    run('su - '+user+' -c "chmod go= ~/.ssh/authorized_keys"')

    # set random root password
    run('cat /dev/urandom | tr -dc "a-z0-9" | fold -w 48 | head -n 1 | passwd --stdin root')

    # build exec nodes
    if howmany:
	gridgrow(cn,howmany)


def gridterm(cn='fab'):
    """
    Terminate all ec2 instances for a given cluster.
    """
    # are we sure?
    #if not confirm('About to terminate all '+cn+'node instances.  Continue?'):
    #	abort("Aborting at user request.")

    # connect and get all instances
    grid = boto.connect_ec2()
    instances = grid.get_all_instances()

    # get head node instance
    qmaster=find_node(cn+'node0')
    
    # terminate all nodes of given cluster
    for reservation in instances:
        for inst in reservation.instances:
	    if inst.tags.get('type') == cn+'node' and inst.tags.get('state') == 'active':
		inst.add_tag('state', 'terminated')
		print 'TERMINATING', inst.tags.get('Name'), inst.dns_name
		inst.terminate()

    ## delete storage raid volumes after head node shutdown
    #while not qmaster.update() == 'terminated':
    #	print 'waiting for '+cn+'node0 shutdown...'
    #	time.sleep(15)
    #volumes = grid.get_all_volumes()
    #for vol in volumes:
    #	if vol.tags.get('type') == cn+'raid' and vol.tags.get('state') == 'active':
    #	    vol.add_tag('state', 'deleted')
    #	    print 'DELETING', vol.tags.get('Name')
    #	    vol.delete()


def gridgrow(cn='fab',newcount='1'):
    """
    Build and add N execution hosts to a given cluster.
    """
    env.disable_known_hosts=True
    env.user = 'root'
    env.key_filename = home+'/.ssh/ec2-'+cn+'00-key.pem'

    # connect
    grid = boto.connect_ec2()
    instances = grid.get_all_instances()
    nodelist = []
    nodecount = 0

    # walk thru instances, count and build a list of node instances
    for reservation in instances:
        for inst in reservation.instances:
	    if inst.tags.get('type') == cn+'node' and inst.state == 'running':
		#print 'found', inst.tags.get('Name'), inst.dns_name
		nodelist.append(inst)
		nodecount += 1

    # install each new node
    nodecountm = nodecount
    spq = []
    for node_inst in range(int(newcount)):
	sp = subprocess.Popen(['fab', 'install_node:'+cn+','+str(nodecount)])
	spq.append(sp)
	nodecount += 1

    # wait for each subprocces to finish
    nodecount = nodecountm
    for node_inst in range(int(newcount)):
	sp = spq.pop()
	sp.wait()
	nodecount += 1
    print 'Finished installing additional nodes.'


def install_node(cn, node_num):
    """
    Create a node in a given cluster.
    """
    env.disable_known_hosts=True
    env.user = 'root'
    env.key_filename = home+'/.ssh/ec2-'+cn+'00-key.pem'

    # identify qmaster and image type
    qmaster = find_node(cn+'node0')
    ami = qmaster.image_id
    itype = qmaster.instance_type

    # set placement group for HPC networking
    if itype == 'cc1.4xlarge':
    	pgroup = cn+'cluster'
    else:
    	pgroup = None

    # create new node instance
    grid = boto.connect_ec2()
    node_reservation = grid.run_instances(image_id=ami, key_name='ec2-'+cn+'00-key', instance_type=itype, security_groups=['default',cn+'sec'], min_count=1, max_count=1, placement_group=pgroup)

    # identify new instance
    execnode = node_reservation.instances[0]
    aminfo = grid.get_image(ami)
    time.sleep(10)

    # node hostname
    N = str(node_num)
    node = cn+'node'+N

    # wait for boot
    while not execnode.update() == 'running':
	print 'waiting for', node, 'boot...'
        time.sleep(15)
    execnode.add_tag('Name', node)
    execnode.add_tag('type', cn+'node')
    execnode.add_tag('state', 'active')
    print execnode.id, execnode.tags.get('Name'), execnode.state, execnode.dns_name

    # wait for socket connect to ssh daemon
    while True:
	try:
	    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    sock.settimeout(1)
	    sock.connect((execnode.dns_name, 22))
	    break
	except:
	    print 'waiting for', node, 'ssh daemon...'
	    time.sleep(15)
	finally:
	    sock.close()
    print 'connecting to', execnode.dns_name
    time.sleep(15)
    env.host_string=execnode.dns_name

    # enable root login on Amazon Linux
    if 'amzn' in aminfo.name:
	amzn_fix(cn,execnode.dns_name)

    # set hostname to something usable
    env.user = 'root'
    run('hostname '+node)
    run('echo HOSTNAME='+node+' >>/etc/sysconfig/network')

    # set random root password
    run('cat /dev/urandom | tr -dc "a-z0-9" | fold -w 48 | head -n 1 | passwd --stdin root')

    # build /etc/hosts for name resolution
    qmhostip = 'echo ' +  qmaster.private_ip_address  + ' ' + cn+'node0' + ' >>/etc/hosts'
    exhostip = 'echo ' +  execnode.private_ip_address + ' ' + node       + ' >>/etc/hosts'
    run(qmhostip)
    run(exhostip)

    # add node to allowed nfs clients and queue hosts
    env.host_string=qmaster.dns_name
    run(exhostip)
    run('echo "/home '+node+'(rw,async,no_root_squash)" >>/etc/exports')
    run('echo "/usr/global '+node+'(rw,async,no_root_squash)" >>/etc/exports')
    run('exportfs -ar')
    run('qconf -ah '+node)

    # collect ssh keys
    run('ssh-keyscan -t rsa '+node+' >>/etc/ssh/ssh_known_hosts')

    # mount optimized nfs
    env.host_string=execnode.dns_name
    with hide('stdout'):
	with settings(warn_only=True):
	    run('if [ -f /sbin/portmap ] ; then service portmap restart ; fi', shell=True, pty=True)
	    run('if [ -f /sbin/rpcbind ] ; then service rpcbind restart ; fi', shell=True, pty=True)
	    run('service nfslock restart', shell=True, pty=True)
	    run('service nfs restart', shell=True, pty=True)
    run('echo "'+cn+'node0:/usr/global /usr/global nfs noatime,noac,rsize=8192,wsize=8192,hard,intr,vers=3 0 0" >>/etc/fstab')
    run('mkdir /usr/global ; mount /usr/global')
    run('echo "'+cn+'node0:/home /home nfs noatime,noac,rsize=8192,wsize=8192,hard,intr,vers=3 0 0" >>/etc/fstab')
    run('mount /home')
    #rsize=32768,wsize=32768

    ## increasing the default TCP receive memory size & mount optimized nfs
    #run('echo "net.ipv4.tcp_rmem = 4096 2621440 16777216" >> /etc/sysctl.conf')
    #run('sysctl -p > /dev/null 2>&1')
    #run('ifconfig eth0 mtu 9000')

    # enable grid engine environment
    run('cat /usr/global/id_rsa.pub.'+cn+'node0 >> /root/.ssh/authorized_keys')
    run('echo ". /usr/global/sge/default/common/settings.sh" >> /root/.bashrc')
    run('adduser -u 186 sgeadmin')
    run('adduser -u 1000 '+user)
    with cd('/usr/global/sge'):
	with settings(warn_only=True):
	    run('./inst_sge -x -noremote -auto /usr/global/fabgrid.conf >/usr/global/tmp/inst_sge.'+node+'.out 2>&1')

    # sync auth
    env.host_string=qmaster.dns_name
    run('rsync /etc/passwd /etc/shadow /etc/group /etc/hosts '+node+':/etc/')


### DEMO
# fab gridinit:foo
# fab gridmake:foo,2
# fab gridgrow:foo,2
# fab gridlist
# ssh ec2-NNN-NN-NNN-NNN.compute-1.amazonaws.com
# qstat -g c
# qstat -F explain
# su - bug
# for I in `seq 1 100`; do qsub /usr/global/sge/examples/jobs/simple.sh; done
# watch qstat
# cat simple.sh.*
# fab gridterm:foo


