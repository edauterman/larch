import time
from multiprocessing import Pool
import concurrent.futures
import argparse
import random
import string
from util.ssh_util import *
from util.ec2_util import *
from util.prop_util import *
from util.math_util import *

# Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY as environment variables

PROJECT="larch"
USERNAME="ec2-user"

SERVER_NAME = "server"
CLIENT_NAME = "client"

def genPrefix(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def getServerName(prefix):
    return "%s-%s" % (prefix, SERVER_NAME)

def getClientName(prefix):
    return "%s-%s" % (prefix, CLIENT_NAME)

def getHostName(ip_addr):
    return "%s@%s" % (USERNAME, ip_addr)

def getIpByName(conn, name):
    ips = list()
    while (len(ips)!=1):
        waitUntilInitialised(conn,name,1)
        # Update the IP addresses
        ips = getEc2InstancesPublicIp(conn, 'Name', {'tag:Name':name}, True)
    return ips[0][1]
 
def getPrivateIpByName(conn, name):
    ips = list()
    while (len(ips)!=1):
        waitUntilInitialised(conn,name,1)
        # Update the IP addresses
        ips = getEc2InstancesPrivateIp(conn, 'Name', {'tag:Name':name}, True)
    return ips[0][1]
 
def provision(prefix, ec2_file, machines_file):
    properties = loadPropertyFile(ec2_file)
    machines = loadPropertyFile(machines_file)

    conn = startConnection(properties["region"])
    print("Started connection")
    key = getOrCreateKey(conn, properties["keyname"])
    print("Got key")

    startEc2Instance(conn, properties["ami_id"], key, properties["server_instance_type"], [properties["security"]], properties["placement"], name=getServerName(prefix), disk_size=properties["disk_size"])

    startEc2Instance(conn, properties["ami_id"], key, properties["client_instance_type"], [properties["security"]], properties["placement"], name=getClientName(prefix), disk_size=properties["disk_size"])
    
    machines['server_ip_address'] = getIpByName(conn, getServerName(prefix))
    machines['client_ip_address'] = getIpByName(conn, getClientName(prefix))

    with open(machines_file, 'w') as f:
        json.dump(machines, f)

def setup_machine(ip_addr, ec2_file):
    properties = loadPropertyFile(ec2_file)
    executeRemoteCommand(getHostName(ip_addr), 'cd larch; git stash; git pull; make > /dev/null &> /dev/null', key=properties['secret_key_path'], flags="-A")
    #executeRemoteCommand(getHostName(ip_addr), 'cd larch; git stash; rm scripts/totp_experiments.py; git pull', key=properties['secret_key_path'], flags="-A")
    #executeRemoteCommand(getHostName(ip_addr), 'ssh-keyscan github.com >> ~/.ssh/known_hosts; git clone git@github.com:edauterman/larch.git', key=properties['secret_key_path'], flags="-A")

def setupAll(ec2_file, machines_file):
    properties = loadPropertyFile(ec2_file)
    machines = loadPropertyFile(machines_file)

    setup_machine(machines['server_ip_address'], ec2_file)
    setup_machine(machines['client_ip_address'], ec2_file)

def provisionAndSetupAll(prefix, ec2_file, machines_file):
    provision(prefix, ec2_file, machines_file)
    time.sleep(60)
    setupAll(ec2_file, machines_file)

def teardown(prefix, ec2_file):
    properties = loadPropertyFile(ec2_file)
    conn = startConnection(properties['region'])
    key = getOrCreateKey(conn, properties['keyname'])
    server_id = getEc2InstancesId(
        conn, 'Name', {'tag:Name':getServerName(prefix)}, True)
    terminateEc2Instances(conn, server_id)
    client_id = getEc2InstancesId(
        conn, 'Name', {'tag:Name':getClientName(prefix)}, True)
    terminateEc2Instances(conn, client_id)
