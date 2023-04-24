import os
import sys
from setup import *

EC2_FILE = "config/ec2.json"
MACHINES_FILE = "config/totp_machines.json"

ITERS = 10

def run_totp_latency():
    prefix = genPrefix()
    provisionAndSetupAll(prefix, EC2_FILE, MACHINES_FILE)
    properties = loadPropertyFile(EC2_FILE)
    machines = loadPropertyFile(MACHINES_FILE)

    executeRemoteCommand(getHostName(machines['client_ip_address']), 'mkdir -p totp_exp', key=properties['secret_key_path'])
    for i in range(20,120,20):
        for j in range(ITERS):
            executeRemoteCommandNoCheck(getHostName(machines['server_ip_address']), 'pkill -f server > /dev/null &> /dev/null', key=properties['secret_key_path'])
            executeRemoteCommand(getHostName(machines['server_ip_address']), 'cd larch; nohup ./totp/bin/server%d > /dev/null 2>&1 &' % i, key=properties['secret_key_path'])
            time.sleep(1)
            executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./scripts/wan.sh M; ./totp/bin/client%d-init %s' % (i, machines['server_ip_address']), key=properties['secret_key_path']) 
            executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./totp/bin/client%d-auth %s 0 ~/totp_exp/out_%d_raw' % (i, machines['server_ip_address'], i), key=properties['secret_key_path']) 

    getDirectory('out_data/', [getHostName(machines['client_ip_address'])], '~/totp_exp', key=properties['secret_key_path'])
    teardown(prefix, EC2_FILE)

def run_totp_tput():
    ec2_file = "config/ec2_tput_1.json"
    prefix = genPrefix()
    provisionAndSetupAll(prefix, ec2_file, MACHINES_FILE)
    properties = loadPropertyFile(ec2_file)
    machines = loadPropertyFile(MACHINES_FILE)

    executeRemoteCommand(getHostName(machines['client_ip_address']), 'mkdir -p totp_exp', key=properties['secret_key_path'])
    i = 20
    for j in range(ITERS):
        executeRemoteCommandNoCheck(getHostName(machines['server_ip_address']), 'pkill -f server > /dev/null &> /dev/null', key=properties['secret_key_path'])
        executeRemoteCommand(getHostName(machines['server_ip_address']), 'cd larch; nohup ./totp/bin/server%d > /dev/null 2>&1 &' % i, key=properties['secret_key_path'])
        time.sleep(1)
        executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./scripts/wan.sh M; ./totp/bin/client%d-init %s' % (i, machines['server_ip_address']), key=properties['secret_key_path']) 
        executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./totp/bin/client%d-auth %s 0 ~/totp_exp/out_%d_1_raw' % (i, machines['server_ip_address'], i), key=properties['secret_key_path']) 
    getDirectory('out_data/', [getHostName(machines['client_ip_address'])], '~/totp_exp', key=properties['secret_key_path'])
    teardown(prefix, ec2_file)

run_totp_latency()
run_totp_tput()

