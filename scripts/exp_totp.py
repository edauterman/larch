import os
import sys
from setup import *

EC2_FILE = "config/ec2.json"
MACHINES_FILE = "config/totp_machines.json"

def run_totp_latency():
    provisionAndSetupAll(EC2_FILE, MACHINES_FILE)
    properties = loadPropertyFile(EC2_FILE)
    machines = loadPropertyFile(MACHINES_FILE)

    executeRemoteCommand(getHostName(machines['client_ip_address']), 'mkdir totp_exp', key=properties['secret_key_path'])
    for i in range(20,120,20):
        executeRemoteCommand(getHostName(machines['server_ip_address']), 'pkill -f server', key=properties['secret_key_path'])
        executeRemoteCommand(getHostName(machines['server_ip_address']), 'cd zkboo-r1cs; nohup ./totp/bin/server%d > /dev/null 2>&1 &' % i, key=properties['secret_key_path'])
        time.sleep(10)
        executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd zkboo-r1cs; ./scripts/wan.sh M; ./totp/bin/client%d-init %s' % (i, machines['server_ip_address']), key=properties['secret_key_path']) 
        executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd zkboo-r1cs; ./totp/bin/client%d-auth %s 0 ~/totp_exp/out_%d' % (i, machines['server_ip_address'], i), key=properties['secret_key_path']) 

    getDirectory('.', [getHostName(machines['client_ip_address'])], '~/totp_exp', key=properties['secret_key_path'])
    teardown(EC2_FILE)

def run_totp_tput():
    ec2_file = "config/ec2_tput_1.json"
    provisionAndSetupAll(ec2_file, MACHINES_FILE)
    properties = loadPropertyFile(ec2_file)
    machines = loadPropertyFile(MACHINES_FILE)

    executeRemoteCommand(getHostName(machines['client_ip_address']), 'mkdir totp_exp', key=properties['secret_key_path'])
    i = 20
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'pkill -f server', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'cd zkboo-r1cs; nohup ./totp/bin/server%d > /dev/null 2>&1 &' % i, key=properties['secret_key_path'])
    time.sleep(10)
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd zkboo-r1cs; ./scripts/wan.sh M; ./totp/bin/client%d-init %s' % (i, machines['server_ip_address']), key=properties['secret_key_path']) 
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd zkboo-r1cs; ./totp/bin/client%d-auth %s 0 ~/totp_exp/out_%d_1' % (i, machines['server_ip_address'], i), key=properties['secret_key_path']) 
    getDirectory('.', [getHostName(machines['client_ip_address'])], '~/totp_exp', key=properties['secret_key_path'])
    teardown(ec2_file)

executeCommand("mkdir totp_exp")
run_totp_latency()
run_totp_tput()

