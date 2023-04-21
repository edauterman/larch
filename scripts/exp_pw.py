import os
import sys
from setup import *

EC2_FILE = "config/ec2.json"
MACHINES_FILE = "config/pw_machines.json"

def run_pw_exp():
    executeCommand("mkdir pw_exp")
    provisionAndSetupAll(EC2_FILE, MACHINES_FILE)
    properties = loadPropertyFile(EC2_FILE)
    machines = loadPropertyFile(MACHINES_FILE)

    executeRemoteCommand(getHostName(machines['client_ip_address']), 'mkdir ~/pw_exp', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'pkill -f pw_log', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'cd zkboo-r1cs; nohup ./build/bin/pw_log > /dev/null 2>&1 &', key=properties['secret_key_path'])
    time.sleep(10)
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd zkboo-r1cs; ./scripts/wan.sh M', key=properties['secret_key_path']) 
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd zkboo-r1cs; ./build/bin/pw_latency_bench %s ~/pw_exp/out' % (machines['server_ip_address']), key=properties['secret_key_path']) 

    getDirectory('.', [getHostName(machines['client_ip_address'])], '~/pw_exp', key=properties['secret_key_path'])
    teardown(EC2_FILE)

run_pw_exp()

