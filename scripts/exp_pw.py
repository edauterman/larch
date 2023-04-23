import os
import sys
from setup import *

EC2_FILE = "config/ec2.json"
MACHINES_FILE = "config/pw_machines.json"

def run_pw_latency():
    provisionAndSetupAll(EC2_FILE, MACHINES_FILE)
    properties = loadPropertyFile(EC2_FILE)
    machines = loadPropertyFile(MACHINES_FILE)

    executeRemoteCommand(getHostName(machines['client_ip_address']), 'mkdir ~/pw_exp', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'pkill -f pw_log', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'cd larch; nohup ./build/bin/pw_log > /dev/null 2>&1 &', key=properties['secret_key_path'])
    time.sleep(10)
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./scripts/wan.sh M', key=properties['secret_key_path']) 
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./build/bin/pw_latency_bench %s ~/pw_exp/out' % (machines['server_ip_address']), key=properties['secret_key_path']) 

    getDirectory('.', [getHostName(machines['client_ip_address'])], '~/pw_exp', key=properties['secret_key_path'])
    teardown(EC2_FILE)

def run_pw_tput():
    ec2_file = "config/ec2_tput_1.json"
    provisionAndSetupAll(ec2_file, MACHINES_FILE)
    properties = loadPropertyFile(ec2_file)
    machines = loadPropertyFile(MACHINES_FILE)

    executeRemoteCommand(getHostName(machines['client_ip_address']), 'mkdir ~/pw_exp', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'pkill -f pw_log', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'cd larch; nohup ./build/bin/pw_log > /dev/null 2>&1 &', key=properties['secret_key_path'])
    time.sleep(10)
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./scripts/wan.sh M', key=properties['secret_key_path']) 
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./build/bin/pw_latency_bench %s ~/pw_exp/out_1' % (machines['server_ip_address']), key=properties['secret_key_path']) 

    getDirectory('.', [getHostName(machines['client_ip_address'])], '~/pw_exp', key=properties['secret_key_path'])
    teardown(ec2_file)

executeCommand("mkdir pw_exp")
run_pw_latency()
run_pw_tput()

