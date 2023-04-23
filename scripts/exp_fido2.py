import os
import sys
from setup import *

EC2_FILE = "config/ec2.json"
MACHINES_FILE = "config/fido2_machines.json"

def measure_cores(num_client_cores):
    ec2_file = "config/ec2_fido2_%d.json" % num_client_cores
    provisionAndSetupAll(ec2_file, MACHINES_FILE)
    properties = loadPropertyFile(ec2_file)
    machines = loadPropertyFile(MACHINES_FILE)
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'mkdir -p fido2_exp', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'if pgrep log; then pkill -f log > /dev/null &> /dev/null; fi', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'cd larch; nohup ./build/bin/log > /dev/null 2>&1 &', key=properties['secret_key_path'])
    time.sleep(10)
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./scripts/wan.sh M; ./build/bin/auth_bench %s ~/fido2_exp/out_latency_%d' % (machines['server_ip_address'], num_client_cores), key=properties['secret_key_path']) 
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./build/bin/proof_bench ~/fido2_exp/out_proof_%d' % (num_client_cores), key=properties['secret_key_path']) 
    getDirectory('out_data/', [getHostName(machines['client_ip_address'])], '~/fido2_exp', key=properties['secret_key_path'])
    teardown(ec2_file)


def measure_throughput():
    ec2_file = "config/ec2_tput_1.json"
    provisionAndSetupAll(ec2_file, MACHINES_FILE)
    properties = loadPropertyFile(ec2_file)
    machines = loadPropertyFile(MACHINES_FILE)
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'mkdir -p fido2_exp', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'if pgrep log; then pkill -f log > /dev/null &> /dev/null; fi', key=properties['secret_key_path'])
    executeRemoteCommand(getHostName(machines['server_ip_address']), 'cd larch; nohup ./build/bin/log > /dev/null 2>&1 &', key=properties['secret_key_path'])
    time.sleep(10)
    executeRemoteCommand(getHostName(machines['client_ip_address']), 'cd larch; ./scripts/wan.sh M; ./build/bin/throughput_bench %s ~/fido2_exp/out_tput' % (machines['server_ip_address']), key=properties['secret_key_path']) 
    getDirectory('out_data/', [getHostName(machines['client_ip_address'])], '~/fido2_exp', key=properties['secret_key_path'])
    teardown(ec2_file)
 
def run_fido2_exp():
    """
    client_cores = [1,2,4,8]
    for cores in client_cores:
        measure_cores(cores)
    """
    measure_throughput()

run_fido2_exp()

