include os
include sys
from exp_setup import *

EC2_FILE = "config/ec2.json"
MACHINES_FILE = "config/totp_machines.json"

def run_totp_exp():
    executeCommand("mkdir totp_exp")
    provisionAndSetupAll(EC2_FILE, MACHINES_FILE)
    properties = loadPropertyFile(EC2_FILE)
    machines = loadPropertyFile(MACHINES_FILE)

    executeRemoteCommand(getHostName(machines['client_ip_addr']), 'mkdir totp_exp', key=properties['secret_key_path'])
    for i in range(20,120,20):
        executeRemoteCommand(getHostName(machines['server_ip_addr']), 'pkill -f server; cd zkboo-r1cs; ./totp/bin/server%d' % i, key=properties['secret_key_path'])
        time.sleep(10)
        executeRemoteCommand(getHostName(machines['client_ip_addr']), 'cd zkboo-r1cs; ./totp/bin/client%d-init %s' % (i, machines['server_ip_addr']), key=properties['secret_key_path']) 
        executeRemoteCommand(getHostName(machines['client_ip_addr']), 'cd zkboo-r1cs; ./totp/bin/client%d-auth %s 0 ~/totp_exp/out_%d' % (i, machines['server_ip_addr'], i), key=properties['secret_key_path']) 

    getDirectory('.', getHostName(machines['client_ip_addr']), '~/totp_exp', key=properties['secret_key_path'])

