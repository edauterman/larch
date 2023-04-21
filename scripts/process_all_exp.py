import os
import json

field_elem_size = 32
ecdsa_sig_size = 2 * field_elem_size
aes_ct_size = 16
timestamp_size = 8
elgamal_ct_size = 66

min_core_hour_cost = 0.0425
max_core_hour_cost = 0.085
min_out_gb_cost = 0.05
max_out_gb_cost = 0.09

server_cores = 8

def proof_size_bytes(log_len):
    return (33 * 4 * log_len) + (32 * 3 * log_len) + 32 + 4

comm = []
log_len = range(1,10)
lens = [1 << i for i in log_len]

for i in log_len:
    # add 66 for elgamal ct
    comm.append((2.0 * proof_size_bytes(i) + 66.0) / 1024.0)

results = dict()
results["online_time_ms"] = dict()
results["total_time_ms"] = dict()
results["online_comm_kb"] = dict()
results["total_comm_kb"] = dict()
results["out_total_comm_kb"] = dict()
results["auth_record_b"] = dict()
results["log_presig_b"] = dict()
results["auths_per_core"] = dict()
results["10M_min_cost"] = dict()
results["10M_max_cost"] = dict()

# Parse FIDO2
with open('fido2_exp/out_latency_4', 'r') as f:
    lines = f.readlines()
    results["online_time_ms"]["fido2"] = float(lines[1])
    results["total_time_ms"]["fido2"] = float(lines[1])

with open('fido2_exp/out_tput', 'r') as f:
    lines = f.readlines()
    results['auths_per_core']['fido2'] = float(lines[0]) / float(server_cores)

results['log_presig_b']['fido2'] = 6 * field_elem_size
results['auth_record_b']['fido2'] = ecdsa_sig_size + aes_ct_size + timestamp_size

# TODO get the numbers for this
results['online_comm_kb']['fido2'] = 0
results['total_comm_kb']['fido2'] = 0
results['out_total_comm_kb']['fido2'] = 0 
# separately get in_comm

results["10M_min_cost"]["fido2"] = 10e6 * (1.0 / results['auths_per_core']['fido2'] * min_core_hour_cost + results["out_total_comm_kb"]["fido2"] / float(1<<20) * min_out_gb_cost)
results["10M_max_cost"]["fido2"] = 10e6 * (1.0 / results['auths_per_core']['fido2'] * max_core_hour_cost + results["out_total_comm_kb"]["fido2"] / float(1<<20) * max_out_gb_cost)

# Parse TOTP
# offline MB, online MB, offline ms, online ms
with open('totp_exp/out_20', 'r') as f:
    lines = f.readlines()
    results['online_time_ms']['totp'] = float(lines[3])
    results['total_time_ms']['totp'] = float(lines[2]) + float(lines[3])
    results['online_comm_kb']['totp'] = float(lines[1]) * (1<<10)
    results['total_comm_kb']['totp'] = (float(lines[0] + float(lines[1]))) * (1<<10)
    # TODO fix out to actually just be the comm from server to client
    results['out_total_comm_kb']['totp'] = (float(lines[0] + float(lines[1]))) * (1<<10)
    # TODO fix tput to be from server with 1 core
    results['auths_per_core']['totp'] = 1.0 / results['total_time_ms']['totp']

results['log_presig_b']['totp'] = '0'
results['auth_record_b']['totp'] = ecdsa_sig_size + aes_ct_size + timestamp_size

results["10M_min_cost"]["totp"] = 10e6 * (1.0 / results['auths_per_core']['totp'] * min_core_hour_cost + results["out_total_comm_kb"]["totp"] / float(1<<20) * min_out_gb_cost)
results["10M_max_cost"]["totp"] = 10e6 * (1.0 / results['auths_per_core']['totp'] * max_core_hour_cost + results["out_total_comm_kb"]["totp"] / float(1<<20) * max_out_gb_cost)

# Parse passwords
with open('pw_exp/out', 'r') as f:
    lines = f.readlines()
    results['online_time_ms']['pw'] = float(lines(6*3))
    results['total_time_ms']['pw'] = float(lines(6*3))
    # TODO fix tput to be from server with 1 core
    results['total_time_ms']['pw'] = float(lines(6*3))
    
results['online_comm_kb']['pw'] = (2 * proof_size_bytes(128) + elgamal_ct_size) / 1024.0
results['total_comm_kb']['pw'] = (2 * proof_size_bytes(128) + elgamal_ct_size) / 1024.0
results['out_total_comm_kb']['pw'] = 0

results['log_presig_b']['pw'] = '0'
results['auth_record_b']['pw'] = elgamal_ct_size + timestamp + ecdsa_sig_size

results["10M_min_cost"]["pw"] = 10e6 * (1.0 / results['auths_per_core']['pw'] * min_core_hour_cost + results["out_total_comm_kb"]["pw"] / float(1<<20) * min_out_gb_cost)
results["10M_max_cost"]["pw"] = 10e6 * (1.0 / results['auths_per_core']['pw'] * max_core_hour_cost + results["out_total_comm_kb"]["pw"] / float(1<<20) * max_out_gb_cost)


