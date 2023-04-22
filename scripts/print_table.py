import json

IN_FILE = "perf.json"

with open(IN_FILE, 'r') as f:
  results = json.load(f)

dict_rows = ["online_time_ms", "total_time_ms", "online_comm_kb", "total_comm_kb", "out_total_comm_kb", "auth_record_b", "log_presig_b", "auths_per_core", "10M_min_cost", "10M_max_cost"]
row_labels = ["Online time (ms)", "Total time (ms)", "Online comm (KiB)", "Total comm (KiB)", "Auth record (B)", "Log presig (B)", "Auths/core/s", "10M auths min cost ($)", "10M auths max cost ($)"]
dict_cols = ["fido2", "totp", "pw"]
col_labels = ["FIDO2", "TOTP", "PW"]

print("\t %s \t %s \t %s" % (col_labels[0], col_labels[1], col_labels[2]))

for i,row in enumerate(dict_rows):
    print("%s \t %s \t %s \t %s" % (row_labels[i], results[row]['fido2'], results[row]['totp'], results[row]['pw']))
