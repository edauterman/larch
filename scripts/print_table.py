import json
from tabulate import tabulate

IN_FILE = "out_data/perf.json"

with open(IN_FILE, 'r') as f:
  results = json.load(f)

dict_rows = ["online_time_ms", "total_time_ms", "online_comm_kb", "total_comm_kb", "auth_record_b", "log_presig_b", "auths_per_core", "10M_min_cost", "10M_max_cost"]
row_labels = ["Online time (ms)", "Total time (ms)", "Online comm (KiB)", "Total comm (KiB)", "Auth record (B)", "Log presig (B)\t", "Auths/core/s\t", "10M auths min cost ($)", "10M auths max cost ($)"]
dict_cols = ["fido2", "totp", "pw"]
col_labels = ["FIDO2", "TOTP", "PW"]

table = [col_labels]
for i,row in enumerate(dict_rows):
    table.append([row_labels[i], results[row]['fido2'], results[row]['totp'], results[row]['pw']])

print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))
