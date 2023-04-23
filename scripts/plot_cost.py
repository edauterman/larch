import matplotlib.pyplot as plt
import custom_style
from custom_style import remove_chart_junk
import sys
import numpy as np
import math
from math import ceil
import json

max_cpu_hour_cost = 0.085
network_gb_cost = 0.05

IN_FILE = "out_data/perf.json"

with open(IN_FILE, 'r') as f:
  results = json.load(f)

def get_fido2_cost(auths):
    auth_tput = results["auths_per_core"]["fido2"]
    auth_sec = auths / auth_tput
    core_hours = ceil(auth_sec/60.0/60.0)
    core_cost = max_cpu_hour_cost * core_hours

    data_gb = auths * results["out_total_comm_kb"]["fido2"] / (1 << 20)
    network_cost = network_gb_cost * data_gb

    return core_cost + network_cost

def get_pw_cost(auths):
    auth_tput = results["auths_per_core"]["pw"]
    auth_sec = auths / auth_tput
    core_hours = ceil(auth_sec / 60.0 / 60.0)
    core_cost = max_cpu_hour_cost * core_hours

    data_gb = auths * results["out_total_comm_kb"]["pw"] / (1 << 20)
    network_cost = network_gb_cost * data_gb

    return core_cost + network_cost

def get_totp_cost(auths):
    auth_tput = results["auths_per_core"]["totp"]
    auth_sec = auths/auth_tput
    core_hours = ceil(auth_sec / 60.0 / 60.0)
    core_cost = max_cpu_hour_cost * core_hours

    data_gb = auths * results["out_total_comm_kb"]["totp"] / (1 << 20)
    network_cost = network_gb_cost * data_gb
    return core_cost + network_cost


out_name = "out_plots/plot_cost.pdf" 
numAuths = [1000 * i for i in range(1,10000)]
fido2 = []
pw = []
totp = []
colors = [custom_style.mix_colors[3], custom_style.mix_colors[2], custom_style.mix_colors[0]]


for i,auths in enumerate(numAuths):
    pw.append(get_pw_cost(auths))
    totp.append(get_totp_cost(auths))
    fido2.append(get_fido2_cost(auths))

fig = plt.figure(figsize = (1.9,1.9))
ax = fig.add_subplot(111)
ax.plot(numAuths, pw, label="Passwords", color=colors[0])
ax.plot(numAuths, totp, label="TOTP", color=colors[1])
ax.plot(numAuths, fido2, label="FIDO2", color=colors[2])
#ax.plot(x, yBaseline, label="Plaintext", color="black", linestyle="dashed")
ax.set_xlabel("Authentications")
ax.set_ylabel("Cost")
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_yticks([0.1, 1,10,100,1000,10000,100000])
ax.set_yticklabels(["\$0.1","\$1","\$10","\$100","\$1K", "\$10K", "\$100K"])
ax.set_xticks([1000,10000,100000,1000000,10000000])
ax.set_xticklabels(["1K","10K","100K","1M","10M"])
#ax.set_yticks([0, 5, 10, 15, 20])
#ax.set_xticklabels(["0", "5K", "10K"])
#ax.set_yticks([0, 1e6, 2e6, 3e6])
#ax.set_yticklabels(["0", "1M", "2M", "3M"])

handles, labels1 = ax.get_legend_handles_labels()
handles.reverse()
labels1.reverse()
#ax.legend(handles, labels1, fontsize=7, labelspacing=0, ncol=1)
ax.legend(handles, labels1, bbox_to_anchor=(-0.2, 1.1, 1., .102), loc='lower left', ncol=1, borderaxespad=0., fontsize=7,labelspacing=0)

#ax.spines['left'].set_position("zero")
#ax.spines['bottom'].set_position("zero")

remove_chart_junk(plt,ax, grid=False, below=False)
ax.yaxis.grid(which='major', color='0.8', linestyle=':')
plt.savefig(out_name, bbox_inches='tight')
