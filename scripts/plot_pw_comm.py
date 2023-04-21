import matplotlib.pyplot as plt
import custom_style
from custom_style import remove_chart_junk
import sys
import numpy as np
import math

out_name = "plot_pw_comm.pdf"

def proof_size_bytes(log_len):
    return (33 * 4 * log_len) + (32 * 3 * log_len) + 32 + 4

comm = []
log_len = range(1,10)
lens = [1 << i for i in log_len]

for i in log_len:
    # add 66 for elgamal ct
    comm.append((2.0 * proof_size_bytes(i) + 66.0) / 1024.0)

for i in range(len(lens)):
    print("%d : %f" % (lens[i], comm[i]))
fig = plt.figure(figsize = (2.2,1.7))
ax = fig.add_subplot(111)
ax.step(lens, comm, marker="o")
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Relying parties \n \\textbf{Passwords}")
ax.set_ylabel("Communication (KiB)")
ax.set_xticks([2,8,32,128,512])
ax.set_xticklabels(["2","8","32","128","512"])
ax.set_yticks([1,2,4])
ax.set_yticklabels(["1","2","4"])
#ax.legend(fontsize=7, labelspacing=0)

remove_chart_junk(plt,ax,xticks=True,ticks=True,grid=True)
plt.save_fig(out_name, bbox_inches='tight')
