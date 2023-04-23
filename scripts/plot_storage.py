import matplotlib.pyplot as plt
import custom_style
from custom_style import remove_chart_junk
import sys
import numpy as np
import math

out_name = "out_plots/plot_storage.pdf"
x = []
y1 = []
y2 = []
yLong = []
yBaseline = []
labels = ["Authentication records", "Presignatures"]
colors = [custom_style.mix_colors[3], custom_style.mix_colors[0]]

max_auths = 10000

for i in range(1000, 10000, 100):
    x.append(i)
    # ct (32) + sig (64) + timestamp (8)
    storage1 = (i * (32 + 8 + 64)) / 2**20
    storage2 = ((max_auths - i) * 6) * 32 / 2**20
    # long term storage: sk (32) + ctr (4) + auth_pk (33) + comm(32)
    yLong.append((32 + 4 + 33 + 32) / 2**20)
    # rpid (2) + timestamp (8)
    storageBaseline = (i * (2 + 8)) / 2**20
    y1.append(storage1)
    y2.append(storage2)
    yBaseline.append(storageBaseline)

fig = plt.figure(figsize = (1.9,1.9))
ax = fig.add_subplot(111)
ax.stackplot(x, y1, y2, labels=labels, colors=colors)
#ax.plot(x, yBaseline, label="Baseline", color="black")
#ax.plot(x, yBaseline, label="Plaintext", color="black", linestyle="dashed")
ax.set_xlabel("Authentications \n FIDO2")
ax.set_ylabel("Log storage (MiB)")
ax.set_xticks([0, 5000, 10000])
#ax.set_yticks([0, 5, 10, 15, 20])
ax.set_xticklabels(["0", "5K", "10K"])
#ax.set_yticks([0, 1e6, 2e6, 3e6])
#ax.set_yticklabels(["0", "1M", "2M", "3M"])

handles, labels1 = ax.get_legend_handles_labels()
handles.reverse()
labels1.reverse()
#ax.legend(handles, labels1, fontsize=7, labelspacing=0, ncol=1)
ax.legend(handles, labels1, bbox_to_anchor=(-0.2, 1.1, 1., .102), loc='lower left', ncol=1, borderaxespad=0., fontsize=7,labelspacing=0)

ax.spines['left'].set_position("zero")
ax.spines['bottom'].set_position("zero")

remove_chart_junk(plt,ax, grid=False, below=False)
ax.yaxis.grid(which='major', color='0.9', linestyle=':')
plt.savefig(out_name, bbox_inches='tight')
