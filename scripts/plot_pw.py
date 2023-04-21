import re
import custom_style
from custom_style import setup_columns,col,remove_chart_junk
import matplotlib.pyplot as plt
import sys
import numpy as np
from matplotlib.ticker import FuncFormatter
import math
from collections import defaultdict
from matplotlib.patches import Patch
import scipy.special

out_name =  "plot_pw.pdf" 
in_name = "pw_exp/out" 
labels = ["Network", "Verify (Server)", "Prove (Client)"] 
colors=[custom_style.hash_colors[4], custom_style.hash_colors[3], custom_style.hash_colors[1]]

# log, client, total
y = [[], [], []]
with open(in_name, 'r') as f:
    for i, line in enumerate(f):
        y[i % 3].append(float(line))
        if i > 2:
            y[i % 3].append(float(line))



fig = plt.figure(figsize = (2.4,2))
#fig = plt.figure(figsize = (2.4,1.6))
ax = fig.add_subplot(111)
x = []
for i in range(1,10):
    if i != 1:
        x.append((1 << (i-1)) + 0.000000001)
    x.append(1 << i)
#for i in range(3):
#    ax.plot(x, y[i], label=labels[i], color=colors[i])
#ax.plot(x, [y[0][i] + y[1][i] + y[2][i] for i in range(len(y[0]))], label=labels[3], color=colors[3])
network = [y[2][i] - y[0][i] - y[1][i] for i in range(len(y[0]))]
print(network)
print(y[0])
print(y[1])
print("len network = %d, len server = %d, len client = %d, len x = %d" % (len(network), len(y[0]), len(y[1]), len(x)))
ax.stackplot(x, network, y[0], y[1], labels=labels, colors=colors)
ax.set_xlabel("Relying parties \n Passwords")
ax.set_ylabel("Auth time (ms)")
#ax.set_xscale("log")
#ax.set_yscale("log")
#ax.set_ylim([0,1.2])
#ax.set_xlim([40,105])
ax.minorticks_on()
#ax.set_xticks([1,2,4,8])
#ax.set_xticks([2,8,32,128,512])
ax.set_yticks([50*x for x in range(6)])
ax.set_xticks([0,100,200,300,400,500])
#ax.set_xticklabels(["2","8","32","128","512"])
#ax.set_xticklabels(["100","200","300","400","500"])
#ax.set_yticks([20,40,80,160,320])
#ax.set_yticks([50,100,150,200])
#ax.set_yticklabels(["20","40","80","160","320"])

#ax.set_yticks([0,2,4,6,8,10])
handles, labels = ax.get_legend_handles_labels()
handles.reverse()
labels.reverse()
#ax.legend(handles, labels, bbox_to_anchor=(-0.2, 1.1, 1., .102), loc='lower left', ncol=1, borderaxespad=0., fontsize=7,labelspacing=0)
#ax.legend(bbox_to_anchor=(-0.05, 1.2, 0.9, .102), fontsize=7.5)


ax.spines['left'].set_position("zero")
#ax.spines['bottom'].set_position("zero")
remove_chart_junk(plt,ax,grid=True,below=False)

ax.yaxis.grid(which='major', color='0.9', linestyle=':')
plt.savefig(out_name, bbox_inches='tight')
#custom_style.save_fig(fig, out_name, [3.25, 1.8])
#plt.show()
