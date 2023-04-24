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

out_name = "out_plots/plot_fido2.png" 
in_dir = "out_data/fido2_exp/"
labels = ["Verify (Server)", "Other", "Prove (Client)"] 
colors=[custom_style.hash_colors[3], custom_style.hash_colors[4], custom_style.hash_colors[1]]
#colors=[custom_style.mix_colors[3], custom_style.hash_colors[4], custom_style.hash_colors[1], custom_style.hash_colors[0]]

y = [[], [], []]
total = []

cores = [1,2,4,8]

for i in cores:
    with open("%s/out_latency_%d" % (in_dir, i), 'r') as f:
        for j, line in enumerate(f):
            if j % 2 == 0:
                y[0].append(float(line))
            else:
                total.append(float(line))
    with open("%s/out_proof_%d" % (in_dir, i), 'r') as f:
        for j, line in enumerate(f):
            if j == 0:
                y[2].append(float(line))
y[1] = [total[i] - y[0][i] - y[2][i] for i in range(len(total))]

# N = 10000, n = 100

#for i in range(len(y)):
#    y[i] = y[i][3:]


fig = plt.figure(figsize = (2.4,1.6))
ax = fig.add_subplot(111)
ax.stackplot([1,2,4,8], y[0], y[1], y[2], labels=labels, colors=colors)
#ax.stackplot(np.arange(10, 110, step=10), y[0], y[1], y[2], y[3], labels=labels, colors=colors)
ax.set_xlabel("Client cores \n FIDO2")
ax.set_ylabel("Auth time (ms)")
#ax.set_ylim([0,1.2])
#ax.set_xlim([40,105])
ax.minorticks_on()
ax.set_xticks([1,2,4,8])

ax.set_yticks([0,100,200,300])
handles, labels = ax.get_legend_handles_labels()
handles.reverse()
labels.reverse()
#ax.legend(handles, labels, bbox_to_anchor=(-0.2, 1.1, 1., .102), loc='lower left', ncol=1, borderaxespad=0., fontsize=7,labelspacing=0)
#ax.legend(bbox_to_anchor=(-0.05, 1.2, 0.9, .102), fontsize=7.5)


#ax.spines['left'].set_position("zero")
ax.spines['bottom'].set_position("zero")
remove_chart_junk(plt,ax,grid=True,below=False)

ax.yaxis.grid(which='major', color='0.9', linestyle=':')
plt.savefig(out_name, bbox_inches='tight')
#custom_style.save_fig(fig, out_name, [3.25, 1.8])
#plt.show()
print("Output plot at %s" % out_file)
