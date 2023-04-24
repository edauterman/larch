import re
from custom_style import setup_columns,col,remove_chart_junk
import matplotlib.pyplot as plt
import sys
import custom_style
import numpy as np
from matplotlib.ticker import FuncFormatter
import math
from collections import defaultdict
from matplotlib.patches import Patch
import scipy.special

out_name = "out_plots/plot_totp.png" 
in_dir = "out_data/totp_exp/"
labels = ["Offline", "Online"] 
colors=[custom_style.hash_colors[2], custom_style.mix_colors[5], custom_style.hash_colors[1], custom_style.hash_colors[0]]

y = [[], []]
for i in range(20,120,20):
    with open("%s/out_%d" % (in_dir, i), 'r') as f:
        lines = f.readlines()
        y[0].append(float(lines[3]) / 1000.0)
        y[1].append(float(lines[4]) / 1000.0)

# N = 10000, n = 100

#for i in range(len(y)):
#    y[i] = y[i][3:]


fig = plt.figure(figsize = (2.4,1.6))
ax = fig.add_subplot(111)
x = [20*x for x in range(1,6)]
ax.stackplot(x, y[0], y[1], labels=labels, colors=colors)
#ax.stackplot(np.arange(10, 110, step=10), y[0], y[1], y[2], y[3], labels=labels, colors=colors)
ax.set_xlabel("Relying parties \n TOTP")
ax.set_ylabel("Auth time (s)")
#ax.set_ylim([0,1.2])
#ax.set_xlim([40,105])
ax.minorticks_on()

ax.set_yticks([0,0.5,1,1.5])
handles, labels = ax.get_legend_handles_labels()
handles.reverse()
labels.reverse()
#ax.legend(handles, labels, bbox_to_anchor=(-0.2, 1.1, 1., .102), loc='lower left', ncol=2, borderaxespad=0., fontsize=7,labelspacing=0)
ax.legend(bbox_to_anchor=(-0.05, 1.2, 0.9, .102), fontsize=7.5)


#ax.spines['left'].set_position("zero")
ax.spines['bottom'].set_position("zero")
remove_chart_junk(plt,ax,grid=True,below=False)

ax.yaxis.grid(which='major', color='0.9', linestyle=':')
plt.savefig(out_name, bbox_inches='tight')
print("Output plot at %s" % out_name)
