# graphing imports
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
from random import random

def gen_ssh_traffic_baseline_graph(nodes):
    ip_list, count_list = [],[]
    baseline = []
    for n in nodes:
        ip_list.append(n.ip)
        count_list.append(n.get_totaltries())
        if 'user_bruteforce' not in n.attacks.keys():
            baseline.append(n.get_totaltries())
    grpip = pd.DataFrame(data={'IP':ip_list, 'Count':count_list})
    vals = grpip['Count'].values.tolist()
    avg = sum(baseline) / len(baseline)
    width = 1
    fig, ax = plt.subplots()
    clrs = ['blue' if (x >= avg ) else 'grey' for x in vals ]
    rects1 = ax.barh(grpip['IP'], vals, width,color = clrs)
    plt.axvline(x=avg, color='r', linestyle='-')
    plt.grid()
    plt.subplots_adjust(left=0.4)
    plt.title('Traffic Breakdown')
    plt.gcf().set_size_inches(11,5)
    plt.savefig('static/deviation.png')
    return True

def gen_ftp_deviation_graph(nodes,export):
    
    ips = export.groupby('Ip Address').size()
    kv = ips.to_dict()
    ips = pd.DataFrame({'IP':ips.index, 'Count':ips.values})
    ips = []
    for n in nodes:
        if 'user_bruteforce' in n.attacks.keys():
            ips.append(n.ip)
    fig,axes=plt.subplots()
    i = 0
    # labels and lines for legend
    lns = []
    x = export[(export == ips[i]).any(axis=1)]
    dates = x.groupby('Timestamp').size()
    dates = pd.DataFrame({'Date': dates.index, 'Count': dates.values})
    dates['Count'] = dates['Count'].cumsum()
    r = random()
    b = random()
    g = random()
    color = (r, g, b)
    lns.append(axes.plot(dates['Date'], dates['Count'],color=color,label=ips[i]))
    axes.get_xaxis().set_ticks([])
    axes.set_ylabel('Traffic Count')
    axes.set_xlabel('Time')
    i+=1
    while i < len(ips):
        x = export[(export == ips[i]).any(axis=1)]
        dates = x.groupby('Timestamp').size()
        dates = pd.DataFrame({'Date': dates.index, 'Count': dates.values})
        dates['Count'] = dates['Count'].cumsum()
        r = random()
        b = random()
        g = random()
        color = (r, g, b)
        ax2 = axes.twiny()
        lns.append(ax2.plot(dates['Date'], dates['Count'],color=color,label=ips[i]))
        ax2.get_xaxis().set_ticks([])
        i += 1
    x = export[(export == '192.168.0.1').any(axis=1)]
    dates = x.groupby('Timestamp').size()
    dates = pd.DataFrame({'Date': dates.index, 'Count': dates.values})
    dates['Count'] = dates['Count'].cumsum()
    ax2=axes.twiny()
    ax2.plot(dates['Date'], dates['Count'], color = 'red',label='Baseline')
    ax2.get_xaxis().set_ticks([])
    plt.axhline(y=max(dates['Count']),linestyle=(0, (5,10)), color='red') 
    plt.grid()
    fig.legend(loc="center right")
    plt.title('Brute Force Detection')
    plt.gcf().set_size_inches(11,5)
    plt.savefig('static/deviation.png')
    return True