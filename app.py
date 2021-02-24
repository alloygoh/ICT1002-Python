# routing imports
from flask import Flask, flash, request, redirect, url_for
from flask.templating import render_template
from werkzeug.utils import secure_filename
# graphing imports
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import pandas as pd
# utils import
import os
import folium
from time import sleep
from collections import Counter
from functools import reduce
from itertools import count, islice

# custom imports
from processing import process_ssh
from ftp import process_ftp

# app configs
ALLOWED_EXTENSIONS = {'txt', 'log'}
UPLOAD_FOLDER = './resource/uploads/'
app = Flask(__name__)
app.secret_key = b'\xed\xa1\x80\t\xa5n_\xcd\xb7\xfc\x83\xa20\x13]\x9b\xfe\xf3\xc4\xd3\xa5'
# increase file size limit to prevent 413 error
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# internal cache
current_analysis = None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/",methods=["GET","POST"])
def index(filename=None):
    if request.method == "POST":
        # check POST request for file
        if 'file' not in request.files:
            flash('No File Part','error')
            return redirect(request.url)

        file = request.files['file']
        # check for empty file upload
        if file.filename == '':
            flash('No File Selected', "error")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if not os.path.isdir('./resource/uploads'):
                os.mkdir(os.path.join(os.getcwd(),'resource/uploads'))
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            return redirect(url_for('drender',filename=filename))

        else:
            flash("Invalid file extention")
            return render_template('index.html')

    return render_template('index.html')

@app.route('/drender')
def drender():
    filename = request.args.get('filename')
    full_path = os.path.join(app.config['UPLOAD_FOLDER'],filename)
    # check cache
    global current_analysis
    if current_analysis is None:
    # handle exception for unexpected log file
        try:
            print("[+] Performing Analysis now")
            if 'sshd' in full_path:
                nodes = process_ssh(full_path)
            else:
                nodes = process_ftp(full_path)
            # add to cache to prevent re-process on reload
            current_analysis = nodes
        except Exception as e:
            flash("Unable to process and render visuals",'error')
            print(e)
            return redirect(url_for('index'))
    else:
        nodes = current_analysis
        print("[+] Retreived from cache")
    # debug info
    print(nodes)
    print(len(nodes))
    if generate_map(nodes):
        # if ssh attack node
        if nodes[0].errortype == None:
            gen_ssh_traffic_baseline_graph(nodes)
        ttu_data = pchart_wrapper(nodes,'top-ten-users')
        gen_chart_data("Top Ten Users", 'ttu.html',ttu_data)
        cbd_data = pchart_wrapper(nodes,'countries')
        gen_chart_data("Countries Breakdown",'cbd.html',cbd_data)
        return render_template('visuals.html',nodes=nodes,fnames=['ttu.html','cbd.html'])
    # handle unexpected exception
    flash('Something went wrong!!','error')
    return redirect(url_for('index'))

# drender helper function
def generate_map(nodes):
    # run attack signatures
    start_geo = (1.3521, 103.8198)
    baseline_geo = []
    folium_map = folium.Map(location=start_geo,zoom_start=4,tiles='Stamen Toner',min_zoom=2)
    for i in nodes:
        attack_info = ''
        for attack in i.attacks.keys():
            if attack == 'ssh_enum_user':
                attack_info += '<li><a href="https://www.cvedetails.com/cve/CVE-2018-15473/">Possible SSH User Enumeration Detected</a></li>'
            if attack == 'ssh_bruteforce':
                attack_info += '<li>Possible Bruteforce Attempt Detected</li>'
            if attack == 'fuzzing':
                attack_info += '<li>Suspicious Non-Ascii Traffic, Possible Fuzzing Attempt Detected</li>'
        if i.geo in baseline_geo:
            mgeo = [str(float(i.geo[0]) + 0.0050),i.geo[1]]
        else:
            mgeo = i.geo
        folium.Marker(
            mgeo,
            popup=i.ip + '</br>' + attack_info, 
            tooltip='More Info'
        ).add_to(folium_map)
        baseline_geo.append(mgeo)
    folium_map.save('static/map.html')
    return True

@app.route('/api/release-cache')
def release_cache():
    global current_analysis
    current_analysis = None
    os.remove('static/cbd.html')
    os.remove('static/map.html')
    os.remove('static/ttu.html')
    print("[+] cache released!")
    print(current_analysis)
    return redirect(url_for('index'))

@app.route('/api/refresh-map',methods=['POST'])
def refresh_map():
    data = request.form.to_dict()
    ip_parsed = data['ip'].split(',')
    global current_analysis
    nodes = current_analysis
    refresh_nodes = [n for n in nodes if n.ip in ip_parsed]
    print(refresh_nodes)
    generate_map(refresh_nodes)
    sleep(1) 
    return "Success" 

def pchart_wrapper(nodes,purpose):
    if purpose == 'top-ten-users':
        target_list = [d.targets for d in nodes]
        combined = dict(reduce(lambda x,y: Counter(x) + Counter(y),target_list))
        if 'UNSPECIFIED' in combined.keys():
            combined.pop('UNSPECIFIED')
        combined = dict(sorted(combined.items(),key=lambda item: item[1],reverse=True))
        top_ten = dict(islice(combined.items(),10))
        others = sum([v for k,v in combined.items() if k not in top_ten.keys()])
        top_ten["Others"] = others
        return top_ten
    elif purpose == 'countries':
        country_list = list(set([d.country for d in nodes]))
        country_dict = {}
        for c in country_list:
            country_dict[c] = sum([t.get_totaltries() for t in nodes if t.country == c])
        return country_dict

def gen_chart_data(chart_title,filename,data):
    with open('static/' + filename,'w') as f:
        f.write(render_template('pie-chart.html', chart_title=chart_title, data=data))
        f.close()
    return True

def gen_ssh_traffic_baseline_graph(nodes):
    #grpip = pd.DataFrame({'IP':grpip.index, 'Count':grpip.values})
    ip_list, count_list = [],[]
    for n in nodes:
        ip_list.append(n.ip)
        count_list.append(n.get_totaltries())
    grpip = pd.DataFrame(data={'IP':ip_list, 'Count':count_list})
    vals = grpip['Count'].values.tolist()
    avg = sum(vals) / len(vals)
    width = 1
    fig, ax = plt.subplots()
    clrs = ['blue' if (x >= avg ) else 'grey' for x in vals ]
    rects1 = ax.barh(grpip['IP'], vals, width,color = clrs)
    plt.axvline(x=avg, color='r', linestyle='-')
    plt.grid()
    plt.subplots_adjust(left=0.4)
    plt.title('Exceptional Traffic')
    plt.gcf().set_size_inches(11,5)
    plt.savefig('static/ssh_baseline.png')
    return True