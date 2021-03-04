# routing imports
from flask import Flask, flash, request, redirect, url_for
from flask.helpers import send_file
from flask.templating import render_template
from werkzeug.utils import secure_filename

import pandas as pd
# utils import
import os
import folium
from time import sleep
from collections import Counter
from functools import reduce
from itertools import islice

# custom imports
from processing import process_ssh
from ftp import process_ftp
from deviation import gen_ftp_deviation_graph, gen_ssh_traffic_baseline_graph

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
current_df_raw = None
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
            flash("Invalid file extension")
            return render_template('index.html')

    return render_template('index.html')

@app.route('/drender')
def drender():
    filename = request.args.get('filename')
    full_path = os.path.join(app.config['UPLOAD_FOLDER'],filename)
    # check cache
    global current_analysis
    global current_df_raw
    if current_analysis is None:
    # handle exception for unexpected log file
        try:
            print("[+] Performing Analysis now")
            if 'sshd' in full_path:
                nodes = process_ssh(full_path)
                df_raw = None
            else:
                nodes,df_raw = process_ftp(full_path)
            # add to cache to prevent re-process on reload
            current_analysis = nodes
            current_df_raw = df_raw 
        except Exception as e:
            flash("Unable to process and render visuals",'error')
            print(e)
            return redirect(url_for('index'))
    else:
        nodes = current_analysis
        df_raw = current_df_raw
        print("[+] Retreived from cache")
    # debug info
    print(nodes)
    print(len(nodes))
    if generate_map(nodes):
        # if ssh attack node
        if nodes[0].errortype == None:
            gen_ssh_traffic_baseline_graph(nodes)
        else:
            print(df_raw)
            gen_ftp_deviation_graph(nodes,df_raw)
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
            if attack == 'user_bruteforce':
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


@app.route('/export')
def export():
    global current_analysis
    if current_analysis is None:
        flash('No Analysis Found!')
        return redirect(url_for('index'))
    return render_template('export.html')
@app.route('/api/export', methods=["POST"])
def gen_file():
    global current_analysis
    nodes = current_analysis
    data = request.form.to_dict()
    if len(data.keys()) == 1:
        flash('No Field Selected!')
        return redirect(url_for('export'))
    file_format = data['format-select'] 
    fields = list(data.keys())
    fields.remove('format-select')
    if 'user-count' in fields and 'user' in fields:
        fields.remove('user')
    export_format = {}
    for f in fields:
        if f == 'ip':
            export_format['IP Address'] = [n.ip for n in nodes]
        elif f == 'country':
            export_format['Country'] = [n.country for n in nodes]
        elif f == 'count':
            export_format['Traffic Count'] = [n.get_totaltries() for n in nodes]
        elif f == 'user':
            export_format['Usernames Tried'] = [list(n.targets.keys()) for n in nodes]
        elif f == 'sigs':
            export_format['Threats Detected'] = [' & '.join(n.sigs_descriptions()) for n in nodes]
        elif f == 'user-count':
            if file_format == 'json':
                export_format['Usernames Tried'] = [n.targets for n in nodes]
            else:
                export_format['tmp'] = [n.targets.items() for n in nodes]
    df = pd.DataFrame(export_format)
    if file_format == 'json':
        fpath = 'static/export.json'
        df.to_json(fpath,orient='records')
        return send_file(fpath, as_attachment=True)
    if 'user-count' in fields:
        df = df.explode('tmp')
        df[['Usernames Tried','Attempts']] = pd.DataFrame(df['tmp'].to_list())
        df = df.drop(columns=['tmp'])
    df.reset_index(drop=True,inplace=True)
    fpath = 'static/export.csv'
    df.to_csv(fpath,index=False)
    return send_file(fpath, as_attachment=True)