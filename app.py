# imports
from flask import Flask, flash, request, redirect, url_for
from flask.templating import render_template
from werkzeug.utils import secure_filename
import os
import folium
from time import sleep

# custom imports
from processing import process_ssh

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
            nodes = process_ssh(full_path)
            # add to cache to prevent re-process on reload
            current_analysis = nodes
        except:
            flash("Unable to process and render visuals",'error')
            return redirect(url_for('index'))
    else:
        nodes = current_analysis
        print("[+] Retreived from cache")
    # debug info
    print(nodes)
    print(len(nodes))
    if generate_map(nodes):
        return render_template('visuals.html',nodes=nodes)
    # handle unexpected exception
    flash('Something went wrong!!','error')
    return redirect(url_for('index'))

# drender helper function
def generate_map(nodes):
    start_geo = (1.3521, 103.8198)
    folium_map = folium.Map(location=start_geo,zoom_start=4,tiles='Stamen Toner',min_zoom=2)
    for i in nodes:
        folium.Marker(
            i.geo,
            popup=i.ip, 
            tooltip='More Info'
        ).add_to(folium_map)
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
    # add code to generate new map
    generate_map(refresh_nodes)
    sleep(1)
    return "Success"