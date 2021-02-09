# imports
from types import MethodDescriptorType
from flask import Flask, flash, request, redirect, url_for
from flask.templating import render_template
from werkzeug.utils import secure_filename
import os

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
            print(url_for('index',_external=True,filename=filename))
            return redirect(url_for('index',filename=filename,_external=True))

        else:
            flash("Invalid file extention")
            return render_template('index.html')
    elif request.method == "GET" and filename is not None:
        #process and assign job for file
        #job_id=process(filename)
        # return url_for(drender/job_id)
        
        nodes = process_ssh()
        return redirect(url_for('drender',nodes))
    
    return render_template('index.html')

@app.route('/drender')
def drender(nodes):
    print(nodes)
    #look up job_id and display stuff
    return