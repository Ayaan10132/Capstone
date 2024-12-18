#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import random
import string
import pathlib
import hashlib
from  conf import *

from flask import *
from flask_mail import Mail, Message
from flask import Flask, render_template, request, redirect
from flask_login import login_required, current_user, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.utils import secure_filename
from werkzeug.datastructures import ImmutableMultiDict
from requests import get
from flask import abort, request, render_template
from functools import wraps

from App.CheckMLUrl import *
from App.ThreatFoxFeeds import *
from App.Yarascan import *
from App.CheckLexical import *
from App.urltotal import *
from App.SuspiciousStrings.check_strings import *
from App.SuspiciousDLL import *
from App.signaturecheck import *
from App.FilesHashes import FileInfo
from App.Pe_GetInfo import PEInfo
from App.models import UserModel, db, login, keymodel, MalFilesModel, MalUrlsModel

# Flask app configuration
app = Flask(__name__, template_folder='templates', static_url_path='/static')
UPLOAD_FOLDER = 'Uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['YARA_TEST'] = YARATEST
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'tXkjA3CrTigbZuMeBkHqUW4EEimo6p54'

# Ensure the 'db' directory exists
if not os.path.exists('db'):
    os.makedirs('db')

# Set up an absolute path for the database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'db/data.db')}"

# Initialize extensions
db.init_app(app)
login = LoginManager(app)
login.login_view = 'login'

# Mail configuration
mail = Mail(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = EMAIL
app.config['MAIL_PASSWORD'] = PASSWD
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


@login.user_loader
def load_user(user_id):
    return UserModel.query.get(int(user_id))

# Database creation logic moved out of before_request
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"Error during database initialization: {e}")



 
def generate_random_key():
	if ( not keymodel.query.all()):
		auth_keys=""
		for i in range(0,20):
			k = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(25))
			k = (hashlib.md5(k.encode()).hexdigest())
			auth_keys += str(k)+' --- '
			_key_ = keymodel(k)
			#print(_key_)
			db.session.add(_key_)
			db.session.commit()
		try:
			msg = Message("ThreatBox: PLease Don't Share The Keys ", 
			sender = email, 
			recipients = [email])
			msg.html = """<p>hey<strong> Team Leader</strong> </p>
			<p><strong>ThreatBox - Cyber threat Hunting &amp; Malware Analysis Box</strong></p>
			<p><strong>ThreatBox generate all those Keys of user to access</strong></p><br>"""+auth_keys+"<br>"
			mail.send(msg)
		except:	
			pass 
		f  = open("Keys/keys.txt", "w+")
		f.write(auth_keys)
	else: 
		pass

@app.before_request
def create_all():
    db.create_all()
    print(generate_random_key())
     

 

  
@app.route('/dashboard')
@app.route('/')
@login_required
def statistic():	
	malfile = MalFilesModel.query.filter().all()
	malfile_count = MalFilesModel.query.count()	
	malurl = MalUrlsModel.query.filter().all()
	malurl_count = MalUrlsModel.query.count()
	return render_template('index.html' , malfile = malfile ,malfile_count=malfile_count ,malurl = malurl ,malurl_count=malurl_count)
    
  

 
@app.route('/scan')
@login_required
def scan():
	return render_template('dashboard.html')
    
@app.route('/feeds')
@login_required
def feeds():
	n =ThreatFoxFeeds().fetch_threatfox(1)
	return render_template('feeds_ioc.html',feed=n)
    
   



@app.route('/login', methods = ['POST', 'GET'])
def login():

    if current_user.is_authenticated:
        return redirect('/dashboard')

    if request.method == 'POST':
        email = request.form['email']
        user = UserModel.query.filter_by(email = email).first()
        if user is not None and user.check_password(request.form['password']):
            login_user(user)
            return redirect('/dashboard')
        else: 
            return render_template('login.html' , error_msg='incorrect username or password  ')
     
    return render_template('login.html')


 
 
 
 
    
 
 
@app.route('/register', methods=['POST', 'GET'])
def register(): 
	if request.method == 'GET':
		return render_template('login_access_key.html')
	if request.method == 'POST':
		key = request.form['key']
		if keymodel.query.filter_by(keys = key).first(): 
			#db.session.add(key)
			#db.session.commit()
			return render_template('_register_.html')
		else:
			return render_template('login_access_key.html', error="key Used Not Valide")

		return render_template('login_access_key.html')

        

    
 
 
@app.route('/page/register', methods=['POST'])
def _register():
    if current_user.is_authenticated:
        return redirect('/')
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        if UserModel.query.filter_by(email=email).first():
            return ('Email already Present')
        user = UserModel(email=email, username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('_register_.html')


 
 
 
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')




def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS



@app.route('/file/results', methods=['POST', 'GET'])
@login_required
def results_file():
        filename = "WannaCry_Ransomware.exe" 
        filepath = "./ANSI_ANALYSER/script_Analyzers/WannaCry_Ransomware.exe" 
        calls = calls_nd_strings(filepath).run()
        yaradetect = yaraScan(filepath).results()

        Hashes_Data = FileInfo(filepath).run()
        st = strings_all(filepath)
        strings = st.unicode_strings()
        email = st.getemail()
        ip = st.getip()
        return render_template('results_file_scan.html',
		email = email ,
		ip=ip , 
		yaradetect = yaradetect, 
		strings = strings ,
		calls = calls,
		Hashes_Data = Hashes_Data)





    
    
@app.route('/profile',  methods=['POST', 'GET'])
@login_required
def Profile_Settings():
    if request.method == 'POST':
        admin = UserModel.query.filter_by(email = request.form['email']).first()
        email = request.form['email']
        old_password = request.form['old-password']
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-password']
        if not admin.check_password(old_password):
            return "old password not correct !! "
        elif (new_password != confirm_password):
            return "new_password different confirm_password"
        admin.set_password(confirm_password)
        db.session.commit()
        logout()
        return redirect('/login')

    
    return render_template('profile.html')
 
    
       
        
        
  
        

@app.route('/url', methods=['POST'])
@login_required
def scan_url():
    if request.method == 'POST':
        url = request.form['urladdress']
        geturltotal = VTotalAPI(url).run()
        lexical_features = extract_data(url).results()
        ml = malicious_url_ML(url).run()
        malur = MalUrlsModel(url, "detected")
        db.session.add(malur)
        db.session.commit()
        return render_template(
            "results_url_scan.html",
            lexical_features=lexical_features,
            geturltotal=geturltotal,
            ml=ml,
        )
    else:
        abort(405)
       

@app.route('/file', methods=['POST'])
@login_required
def scan_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file uploaded'
        
        file = request.files['file']
        if file.filename == '':
            return 'No file selected'
            
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            File_Info = FileInfo(filepath)
            Hashes_Data = File_Info.get_hashes()
            
            # Match parameters to MalFilesModel constructor
            malfil = MalFilesModel(
                name=file.filename,
                md5hash=str(Hashes_Data["MD5"]),
                ftype=str(Hashes_Data["Type"]),
                status="active"
            )
            
            # Rest of your scan_file logic...
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            print(f"Looking for file at: {filepath}")
            filesize = os.path.getsize(filepath)

            # Process the file
            calls = calls_nd_strings(filepath).run()
            yaradetect = yaraScan(filepath).results()
            signa = signateur(filepath).check_signateur()
            Hashes_Data = FileInfo(filepath).run()
            peinfo = PEInfo(filepath).run()
            st = strings_all(filepath)
            strings = st.unicode_strings()
            email = st.getemail()
            ip = st.getip()

            detected = next(iter(yaradetect.values())) != "None"
            malfil = MalFilesModel(file.filename, str(Hashes_Data["MD5"]), str(Hashes_Data["Type"]), "detected")
            db.session.add(malfil)
            db.session.commit()

            # Render the results
            return render_template(
                'results_file_scan.html',
                detected=detected,
                peinfo=peinfo,
                signaa=signa,
                filename=filename,
                filesize=filesize,
                email=email,
                ip=ip,
                yaradetect=yaradetect,
                strings=strings,
                calls=calls,
                Hashes_Data=Hashes_Data
            )
        else:
            # Return an error if the file is not valid
            return "Invalid file or file type not allowed", 400
    else:
        # Return an error for unsupported HTTP methods
        return "Method not allowed", 405



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', port=5000, debug=True)
