from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager
import secrets
import random
import string
import hashlib

login = LoginManager()
db = SQLAlchemy()
 



class MalUrlsModel(db.Model):
    __tablename__ = 'MalUrls'
 
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(50), unique=False)
    Status = db.Column(db.String(50), unique=False)
 
    def __init__(self, url, Status):
        self.url = url
        self.Status = Status



class MalFilesModel(db.Model):
    __tablename__ = 'malfiles'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    md5 = db.Column(db.String(100))
    filetype = db.Column(db.String(100))
    status = db.Column(db.String(100))

    def __init__(self, name, md5hash, ftype, status):
        self.filename = name
        self.md5 = md5hash
        self.filetype = ftype
        self.status = status

    def __repr__(self):
        return f'<MalFile {self.name}>'






class keymodel(db.Model):
    __tablename__ = 'keys'
 
    id = db.Column(db.Integer, primary_key=True)
    keys = db.Column(db.String(50), unique=True)
 
    def __init__(self, key):
        self.keys = key




 
 
class UserModel(UserMixin, db.Model):
    __tablename__ = 'users'
 
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String())
 
    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
     
    def check_password(self,password):
        return check_password_hash(self.password_hash,password)
 
 
 


@login.user_loader
def load_user(id):
    return UserModel.query.get(int(id))
