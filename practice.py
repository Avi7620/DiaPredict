from flask import flask,request,render_templates
from flask_sqlalchemy import SQLALchemy

app=Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URL"]='sqlite:///practice.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
db=SQLALchemy(app)
app.secret_key='your secret key'

class form(db.Model):
    username=db.Column(db.String(200),primary_key=True )
    password=db.Column(db.String(200))
