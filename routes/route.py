from flask import Flask,flash
import flask

from queries import list_names
from web_app import app,db
from models.model import USER
from sqlalchemy.exc import IntegrityError


@app.route("/testing")
def testing():
    a=list_names()
    user_data=[]
    for i in a:
        print (i)
        user_data.append(i)
        print (user_data)
    return a


@app.route("/")
@app.route("/signup")
def signup():
    return flask.render_template("signup.html",action="/signup_post") 
 

@app.route("/signup_post", methods = ["POST"])
def post_signup():
    try:
        user_records={
        'user_name' :flask.request.form["username"],
        'user_email':flask.request.form["email_signup"],
        'password':flask.request.form["password"],
        'otp':"",
        }

        user = USER(**user_records)
        db.session.add(user)
        db.session.commit()
        
        return flask.render_template("Welcomepage.html")
    
    except IntegrityError:
        flash("The email you entered is already available please go to login. Please choose new email",'Wrong_OTP')
        return flask.render_template("signup.html")














