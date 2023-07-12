from flask import Flask,flash,session,redirect
import flask

from queries import list_names
from web_app import app,db
from models.model import USER
from sqlalchemy.exc import IntegrityError
import hashlib


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
        password=flask.request.form["password"]
        hashed_password=hashlib.sha256(password.encode('utf-8')).hexdigest()
        user_records={
        'user_name' :flask.request.form["username"],
        'user_email':flask.request.form["email_signup"],
        'password':hashed_password,
        'otp':"",
        }

        user = USER(**user_records)
        db.session.add(user)
        db.session.commit()
        
        return flask.render_template("login.html")
    
    except IntegrityError:
        flash("The email you entered is already available please go to login. Please choose new email",'Wrong_OTP')
    return flask.render_template("signup.html")


@app.route("/login")
def login():
    print('Get----')
    return flask.render_template("login.html",action="/login_post")


@app.route("/login_post", methods = ["POST"])
def post_login():
    user_email=flask.request.form["email_signup"]
    password =flask.request.form["password"]
    hashed_password=hashlib.sha256(password.encode('utf-8')).hexdigest()
    user = USER.query.filter_by(user_email = user_email).first()
    if user_email and user.password == hashed_password:
        session['current_user']={
            "username":user.user_name,
            "useremail":user.user_email,
            "password":user.password
        }
        return flask.render_template("Welcomepage.html")
    return flask.render_template('login.html')




