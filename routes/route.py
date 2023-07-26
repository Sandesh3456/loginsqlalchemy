from flask import flash, session, redirect
import flask
import re
from flask_session import Session
from queries import list_names
from web_app import app,db
from models.model import USER
from sqlalchemy.exc import IntegrityError
import hashlib,secrets,time
from flask_mail import Mail,Message
from config import *

# app.config.from_pyfile("config.py")

# Session(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = "sandeshpathak282@gmail.com"
app.config['MAIL_PASSWORD'] = "lknrkhplqrdgcqhr"
mail = Mail(app)

app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]123LWX/,?RT'


@app.route("/testing")
def testing():
    # d = DATABASE_URI
    # print(MAIL_SERVER)
    # print(MAIL_PORT)
    # print(MAIL_USE_SSL)
    # print(MAIL_USERNAME)
    # print(MAIL_PASSWORD)
    # print(SESSION_PERMANENT)
    # print(SESSION_TYPE)
    # a=list_names()
    # user_data=[]
    # for i in a:
    #     print (i)
    #     user_data.append(i)
    #     print (user_data)
    return 'a'


@app.route("/")
@app.route("/signup")
def signup():
    return flask.render_template("signup.html",action="/signup_post") 
 

@app.route("/signup_post", methods = ["POST"])
def post_signup():
    try:
        signup_email = flask.request.form["email_signup"]
        regex = re.compile(r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])")
        if re.fullmatch(regex, signup_email):
            password=flask.request.form["password"]
            hashed_password=hashlib.sha256(password.encode('utf-8')).hexdigest()
            user_records={
            'user_name' :flask.request.form['username'],
            'user_email':signup_email,
            'password':hashed_password,
            }
            user = USER(**user_records)
            db.session.add(user)
            db.session.commit()
            return redirect("/login")
    
    except IntegrityError:
        flash("The email you entered is already available please go to login. Please choose new email",'Wrong_Email')
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
        }
        return flask.render_template("Welcomepage.html")
    return redirect('/login')

@app.route("/forgot")
def forgot():
    return flask.render_template("forgot.html",action="/forgot_post")

@app.route("/forgot_post", methods = ["POST"])
def post_forgot():
    user_email=flask.request.form["email_signup"]
    user = USER.query.filter_by(user_email = user_email).first()
    if user.user_email==user_email:
        otp=secrets.token_hex(8)
        # session['forgot_password'] = {'email': user_email, 'otp': otp, 'timestamp': time.time()}
        receiver=[]
        receiver.append(user_email)
        msg = Message(subject='Hello ! Reset Your Password', sender='sandeshpathak282@gmail.com', recipients=receiver)
        msg.body = 'Your one time password is {}.Please use the one time password within one minutes'.format(otp)
        mail.send(msg)
        return redirect ('/otp')

@app.route("/otp")
def otp():
    return flask.render_template("otp.html",action="/otp_post")


@app.route("/otp_post", methods=["POST"])
def otp_post():
    print("hello")
    user_email=flask.request.form["user_email"]
    user_otp=flask.request.form["user_otp"]
    new_password=flask.request.form["new_password"]
    confirm_new_password=flask.request.form["confirm_new_password"]
    otp_data = session.get('forgot_password', {})
    print(".......................................")
    if otp_data and 'otp' in otp_data and 'email' in otp_data:
        old_otp = otp_data['otp']
        stored_email = otp_data['email']
        print(user_otp)
        print(user_email)
        print(old_otp)
        print(stored_email)
    
        if stored_email == user_email and user_otp == old_otp:
            if new_password == confirm_new_password:
                # Update user's password 
                return redirect("/login")
            else:
                return redirect ("/otp")
        #"New password and confirm password do not match. Please try again."
        else:
        # Email or OTP does not match, handle the error or show an error message to the user
            return redirect ("/otp")
    else:
        return redirect ("/login")
    # "OTP data not found. Please generate a new OTP and try again."






