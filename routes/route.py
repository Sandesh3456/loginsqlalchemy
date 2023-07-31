from flask import flash, session, redirect
import flask
import re
from flask_session import Session
from web_app import app, db
from models.model import USER
from sqlalchemy.exc import IntegrityError
import hashlib
import secrets
from flask_mail import Mail, Message
from datetime import timedelta
import config as config
from functools import wraps


app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_SSL'] = config.MAIL_USE_SSL
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
mail = Mail(app)


app.config['SESSION_TYPE'] = config.SESSION_TYPE
Session(app)


app.secret_key = secrets.token_urlsafe(32)


@app.before_request
def make_session_permanent():
    session.permanent = config.SESSION_PERMANENT
    app.permanent_session_lifetime = timedelta(minutes=30)


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'useremail' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect('/login')
    return wrap


@app.route("/signup")
@login_required
def signup():
    return flask.render_template("signup.html")


@app.route("/signup_post", methods=["POST"])
def post_signup():
    try:
        signup_email = flask.request.form["email_signup"]
        regex = re.compile(r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])")
        if re.fullmatch(regex, signup_email):
            password = flask.request.form["password"]
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            user_records = {
             'user_name': flask.request.form['username'],
             'user_email': signup_email,
             'password': hashed_password,
            }
            user = USER(**user_records)
            db.session.add(user)
            db.session.commit()
            return redirect("/login")

    except IntegrityError:
        flash("The email you entered is already available.", 'Wrong_Email')
    return flask.render_template("signup.html")


@app.route("/")
@app.route("/login")
def login():
    return flask.render_template("login.html")


@app.route("/login_post", methods=["POST"])
def post_login():
    user_email = flask.request.form["email_signup"]
    password = flask.request.form["password"]
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    user = USER.query.filter_by(user_email=user_email).first()
    if user_email and user.password == hashed_password:
        session['current_user'] = {
            "userid": user.user_id,
            "username": user.user_name,
            "useremail": user.user_email,
        }
        return flask.render_template("Homepage.html")
    return redirect('/login')


@app.route("/forgot")
@login_required
def forgot():
    return flask.render_template("forgot.html")


@app.route("/forgot_post", methods=["POST"])
def post_forgot():
    user_email = flask.request.form["email_signup"]
    user = USER.query.filter_by(user_email=user_email).first()
    if user.user_email == user_email:
        otp = secrets.token_hex(8)
        session['forgot_password'] = {'user_id': user.user_id,
                                      'email': user.user_email,
                                      'user_name': user.user_name,
                                      'otp': otp}
        receiver = []
        receiver.append(user_email)
        msg = Message(subject='Hello ! Reset Your Password', sender='sandeshpathak282@gmail.com', recipients=receiver)
        msg.body = 'Your one time password is {}'.format(otp)
        mail.send(msg)
        return redirect('/otp')


@app.route("/otp")
@login_required
def otp():
    return flask.render_template("otp.html")


@app.route("/otp_post", methods=["POST"])
def otp_post():
    user_name = flask.request.form["user_name"]
    user_email = flask.request.form["user_email"]
    user_otp = flask.request.form["user_otp"]
    new_password = flask.request.form["new_password"]
    confirm_new_password = flask.request.form["confirm_new_password"]
    otp_data = session.get('forgot_password', {})
    if otp_data and 'otp' in otp_data and 'email' in otp_data:
        old_otp = otp_data['otp']
        stored_email = otp_data['email']
        users_id = otp_data["user_id"]
        if stored_email == user_email and user_otp == old_otp:
            if new_password == confirm_new_password:
                hashed_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
                print("hashed password is", hashed_password)
                user = USER.query.filter_by(user_id=users_id).first()
                print("user_is", user)
                if user:
                    user.user_name = user_name
                    user.password = hashed_password
                db.session.add(user)
                db.session.commit()
                return redirect("/login")
            else:
                flash("Passwords do not match.", 'Password_dont_match')
                return redirect("/otp")
        else:
            flash("Email or otp does not match", 'Email_dont_match')
            return redirect("/otp")
    else:
        flash("OTP is wrong", 'OTP_wrong')
        return redirect("/login")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect('/login')
