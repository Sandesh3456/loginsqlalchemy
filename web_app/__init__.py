from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail,Message
import config as config

app = Flask(
    __name__
)
mail = Mail(app)




app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
# app.config.from_pyfile("config.py")

app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
db.init_app(app)

from routes import *