from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import config as config


app = Flask(
    __name__)


app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
db.init_app(app)


from routes import *
