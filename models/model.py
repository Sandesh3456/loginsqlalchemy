from web_app import db
from sqlalchemy import Column, String

class USER(db.Model):

    __tablename__="user_table"

    user_name=  Column(String(255))
    user_email= Column(String,primary_key=True)
    password=   Column(String(255))
    otp=        Column(String(255))
