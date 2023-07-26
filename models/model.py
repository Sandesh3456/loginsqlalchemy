from web_app import db
from datetime import datetime
from sqlalchemy import Column, String ,Integer


class USER(db.Model):

    __tablename__="user_table"


    user_id = Column(Integer, primary_key=True)
    user_name =  Column(String(255))
    user_email = Column(String, primary_key=True)
    password =   Column(String(255))
    created_date = Column(String(30), default = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])
