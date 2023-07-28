from web_app import db


def list_names():
    sql = "select * from user_table;"
    row = db.session.execute(sql)
    return row


list_names()
