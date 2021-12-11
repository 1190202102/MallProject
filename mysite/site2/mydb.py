import mysql.connector
from . import crypto
myconfig={
    'host':'localhost',
    'user':'root',
    'pwd':'200178heyang'
}
CAHost='127.0.0.1'
def get_pubkey_fromClientDB(clientID):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='bank_base',
    )
    cursor = db.cursor()

    cursor.execute(f"select certi from cli_certi where client=\'{clientID}\'")
    result = cursor.fetchall()
    certi = result[0][0]
    pubkey = crypto.load_cert(certi)['pubkey']
    return pubkey