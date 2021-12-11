import json
from datetime import time
import random
import mysql.connector
myconfig={
    'host':'localhost',
    'user':'root',
    'pwd':'200178heyang'
}
def sendToBank(msg_toBank):
    pass
def proceed_trade(shopcart_json,clientID):
    shopcart=json.loads(shopcart_json)
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )

    cursor=db.cursor()
    cursor.execute(f"select cart_info from cart where owner=\'{clientID}\'")
    result=cursor.fetchall()
    cart=result[0][0]

    cursor.execute("select count(*) from product_list")
    result = cursor.fetchall()
    line = result[0][0]
    lines=str(line+1)

    trade_time= str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))
    prog = 100 * random.random()

    cursor.execute(f"insert into bought_prod (trade_id,client,goods,trade_time,progess) values(\'{lines}\',\'{clientID}\',\'{cart}\',\'{trade_time}\',\'{prog}\')")
    db.commit()
    return
