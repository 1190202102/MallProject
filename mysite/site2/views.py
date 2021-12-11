from django.core.files.uploadedfile import InMemoryUploadedFile
from django.http import HttpResponse
from django.shortcuts import render
import mysql.connector
import hashlib
from django.core.cache import cache
import random
import json
import requests
from . import  crypto
from . import  jwt
from io import BytesIO



global hash_pwd
global challenge


myconfig={
    'host':'localhost',
    'user':'root',
    'pwd':'200178heyang'
}

def user(request):
    if request.method == 'POST':
        import requests
        import json
        user = request.POST['user']
        user_request = requests.get("https://api.github.com/users/" + user)
        username = json.loads(user_request.content)
        return render(request, 'user.html', {'user': user, 'username': username})
    else:
        notfound = "请在输入框中输入"
        return render(request, 'user.html', {'notfound': notfound})

def hash_accept(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    cursor = db.cursor()
    cursor.execute(f"select challenge from temp")
    result = cursor.fetchall()
    challenge = result[0][0]

    cursor.execute(f"select hash_pwd from temp")
    result = cursor.fetchall()
    hash_pwd = result[0][0]
    cursor.execute("delete from temp")
    db.commit()
    db.close

    temp=hash_pwd+challenge
    my_hash=hashlib.md5(temp.encode('utf8')).hexdigest()
    print(request.POST.get("hash"))
    mt_hash=request.POST.get("hash")
    key = "Q2Cm1lW95HmteIrluXIbn1jJgoG4iR6SuLWGILV1Jg0=".encode()
    mt_hash = crypto.fernet_decrypt(mt_hash, key)
    mt_hash=bytes.decode(mt_hash)

    if (mt_hash==my_hash):
        # 这里需要生成token
        p="pri_key"
        cursor.execute(f"select valstr from perm where keystr=\'{p}\'")
        result = cursor.fetchall()
        pri_key = result[0][0]

        username = request.POST.get("username")
        print("dayingde")
        print(username)
        query = f"select role from login where username=\'{username}\'"
        print(query)
        cursor.execute(query)
        result = cursor.fetchall()
        print(result[0][0])
        role = result[0][0]

        query = f"select user_ID from login where username=\'{username}\'"
        print(query)
        cursor.execute(query)
        result = cursor.fetchall()
        print(result[0][0])
        user_ID = result[0][0]

        token = jwt.generate_token(username,user_ID, role, pri_key)
        print("this is token")
        print(token)
        return HttpResponse(json.dumps({"resul" : "right","token":token}))
    else:
        return HttpResponse(json.dumps({"resul": "wrong"}))

def challenge_sender(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    cursor = db.cursor()
    challenge = hex(random.randint(0, 2 ** 64))
    challenge = challenge[2:18]

    m_name = request.POST.get("username")
    key = "Q2Cm1lW95HmteIrluXIbn1jJgoG4iR6SuLWGILV1Jg0=".encode()
    m_name = crypto.fernet_decrypt(m_name, key)
    m_name = bytes.decode(m_name)
    print(m_name)
    query = f"select hash_pwd from login where username=\'{m_name}\'"
    print(query)
    cursor.execute(query)
    result = cursor.fetchall()
    print(result)
    if (result != []):
        hash_pwd = result[0][0]
        print("查找散列的密码bob:" + hash_pwd)
        cursor.execute(f"insert into temp (challenge,hash_pwd) values (\'{challenge}\', \'{hash_pwd}\')")
        db.commit()
        return HttpResponse(json.dumps({"challenge": challenge, "resul": "right"}))
    else:  # 不存在该管理员
        return HttpResponse(json.dumps({"resul": "wrong"}))


def login(request):
    return render(request, 'login.html', {})

def process(request):
    return render(request, 'login.html', {})

def process_login(request):
    return render(request, 'logon.html', {})

def logon(request):
    return render(request, 'logon.html', {})

def send_certi(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    tag = "mall_certi"
    cursor = db.cursor()
    cursor.execute(f"select valstr from perm where keystr=\'{tag}\'")
    result = cursor.fetchall()
    certi = result[0][0]
    return HttpResponse(json.dumps({"certi": certi}))


def push_user_info(text):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    cursor = db.cursor()
    cursor.execute("select count(*) from login")
    result = cursor.fetchall()

    text=eval(text)
    user_ID=text['emali']
    print(user_ID)
    hash_pwd=text['password']
    username=text['username']
    role='user'
    dict={}
    dict_json=json.dumps(dict)
    cursor.execute(f"insert into login (username,hash_pwd,user_ID,role) values (\'{username}\', \'{hash_pwd}\', \'{user_ID}\', \'{role}\')")
    cursor.execute(f"insert into cart (owner,cart_info) values (\'{username}\',\'{dict}\')")
    db.commit()

    db.close
    return

def process_logon(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    cursor = db.cursor()
    name="pri_key"
    cursor.execute(f"select valstr from perm where keystr=\'{name}\'")
    result = cursor.fetchall()
    pri_key = result[0][0]


    info=json.loads(request.body)
    print(info)

    print(info['key'])
    print(type(info['key']))
    print(info['msg'])
    plaintext=crypto.hybrid_decrypt(pri_key.encode(),info['key'],info['msg'])
    userinfo=json.loads(plaintext)
    username=userinfo['username']
    print(username)

    query = f"select user_ID from login where username=\'{username}\'"
    cursor.execute(query)
    result = cursor.fetchall()
    if (result != []): #已经有了这个人
        print("okokokok")
        return HttpResponse(json.dumps({"flag": "wrong"}))
    else: #还没有这个人

        print(plaintext)
        push_user_info(plaintext)
        return HttpResponse(json.dumps({"flag": "right"}))


# 这部分目前剩下两个问题就解决
# 1.注册信息填入到info_user中是否无误
# 2.token填入和检测功能是否正常运行
def mall_home(request):
    return render(request, 'mall_home.html', {})

def store_pro_info(request):
    return
def send_prod_home_info(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    cursor = db.cursor()
    qury=f"select * from product_list;"
    cursor.execute(qury)
    result1 = cursor.fetchall()
    l=len(result1)
    print(result1)
    #处理读出的数据需要主页信息即可，不用简介
    return HttpResponse(json.dumps({"num": l,"data": result1}))

def send_prod_detail_info(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    prod_ID = request.POST.get('prod_ID')
    cursor = db.cursor()
    cursor.execute(f"select * from product_list where prod_ID=\'{prod_ID}\'")
    result1 = cursor.fetchall()
    #全部读出
    return HttpResponse(json.dumps({"data": result1}))



def notfound(request,exception,):
    response = render(request,"404.html")
    response.status_code = 404
    return response

def forgetpwd(request):
    return render(request,'forgot-password.html',{})

def index(request):
    return render(request,'index.html',{})

def login_mall(request):
    return render(request,'login.html',{})

def register(request):
    return render(request,'register.html',{})

def shopcart(request):
    return render(request,'shopcart.html',{})

def tables(request):
    return render(request,'tables.html',{})

def add_product(request):
    return

def personal_index(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    prod_ID = request.POST.get('prod_ID')
    cursor = db.cursor()
    cursor.execute(f"select * from product_list where prod_ID=\'{prod_ID}\'")

def detail_goods(request):
    return render(request,'goods.html',{})

def upload(request):
    return render(request,'upload.html',{})

def store_pro(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    cursor = db.cursor()
    cursor.execute("select count(*) from product_list")
    result = cursor.fetchall()
    line = result[0][0]
    file_obj = request.FILES.get('pic')
    print("line",line)
    f1 = open('./static/product_image/'+str(line+1)+'.jpg', "wb")
    for i in file_obj.chunks():
        f1.write(i)
    f1.close()

    lines=str(line+1)
    pri=request.POST.get('price')
    info=request.POST.get('info')
    name=request.POST.get('name')
    categ='Small-sized'
    cursor.execute(f"insert into product_list (prod_ID,prod_name,prod_price,prod_intro,prod_categ) values (\'{lines}\', \'{name}\', \'{pri}\', \'{info}\', \'{categ}\')")
    db.commit()
    return render(request, 'mall_home.html')

def add_cart(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )

    cursor = db.cursor()
    tag = 'pub_key'
    cursor.execute(f"select valstr from perm where keystr=\'{tag}\'")
    result = cursor.fetchall()
    pub_key = result[0][0]

    info = json.loads(request.body)
    token = info['token']
    print(token)
    if (jwt.verfy_token(token, pub_key.encode()) == False):  # token验证失败
        return HttpResponse(json.dumps({"flag": "token wrong"}))
    else:
        dict_token = jwt.explain_token(token)
        owner_name=dict_token['name']  ####这里的键值有问题可能
        pro_id=info['id']
        pro_num=info['num']

        cursor.execute(f"select * from cart where owner=\'{owner_name}\'")
        result=cursor.fetchall()
        cart=result[0][0]
        cart_dict=json.loads(cart)
        if (cart_dict.has_key(pro_id)==True):
            num=cart_dict.get(pro_id)
            num=num+pro_num
            if (num<0):
                return HttpResponse(json.dumps({"flag": '购物出操作有误'}))
            else:
                cart_dict[pro_id]=num
                cart=json.dumps(cart_dict)
                cursor.execute(f"update cart set cart_info='\{cart}'\ where owner=\'{owner_name}\'")
                return HttpResponse(json.dumps({"flag": cart}))
        else:
            cart_dict={pro_id:pro_num}
            cursor.execute(f"update cart set cart_info='\{cart}'\ where owner=\'{owner_name}\'")
            return HttpResponse(json.dumps({"flag": cart}))

def read_cart(request):
    db = mysql.connector.connect(
        host=myconfig['host'],
        user=myconfig['user'],
        password=myconfig['pwd'],
        db='online_mall',
    )
    cursor = db.cursor()
    tag = 'pub_key'
    cursor.execute(f"select valstr from perm where keystr=\'{tag}\'")
    result = cursor.fetchall()
    pub_key = result[0][0]

    info = json.loads(request.body)
    token = info['token']
    print(token)
    if (jwt.verfy_token(token, pub_key.encode()) == False):  # token验证失败
        return HttpResponse(json.dumps({"flag": "token wrong"}))
    else:
        dict_token = jwt.explain_token(token)
        owner_name = dict_token['name']  ####这里的键值有问题可能
        cursor.execute(f"select cart_info from cart where owner=\'{owner_name}\'")
        result=cursor.fetchall()
        cart=result[0][0]
        return HttpResponse(json.dumps({"flag": cart}))








