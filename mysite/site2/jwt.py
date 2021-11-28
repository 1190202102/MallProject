import datetime
import json
from . import crypto

def generate_token(username,card_ID,u_role,pri_key): #用户信息，权限角色,私钥签名
    # 这里需要生成token
    time1 = datetime.datetime.now()
    time1_str = datetime.datetime.strftime(time1, '%Y-%m-%d %H:%M:%S')
    token_1 = {'user': username, 'card_ID':card_ID, 'role': u_role, 'time': time1_str}
    token_str=str(token_1)
    token_sign=crypto.sign_rsa_b64(token_str.encode(),pri_key.encode())
    token=token_str+'.'+token_sign
    return token

def verfy_token(token,pub_key): #验证token是否正确
    list=token.split(".")
    token_str=list[0]
    token_sign=list[1]
    return crypto.verify_rsa_b64(token_str.encode(),token_sign,pub_key)

def explain_token(token): #如果验证成功通过是正确的token，那么进行这个验证函数
    list = token.split(".")
    token_str = list[0]
    token_dict=eval(token_str)
    return token_dict
