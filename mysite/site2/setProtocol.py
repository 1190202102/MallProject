import hashlib
from . import crypto
from . import mydb
from . import mall_operation
import json

def extract_c2b_data(pri_bytes:bytes,jsonStr:str):
    """
    params:
    pri_bytes: PEM-encoded private key bytes of bank or business
    jsonStr: the message client sent to bank or business,hybrid-encrypted
    return: dict sent by client
    """
    ekey,emsg=crypto.parse_hybrid_token(jsonStr)
    load=crypto.hybrid_decrypt(pri_bytes,ekey,emsg)
    return json.loads(load)

def verify_OI(msg_c2b:dict):
    """
    params:
    msg_c2b: return value of extract_c2b_data
    return:
    boolean
    """
    DS=msg_c2b['DS']
    OIMD=msg_c2b['PIMD']
    OI=msg_c2b['OI']
    PIMD=hashlib.sha1(OI.encode()).hexdigest()
    clientPubkey=mydb.get_pubkey_fromClientDB(OI['clientID'])
    res=crypto.verify_rsa_b64((PIMD+OIMD).encode(),DS,clientPubkey)
    return res

def process_order(msg_c2b:dict):
    """
    params:
    msg_c2b: return value of extract_c2b_data
    return:
    if success, return in-account and the amount of money
    else return false
    """
    if verify_OI(msg_c2b):
        OI_json=json.loads(msg_c2b['OI'])
        if mall_operation.sendToBank(msg_c2b['toBank']):
            mall_operation.proceed_trade(OI_json['clientID'],OI_json['shopcart'])
            return True
    return False

