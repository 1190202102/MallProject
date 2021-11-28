import hashlib
from . import crypto
import json

def extract_c2b_data(pri_bytes:bytes,jsonStr:str):
    """
    params:
    pri_bytes: PEM-encoded private key bytes of bank or business
    jsonStr: the message client sent to bank or business
    return: dict sent by client
    """
    ekey,emsg=crypto.parse_hybrid_token(jsonStr)
    load=crypto.hybrid_decrypt(pri_bytes,ekey,emsg)
    return json.loads(load)

def verify_I(msg_c2b:dict,pub_bytes:bytes):
    """
    verify PI or OI, accounting to msg_c2b
    params:
    msg_c2b: return value of extract_c2b_data
    pub_bytes: client's PEM-encoded public key bytes
    return:
    boolean
    """
    DS=msg_c2b['DS']
    if 'OIMD' in msg_c2b:
        OIMD=msg_c2b['OIMD']
        PI=msg_c2b['PI']
        PIMD=hashlib.sha1(PI.encode()).hexdigest()
    else:
        PIMD=msg_c2b["PIMD"]
        OI=msg_c2b['OI']
        OIMD=hashlib.sha1(OI.encode()).hexdigest()
    res=crypto.verify_rsa_b64((PIMD+OIMD).encode(),DS,pub_bytes)
    return res