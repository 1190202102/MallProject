from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.base import load_pem_x509_csr
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
import base64
import datetime
import time
import hashlib
import json

def fernet_decrypt(token: str, key):
    """
    params:
    token: fernet token ,urlsafe base64-encoded in new Fernet.encrypt()
    key: urlsafe base64-encrypted 32-bytes random integer in hexdump
    return:
    bytes
    """
    fernet = Fernet(key)
    return fernet.decrypt(token.encode())


def fernet_encrypt(m, key):
    """
    params:
    m: plaintext string
    key: urlsafe base64-encrypted 32-bytes random integer in hexdump
    return:
    bytes
    """
    fernet = Fernet(key)
    return fernet.encrypt(m)


def genKey(bits: int):
    """
    params:
    bits: length of key
    return: 
    PEM-encoded RSA  public key-bytes and private key-bytes
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )
    pri_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM)
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM)
    return pub_bytes, pri_bytes


def rsa_decrypt_b64(c64: str, prikey: bytes):
    """
    params:
    c64: base64 encrypted ciphertext in str
    prikey: PEM-encoded private key-bytes
    return: 
    plaintext in bytes
    """
    c = base64.decodebytes(c64.encode())
    private_key = serialization.load_pem_private_key(prikey, None)
    p = private_key.decrypt(c, padding.PKCS1v15())
    return p


def rsa_encrypt_b64(m: str, pubkey: bytes):
    """
    params:
    m: plaintext in str
    pubkey: PEM-encoded public key-bytes
    return: 
    base64-encoded ciphertext in str
    """
    public_key = serialization.load_pem_public_key(pubkey)
    c = public_key.encrypt(m.encode(), padding.PKCS1v15())
    c64 = base64.encodebytes(c).decode()
    return c64


def sign_rsa_b64(info: bytes, prikey: bytes):
    """
    params:
    info: message to be signed, bytes
    prikey: PEM-encoded private key-bytes
    return: 
    base64-encoded signature in str
    """
    private_key = serialization.load_pem_private_key(prikey, None)
    signature = private_key.sign(
        info, padding.PKCS1v15(), hashes.SHA1())
    sig64 = base64.encodebytes(signature).decode()
    sig64=sig64.replace("\n","")
    return sig64


def verify_rsa_b64(info: bytes, s64: str, pubkey: bytes):
    """
    params:
    info: message to be verified
    s64: base64-encoded signature in str
    pubkey: PEM-encoded public key-bytes
    return: 
    True or False
    """
    signature = base64.decodebytes(s64.encode())
    public_key = serialization.load_pem_public_key(pubkey)
    try:
        public_key.verify(signature, info,padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception as e:
        print(str(e))
        return False


def sign_cert_fromPUB(pub_client: bytes, pri_CA: bytes, owner: str):
    CA = serialization.load_pem_private_key(pri_CA, password=None)
    one_day = datetime.timedelta(1, 0, 0)
    print(pub_client)
    public = serialization.load_pem_public_key(pub_client)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, owner),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'myCA'),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(
        datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public)
    # builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u'cryptography.io')]),critical=False)
    # builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,)
    certificate = builder.sign(private_key=CA, algorithm=hashes.SHA1())
    cer_b64 = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return cer_b64


def load_pub_fromCSR(CSR: bytes):
    csr = load_pem_x509_csr(CSR)
    if(csr.is_signature_valid):
        return csr.public_bytes(encoding=serialization.Encoding.PEM)
    else:
        return None


def buildCSR(pri_key: bytes):
    pri_subject=serialization.load_pem_private_key(pri_key)
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    ]))
    #builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,)
    #builder = builder.add_attribute(AttributeOID.CHALLENGE_PASSWORD, b"changeit")
    request = builder.sign(pri_subject, hashes.SHA1())
    return request.public_bytes(encoding=serialization.Encoding.PEM)


def verify_cert(pub_CA: bytes, cert_bytes: bytes):
    pub = serialization.load_pem_public_key(pub_CA)
    cert = load_pem_x509_csr(cert_bytes)
    try:
        pub.verify(cert.signature, cert.tbs_certrequest_bytes,
                   padding.PKCS1v15(), cert.signature_hash_algorithm)
        return True
    except:
        return False


def load_cert(pem_cert):
    if type(pem_cert) is str:
        data = pem_cert.encode()
    else:
        data = pem_cert
    cert = load_pem_x509_certificate(data)
    cert_dict = {}
    cert_dict['certi_num'] = cert.serial_number
    subject = cert.subject
    cert_dict['owner'] = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
        0].value
    cert_dict['start_time'] = str(cert.not_valid_after)
    cert_dict['end_time'] = str(cert.not_valid_before)
    return cert_dict

def parse_hybrid_token(token_json):
    token=json.loads(token_json)
    return (token['key'],token['msg'])

def hybrid_decrypt(pri_bytes, Enc_key: str, encrypted_msg: str)->str:
    """
    params:
    pri_bytes: PEM-encoded private key bytes
    Enc_key: Public-key-encrypted Key for Fernet
    msg: Fernet-Encrypted ciphertext
    return:
    plaintext string
    """
    syn_key = rsa_decrypt_b64(Enc_key, pri_bytes)
    plain = fernet_decrypt(encrypted_msg, syn_key)
    return plain.decode(encoding='utf-8')


def hybrid_encrypt(pub_bytes: bytes, msg: str):
    """
    params:
    pub_bytes: PEM-encoded public key bytes
    msg: plaintext string
    return:
    base64-encoded public-key-encrypted fernet key , 
    fernet token 解密时无需先base64解码
    """
    rnd_key = base64.urlsafe_b64encode(hashlib.md5(
        (str(time.time())+"timerndmize").encode()).hexdigest().encode()).decode()
    Enc_key = rsa_encrypt_b64(rnd_key, pub_bytes)
    enced_msg = fernet_encrypt(msg.encode(), rnd_key).decode()
    return Enc_key, enced_msg


if __name__ == "__main__":
    with open("private.pem", "rb") as prif:
        private = prif.read()
    with open("public.pem", "rb") as pubf:
        public = pubf.read()
    cert = sign_cert_fromPUB(
        public, serialization.load_pem_private_key(private, password=None))
    print(cert)
    print(len(cert))
