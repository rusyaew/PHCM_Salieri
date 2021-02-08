from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import os

def gen_RSAkey():
    return RSA.generate(1024, os.urandom)

def cast_bytes(a):
    if type(a) is bytes:
        return a
    elif type(a) is str:
        return a.encode()
    else:
        return a

def cast_string(a):

    if type(a) is str:
        otp = a
    else:
        otp = a.decode()

    return otp



def signature(msg, RSAprivate):
    hasher = SHA256.new()

    msg = cast_bytes(msg)
    hasher.update(msg)

    signer = pkcs1_15.new(RSAprivate)
    return signer.sign(hasher)

def verify_signature(msg, sig, RSApublic):

    msg = cast_bytes(msg)
    hasher = SHA256.new()
    hasher.update(msg)
    signer = pkcs1_15.new(RSApublic)

    try:
        signer.verify(hasher, sig)
    except:
        return 0
    
    return 1

def debase(msg):
    msg = cast_bytes(msg)
    return base64.b64decode(msg)

def inbase(msg):
    msg = cast_bytes(msg)
    return base64.b64encode(msg)

def export_container(_id, firmware, max_len, code, ts_issued, ts_expiration):
    id_s = str(_id)
    firmware_s = cast_string(firmware)
    max_len_s = str(max_len)
    code_s = cast_string(inbase(code))
    ts_issued_s = str(ts_issued)
    ts_expiration_s = str(ts_expiration)

    otp = [id_s, firmware_s, max_len_s, code_s, ts_issued_s, ts_expiration_s]
    data = ':'.join(otp)
    return data

def parse_container(data):
    data = cast_bytes(data)
    container = data.split(b':')
    _id = int(container[0])
    firmware = debase(container[1])
    max_len = int(container[2])
    code = debase(container[3])
    ts_issued = int(container[4])
    ts_expiration = int(container[5])

    return _id, firmware, max_len, code, ts_issued, ts_expiration

def check_plain(msg, RSApublic):
    msg = cast_bytes(msg)
    parts = msg.split(b':')
    msg = parts[:-1]
    msg = b':'.join(msg)
    signature_b64 = parts[-1]

    signature = debase(signature_b64)
    return verify_signature(msg, signature, RSApublic)

def get_signed_b64(msg, RSAprivate):
    return inbase(msg) + b':' + inbase(signature(msg, RSAprivate))

def get_signed(msg, RSAprivate):
    return cast_bytes( msg ) + b':' + inbase(signature(msg, RSAprivate))


def check_base(msg, RSApublic):
    msg = cast_bytes(msg)
    parts = msg.split(b':')
    msg_b64 = parts[0]
    signature_b64 = parts[1]

    signature = debase(signature_b64)
    msg = debase(msg)

    return verify_signature(msg, signature, RSApublic)



def RSAdecrypt(msg, private_key):
    CipherRSA = PKCS1_OAEP.new(private_key)
    msg = cast_bytes(msg)

    return CipherRSA.decrypt(msg)

def RSAencrypt(msg, public_key):
    CipherRSA = PKCS1_OAEP.new(public_key)
    msg = cast_bytes(msg)

    return CipherRSA.encrypt(msg)

def RSA_AES_encrypt(msg, RSApublic):
    msg = cast_bytes(msg)
    CipherRSA = PKCS1_OAEP.new(RSApublic)
    session_key = os.urandom(16)
    
    enc_session_key = CipherRSA.encrypt(session_key)
    CipherAES = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = CipherAES.encrypt_and_digest(msg)
    msg = enc_session_key + CipherAES.nonce + tag + ciphertext

    return msg

def parse_AES(msg, my_privatekey):
    enc_session_key, nonce, tag, ciphertext = msg[:my_privatekey.size_in_bytes()], \
    msg[my_privatekey.size_in_bytes():my_privatekey.size_in_bytes() + 16], msg[my_privatekey.size_in_bytes() + 16:my_privatekey.size_in_bytes() + 16 + 16],\
    msg[my_privatekey.size_in_bytes() + 32:]

    return enc_session_key, nonce, tag, ciphertext



class SecureTunnel:
    session_key = None
    enc_session_key = None
    RSAprivate_me = None
    RSApublic_other = None
    CipherAES = None

    def __init__(self, _RSAprivate_me, _RSApublic_other):
        session_key = os.urandom(16)
        self.session_key = session_key
        self.enc_session_key = RSAencrypt(session_key, _RSApublic_other)

        CipherAES = AES.new(session_key, AES.MODE_EAX)

        self.RSAprivate_me = _RSAprivate_me
        self.RSApublic_other = _RSApublic_other

    def encrypt(this, msg):
        CipherAES = AES.new(this.session_key, AES.MODE_EAX)
        msg = cast_bytes(msg)
        ciphertext, tag = CipherAES.encrypt_and_digest(msg)
        return this.enc_session_key + CipherAES.nonce + tag + ciphertext

    def decrypt(this, ciphertext):
        enc_session_key, nonce, tag, ciphertext = parse_AES(ciphertext, this.RSAprivate_me)

        session_key = RSAdecrypt(enc_session_key, this.RSAprivate_me)
        DeCipherAES = AES.new(session_key, AES.MODE_EAX, nonce)
        return DeCipherAES.decrypt_and_verify(ciphertext, tag)
