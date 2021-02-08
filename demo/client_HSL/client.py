from PHCMlib import *
import requests
import time
import json


GAMMA_PRIVATE = None
GAMMA_PRIVATE = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDKANc9Ebus/Z2vOxbfR4DWgiI/xkIrgLcQz44d8QZ99AEV/fz2\nq66JSylnernpzJSk0b64Fb4sNYMQPyk89gCwBbEngRZzYeJzTBJr9xIrkVlkzbOU\nZHsO67WiKt74JqqkdicWeaH/JMeOPaCwvRUaVSyRIEQIfDVgujCu5QTxqwIDAQAB\nAoGAExwPlfDlWsD8AlWU3Sw0ACxRFiG+JRm+TReoKk/2B8NQuPu39b6ZuoDtmqL4\nZH7x5EJisvfSRPdjqI1ObDxvewxqt4NHhb/S6LPMQTtZg/aK7/ntP1fQS4UdC83J\nKvS70SY5XYOThdyl04DkpZptXdjDxTVtxrV+MyxBeUkRWC0CQQDiRPD6E9Bi7sO5\nkQeY8KCszEQTOGsTYMe9xmXFhRcar/qOV1MjKd7aLDeIHciItLwdTKmBIkvjn8kz\nY4sXWZ5lAkEA5Iuoya5FLmVmvw3El9NZ56xCw9vZEHuUz6SOkN+ZKZgwPtivmJNH\nHnVfMvneKSyHcv/GpiipPWjk2n41p0GGzwJBAOD4nQR4eOQ088PocD5fWdIVUsYt\nfUEKI+8LeRr3pi4xtJScPJwkwF/6QMiEnGNYGAWluI8dk4jh0UHYAm6X+4UCQEXb\nanw7CGpmFEHRs4W01IY74Sx8xpyDKblOU0V1ExvjqNuM4B+C5PoqZi7usTlkowJD\nrDSduR1MMqeWbE/zd4ECQQDeGEsdOKzoYzAzi/PF+b1ZEQu7JHbxqUOzu03u3uHg\ntayHuvS0LnzG6qkkQijqIN/NzHulgB58quZCWU9prmd8\n-----END RSA PRIVATE KEY-----'
API = "http://127.0.0.1:5000"


class KeyStorage:
    alpha_private = None
    beta_pub = None


    def __init__(self):
        with open("keys/alpha_private.key", "r") as alpha_file:
            self.alpha_private = RSA.importKey(alpha_file.read())
        
        with open("keys/beta_public.key", "r") as beta_file:
            self.beta_pub = RSA.importKey(beta_file.read())

class Container:
    encrypted_state = None
    signature_alpha = None
    signature_gamma = None

    cont_id = None
    firmware = None
    max_len = None
    code = None
    ts_issued = None
    ts_expiration = None

    def __init__(self, encrypted):
        self.encrypted_state = encrypted
    
    def apply_signatures(this, alpha_private, gamma_private):
        this.signature_alpha = signature(this.encrypted_state, alpha_private)
        this.signature_gamma = signature(this.encrypted_state, gamma_private)
    
    def decrypt(this, alpha_private, gamma_private):
        alpha_st = SecureTunnel(alpha_private, gen_RSAkey())
        gamma_st = SecureTunnel(gamma_private, gen_RSAkey())

        msg = gamma_st.decrypt(this.encrypted_state)
        msg = alpha_st.decrypt(msg)

        this.cont_id, this.firmware, this.max_len, this.code, this.ts_issued, this.ts_expiration = parse_container(msg)

    def execute(this, alpha_pub, gamma_pub):
        if (not verify_signature(this.encrypted_state, this.signature_alpha, alpha_pub) or not verify_signature(this.encrypted_state, this.signature_gamma, gamma_pub)):
            return 0
        
        print('[ --- ', this.firmware,  '/MAXINPUTLEN ', this.max_len)

        print("SIGNATURE OK")
        if this.ts_expiration < int(time.time()):
            print("License has expired.")
            return 0

        exec(this.code)

containers = []

class HSL:
    alpha_private = None
    beta_pub = None
    gamma_private = None
    magic_value = None
    cookie = None


    def __init__(self, alpha_private, beta_pub):
        self.alpha_private = alpha_private
        self.beta_pub = beta_pub
        if GAMMA_PRIVATE is not None:
            self.gamma_private = RSA.import_key(GAMMA_PRIVATE)
        else: self.gamma_private = gen_RSAkey()
    
    def handshake_make(this):
        this.magic_value = os.urandom(32)
        msg = b':'.join([b'CLIENT_HELLO', this.beta_pub.export_key(), this.gamma_private.publickey().export_key(), inbase(this.magic_value)])
        msg = get_signed(msg, this.alpha_private)
        msg = get_signed(msg, this.gamma_private)
        alpha_st = SecureTunnel(this.alpha_private, this.beta_pub)
        msg = alpha_st.encrypt(msg)

        return inbase(msg)
    
    def handshake_resp_verify(this, handshake):
        handshake = debase(handshake)
        to_alpha_st = SecureTunnel(this.alpha_private, this.beta_pub)
        to_gamma_st = SecureTunnel(this.gamma_private, this.beta_pub)

        handshake = to_alpha_st.decrypt(handshake)
        handshake = to_gamma_st.decrypt(handshake)

        header, my_key, cookie_session_key, magic_value_b64, beta_sign = handshake.split(b':')

        if header != b"SERVER_RESPONSE" or my_key != this.gamma_private.publickey().export_key():
            return 0

        print("META OK")

        if not check_plain(handshake, this.beta_pub):
            return 0
        
        print("SIGNATURE OK")

        if debase(magic_value_b64) == this.magic_value:
            this.cookie = cookie_session_key
            return 1
            
        else:
            return 0
    
    def InstallContainer(this, enc_cont):
        cont = Container(enc_cont)
        cont.apply_signatures(this.alpha_private, this.gamma_private)
        containers.append(cont)

        return len(containers) - 1
    
    def Execute(this, instance_id):
        inst = containers[instance_id]
        inst.decrypt(this.alpha_private, this.gamma_private)
        inst.execute(this.alpha_private.publickey(), this.gamma_private.publickey())


    
ks = KeyStorage()
hsl = HSL(ks.alpha_private, ks.beta_pub)

s = requests.Session()

def handshake():
    ping = hsl.handshake_make()
    params = {'handshake': ping}
    response = s.post(API + '/handshake', data=params)
    print(response.cookies)
    resp = response.content
    return hsl.handshake_resp_verify(resp)

def request_container(cont_id):
    params = {'id': cont_id}
    response = s.post(API + '/request_container', data=params, cookies=s.cookies)


    if response.content == b'0' or response.content == b'HANDSHAKE_ERROR:Please, proceed to handshake first (/handshake)':
        print("error")
    else:
        instance = hsl.InstallContainer(debase(response.content))
        return instance

def check_available():
    response = s.get(API + '/available_licensies', cookies=s.cookies)
    print(json.dumps(json.loads(cast_string(response.content))))
    

    print(response.content)

