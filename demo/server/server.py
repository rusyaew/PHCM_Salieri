from PHCMlib import *
from flask import Flask, request, session
import time
import json

app = Flask(__name__)
app.secret_key = os.urandom(16)


class KeyStorage:
    beta_private = None
    alpha_pub = None

    def __init__(self):
        with open("keys/beta_private.key", "r") as beta_file:
            self.beta_private = RSA.importKey(beta_file.read())
        
        with open("keys/alpha_public.key", "r") as alpha_file:
            self.alpha_pub = RSA.importKey(alpha_file.read())
    

class Server:
    beta_private = None
    alpha_pub = None
    beta_pub = None
    id_now = 0

    users = []
    containers = []
    active_sessions = []

    def __init__(self, _beta_private, _alpha_pub):
        self.beta_private = _beta_private
        self.alpha_pub = _alpha_pub
        self.beta_pub = _beta_private.publickey()
    
    def __str__(self):
        ret = ""
        ret += "[+] Beta_private: \n"
        ret += self.beta_private.export_key().decode() + "\n"

        ret += "[+] Beta_public: " + "\n"
        ret += self.beta_pub.export_key().decode() + "\n"

        ret += "[+] Alpha_public: "+ "\n"
        ret += self.alpha_pub.export_key().decode() + "\n"

        ret += "[+] Current ID: "
        ret += str(self.id_now) + "\n"

        ret += "[+] Server time: "
        ret += str(int(time.time())) + "\n"

        ret += "--- USERS ---"

        for i in self.users:
            ret += i.__str__()
        
        ret += "--- CONT ---"
        for i in self.containers:
            ret += i.__str__()

        return ret
        


        

    def register_user(this, gamma_pubkey):
        if gamma_pubkey in this.users:
            return 0
        else:
            this.users.append(gamma_pubkey)
    
    def issue_license(this, _id, gamma, ts_delta):
        ts_issued = int(time.time())
        ts_expiration = ts_issued + ts_delta

        license_info =  {'gamma': gamma, 'ts_issued': ts_issued, 'ts_expiration': ts_expiration}
        this.containers[_id]['users'].append(license_info)


    def register_code(this, firmware, max_len, code):
        this.containers.append({'users': [], "firmware": firmware, "max_len": max_len, "code": code})
        this.id_now += 1
        return this.id_now - 1
    
    
    
    def request(this, _id, gamma):
        if (_id >= this.id_now):
            return 0
        
        cont = this.containers[_id]
        user = None

        for i in cont['users']:
            if i['gamma'] == gamma.export_key():
                user = i
        
        if user is None:
            return 0
        
        cur_time = time.time()
        if cur_time > user['ts_expiration']:
            return 0
        
        return export_container(_id, cont['firmware'], cont['max_len'], cont['code'], user['ts_issued'], user['ts_expiration'])
    
    def handshake_response(this, handshake):
        handshake = debase(handshake)
        beta_st = SecureTunnel(this.beta_private, gen_RSAkey().publickey())
        msg = beta_st.decrypt(handshake)
        header, my_key, user_key, magic_value_b64, alpha_singature, gamma_signature = msg.split(b':')

        if cast_bytes( header ) != b'CLIENT_HELLO' or my_key != this.beta_pub.export_key():
            return 0
        
        
        gamma_key = RSA.importKey(user_key)
        if user_key not in this.users:
            return 0
        
        
        magic_value = debase(magic_value_b64)
        
        alpha_part = b':'.join(msg.split(b':')[:5])

        ok_gamma = check_plain(msg, gamma_key)
        ok_alpha = check_plain(alpha_part, this.alpha_pub)

        if not(ok_alpha and ok_gamma):
            return 0


        my_magic_value = os.urandom(32)

        resp = b'SERVER_RESPONSE:' + user_key + b':' + inbase(my_magic_value) + b':' +  inbase(magic_value)
        resp = get_signed(resp, this.beta_private)

        to_gamma_st = SecureTunnel(this.beta_private, RSA.import_key(user_key))
        to_alpha_st = SecureTunnel(this.beta_private, this.alpha_pub)

        msg = to_gamma_st.encrypt(resp)
        msg = to_alpha_st.encrypt(msg)
        this.active_sessions.append({'cookie': inbase(my_magic_value), 'gamma_key': RSA.import_key(user_key)})

        return inbase(msg), inbase(my_magic_value)
        #return beta_st.encrypt(resp)
    
    def active_session_exist(this, cookie):
        sess = None

        for i in this.active_sessions:
            if i['cookie'] == cookie:
                sess = i
        
        if sess is None: return 0

        return sess
    
    def request_enc(this, cont_id, gamma_pub):
        resp = this.request(cont_id, gamma_pub)

        if (resp == 0):
            return 0

        gamma_st = SecureTunnel(gen_RSAkey(), gamma_pub)
        alpha_st = SecureTunnel(gen_RSAkey(), this.alpha_pub)

        msg = alpha_st.encrypt(resp)
        msg = gamma_st.encrypt(msg)

        return inbase(msg)
    
    def available_licensies(this, _gamma):
        plain = _gamma.export_key()
        pt = "{"

        for cont in this.containers:
            for user in cont['users']:
                if user['gamma'] == plain:
                    copy = user
                    copy['gamma'] = cast_string(copy['gamma'])
                    if (len(pt) == 1):
                        pt += "\"" + str(this.containers.index(cont)) + "\":" + json.dumps(copy)
                    else:
                        pt += "," + " \"" + str(this.containers.index(cont)) + "\":" + json.dumps(copy)
        
        pt += "}"
        return pt


def import_containers(serv):
    containers = []
    for i in os.scandir('containers'):
        print('[+]', i.name)

        with open(i.path + '/main.py', 'r') as f:
            code = f.read()
        
        with open(i.path + '/metadata', 'rb') as f:
            metadata = f.read()
        
        firmware, maxlen = metadata.split(b'\x00')
        
        idd = serv.register_code(firmware, int(maxlen.decode()), code)
        print('[+] Registred ', idd, ' - ', i.name)

ks = KeyStorage()
server = Server(ks.beta_private, ks.alpha_pub)
server.register_user(b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKANc9Ebus/Z2vOxbfR4DWgiI/\nxkIrgLcQz44d8QZ99AEV/fz2q66JSylnernpzJSk0b64Fb4sNYMQPyk89gCwBbEn\ngRZzYeJzTBJr9xIrkVlkzbOUZHsO67WiKt74JqqkdicWeaH/JMeOPaCwvRUaVSyR\nIEQIfDVgujCu5QTxqwIDAQAB\n-----END PUBLIC KEY-----')
import_containers(server)
server.issue_license(0, server.users[0], 1337)

@app.route("/handshake", methods=["POST"])
def make_handshake():
    handshake = request.form['handshake']
    resp = server.handshake_response(handshake)
    if resp == 0:
        print('[!] Handshake declined.')
    else:
        print('[+] Handshake accepted. Session created.')

    pong, magic_value = resp
    session['magic_value'] = magic_value

    return pong

@app.route("/request_container", methods=["POST"])
def request_container():
    if 'magic_value' in session:
        backend_sess = 0
        backend_sess = server.active_session_exist(session['magic_value'])
        if backend_sess:
            print('[+] User requested ', int(request.form['id']), 'id.')
            otp =  server.request_enc(int(request.form['id']), backend_sess['gamma_key'])

            if (otp == '0'):
                print('↪ Request declined')
            else:
                print('↪ Request accepted')
            
            return otp
        else:
            print('↪ Session declined')
    else:
        print('↪ Session do not exist')
    
    return "HANDSHAKE_ERROR:Please, proceed to handshake first (/handshake)"

@app.route("/available_licensies", methods=["GET"])
def check_available():
    if 'magic_value' in session:
        backend_sess = 0
        backend_sess = server.active_session_exist(session['magic_value'])

        if backend_sess:
            print('[+] User requested list')
            otp = server.available_licensies(backend_sess['gamma_key'])
            print('[+] Response: ', otp)
            return otp
            

app.run(debug = True)
    
