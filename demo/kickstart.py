from PHCMlib import *

def make_keys():
    alpha_key = gen_RSAkey()
    beta_key = gen_RSAkey()

    alpha_pub = alpha_key.publickey()
    beta_pub = beta_key.publickey()

    with open("server/keys/beta_private.key", "wb") as f:
        print("[+] " + f.name)
        f.write(beta_key.export_key())
    
    with open("server/keys/alpha_public.key", "wb") as f:
        print("[+] " + f.name)
        f.write(alpha_pub.export_key())

    with open("client_HSL/keys/alpha_private.key", "wb") as f:
        print("[+] " + f.name)
        f.write(alpha_key.export_key())

    with open("client_HSL/keys/beta_public.key", "wb") as f:
        print("[+] " + f.name)
        f.write(beta_pub.export_key())