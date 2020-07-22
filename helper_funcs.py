import base64
import json
from Crypto.PublicKey import RSA

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def RSAKeypairGen():
    new_key = RSA.generate(2048, e=65537)
    pubKey = new_key.publickey().exportKey("PEM")
    privKey = new_key.exportKey("PEM")
    return pubKey, privKey


def decode_base64(token, sign=False):
    token_decoded = ""
    if len(token) % 4 != 0:  # check if multiple of 4
        while len(token) % 4 != 0:
            token = token + "="
    try:
        if not sign:
            token_decoded = str(base64.b64decode(token), 'utf-8')
        else:
            token_decoded = str(base64.b64decode(token))
    except Exception as e:
        print(f"{bcolors.FAIL}\nThis may not be a JWT Token. Please check again{bcolors.ENDC}\n")
        print("The following Exception occurred: ", e)

    return token_decoded


def encode_base64(json_token):
    str_json_header = json.dumps(json_token)
    new_header = str(base64.b64encode(str_json_header.encode("utf-8")), 'utf-8')
    return new_header