import jwt
import re
import argparse
import base64
import json
from Crypto.PublicKey import RSA

"""
JWTweak-v1.6

1: Detect the algorithm and decode the input JWT Token
2: Generate new JWT with algorithm ['none','HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']
"""

parser = argparse.ArgumentParser(description='JWTeak Tool')
parser.add_argument('--jwt', nargs='?', help='Input JWT token')
# parser.add_argument('--detect', nargs='?', help='Detect the algorithm of the input JWT Token')
# parser.add_argument('--decode', nargs='?', help='Base64 decode the input JWT Token')
parser.add_argument('--create', nargs='?', help='Create new JWT with new algorithm. Specify algorithm. Default: none')
parser.add_argument('--payload', nargs='?', help='Provide new payload')
parser.add_argument('--key', nargs='?', help='Provide symmetric key')
args = parser.parse_args()


class bcolors:
    """
    Setting terminal colors
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def RSAKeypairGen():
    """
    Creating RSA key pair
    """
    new_key = RSA.generate(2048, e=65537)
    pubKey = new_key.publickey().exportKey("PEM")
    privKey = new_key.exportKey("PEM")
    return pubKey, privKey


def decode_base64(token, sign=False):
    """
    Decode base64 encoded parts of the JWT
    """
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
    """
    Encode parts of JWT using base64
    """
    str_json_header = json.dumps(json_token)
    new_header = str(base64.b64encode(str_json_header.encode("utf-8")), 'utf-8')
    return new_header


class JWTweak:
    def __init__(self, token=None):
        """
        Initializing JWT token, its header and payload
        """
        if token:
            if re.match(r'^ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$', token):
                # print(f"{bcolors.OKGREEN}\nThis is a valid input JWT Token{bcolors.ENDC}")
                # print(f"{bcolors.BOLD}")
                print()
            else:
                raise ValueError("Invalid JWT token")

        self._jwt = token
        self._header, self._payload, self._signature = ("", "", "") if not token \
            else map(lambda x: x, self._jwt.split('.'))
        self._algo = ""

    def detect(self):
        """
        Detect the algorithm of the given JWT
        """
        json_header = json.loads(decode_base64(self._header))
        self._algo = json_header['alg']
        print("The present algorithm of input JWT Token- " + f"{bcolors.OKGREEN}" + f"{bcolors.BOLD}" + self._algo
              + f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

    def decode(self):
        """
        Decode the given JWT
        """
        print(f"{bcolors.WARNING}Decoded JWT:{bcolors.ENDC}")
        sign = self._signature.replace('_', '/').replace('-', '+')
        print("Header = %s \nPayload = %s \nSignature = %s" %
              (decode_base64(self._header), decode_base64(self._payload), decode_base64(sign, sign=True)))

    def create_new_jwt(self, payload, algo, key):
        """
        Create new JWT with the payload, algorithm and key (if applicable) given in the arguments
        """
        mod_payload = ""
        if payload:
            if re.match(r'(.*?)(?:")', payload):
                mod_payload = json.loads(payload)
            else:
                raise ValueError("Not Valid Payload")
        else:
            if self._payload is not None:
                mod_payload = json.loads(decode_base64(self._payload))
            else:
                raise ValueError("No Payload given to create new JWT")

        print("\nPayload(Plain Text)=" + str(mod_payload))
        if algo == 'none':
            # new_jwt = mod_header + "." + encode_base64(mod_payload) + "."
            key = None
            algo = None

        elif algo in ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']:
            if key is None:
                raise ValueError("Please provide key")

        new_jwt = jwt.encode(mod_payload, key, algorithm=algo).decode('utf-8')
        print("\nThe New JWT Token with Algorithm changed to %s is : %s \n\n" % (algo,
                                                                                 f"{bcolors.OKGREEN}" + f"{bcolors.BOLD}"
                                                                                 + new_jwt + f"{bcolors.OKGREEN}{bcolors.ENDC}"))


if __name__ == '__main__':
    jwt_token = JWTweak(args.jwt)
    if args.jwt:
        jwt_token.detect()
        jwt_token.decode()
    if args.create:
        payload = None
        if args.payload:
            payload = args.payload
        try:
            jwt_token.create_new_jwt(payload, args.create, args.key)
        except Exception as e:
            print("Error: ", e)