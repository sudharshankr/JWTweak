import jwt
import re
import json
from helper_funcs import bcolors, decode_base64, encode_base64


class JWTweak:
    def __init__(self, token=None):
        if token:
            if re.match(r'^ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$', token):
                # print(f"{bcolors.OKGREEN}\nThis is a valid input JWT Token{bcolors.ENDC}")
                # print(f"{bcolors.BOLD}")
                print()
            else:
                print("Invalid JWT token")
                exit(1)
        self._jwt = token
        self._header, self._payload, self._signature = ("", "", "") if not token \
            else map(lambda x: x, self._jwt.split('.'))
        self._algo = ""

    def detect(self):
        json_header = json.loads(decode_base64(self._header))
        self._algo = json_header['alg']
        print("The present algorithm of input JWT Token- " + f"{bcolors.OKGREEN}" + f"{bcolors.BOLD}" + self._algo
              + f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

    def decode(self):
        print(f"{bcolors.WARNING}Decoded JWT:{bcolors.ENDC}")
        sign = self._signature.replace('_', '/').replace('-', '+')
        print("Header = %s \nPayload = %s \nSignature = %s" %
              (decode_base64(self._header), decode_base64(self._payload), decode_base64(sign, sign=True)))

    def create_new_jwt(self, payload, algo, key):
        # json_header = json.loads(decode_base64(self._header))
        # json_header['alg'] = algo
        # mod_header = encode_base64(json_header)
        # mod_payload = json.loads(decode_base64(self._payload))
        mod_payload = ""
        if payload:
            if re.match(r'(.*?)(?:")', payload):
                mod_payload = json.loads(payload)
            else:
                print("Not Valid Payload")
                exit(1)
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
                print("Please provide key")
                exit(1)

        new_jwt = jwt.encode(mod_payload, key, algorithm=algo).decode('utf-8')
        print("\nThe New JWT Token with Algorithm changed to %s is : %s \n\n" % (algo,
                                                                                 f"{bcolors.OKGREEN}" + f"{bcolors.BOLD}"
                                                                                 + new_jwt + f"{bcolors.OKGREEN}{bcolors.ENDC}"))
