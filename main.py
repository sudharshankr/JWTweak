import argparse
from jwtweak import JWTweak
"""
JWTweak-v1.6

1: Detect the algorithm of the input JWT Token
2: Base64 decode the input JWT Token
3: Generate new JWT by changing the algorithm to 'none'
4: Generate new JWT by changing the algorithm to 'HS256'
5: Generate new JWT by changing the algorithm to 'HS384'
6: Generate new JWT by changing the algorithm to 'HS512'
7: Generate new JWT by changing the algorithm to 'RS256'
8: Generate new JWT by changing the algorithm to 'RS384'
9: Generate new JWT by changing the algorithm to 'RS512'
"""

parser = argparse.ArgumentParser(description='JWTeak Tool')
parser.add_argument('--jwt', nargs='?', help='Input JWT token')
# parser.add_argument('--detect', nargs='?', help='Detect the algorithm of the input JWT Token')
# parser.add_argument('--decode', nargs='?', help='Base64 decode the input JWT Token')
parser.add_argument('--create', nargs='?', help='Create new JWT with new algorithm. Specify algorithm. Default: none')
parser.add_argument('--payload', nargs='?', help='Provide new payload')
parser.add_argument('--key', nargs='?', help='Provide symmetric key')
args = parser.parse_args()

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








