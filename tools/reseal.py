#!/usr/bin/env python3
"""Darling Home vault tool: decrypt a sealed page to plaintext HTML, or re-seal it.

  decrypt:  python3 reseal.py open  <sealed.html> <passphrase>  > plain.html
  encrypt:  python3 reseal.py seal  <sealed.html> <passphrase> <plain.html>
            (rewrites sealed.html in place with a fresh IV, same salt)

The salt and iteration count are read from the sealed file itself, so cached
device keys keep working across rebakes. Requires: pip install cryptography.
"""
import re, sys, base64, secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def params(page):
    m = re.search(r"const SALT='([^']+)', IV='([^']+)', CT='([^']+)', ITER=(\d+);", page)
    if not m:
        sys.exit('no vault params found — is this a sealed page?')
    return m

def key_for(passphrase, salt, iters):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iters)
    return kdf.derive(passphrase.encode())

mode, path, passphrase = sys.argv[1], sys.argv[2], sys.argv[3]
page = open(path).read()
m = params(page)
salt, iv, ct, iters = base64.b64decode(m.group(1)), base64.b64decode(m.group(2)), base64.b64decode(m.group(3)), int(m.group(4))
aes = AESGCM(key_for(passphrase, salt, iters))

if mode == 'open':
    sys.stdout.write(aes.decrypt(iv, ct, None).decode())
elif mode == 'seal':
    plain = open(sys.argv[4]).read()
    new_iv = secrets.token_bytes(12)
    new_ct = aes.encrypt(new_iv, plain.encode(), None)
    new_line = "const SALT='%s', IV='%s', CT='%s', ITER=%d;" % (
        m.group(1), base64.b64encode(new_iv).decode(), base64.b64encode(new_ct).decode(), iters)
    open(path, 'w').write(page[:m.start()] + new_line + page[m.end():])
    print('resealed', path)
else:
    sys.exit('mode must be open|seal')
