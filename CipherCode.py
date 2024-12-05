# v0.0.1

# Using pycryptodome
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

import json
from base64 import b64encode, b64decode
import uuid

def encryptMessageChaCha20_Poly1305(key, message, aead = ''):
    # The result should be in Json format. Example:
    # {"nonce": "mNZxeCG19fvA2TLF", "header": "aGVhZGVy", "ciphertext": "kGB50VqzN2zeAffmj54=", "tag": "UULZU7fupukN0kxQC2PzpQ=="}
    
    plaintext = bytearray(message, encoding='utf-8')
    header = bytearray(aead, encoding='utf-8')
    
    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    jFields = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    jData = [ b64encode(dx).decode('utf-8') for dx in (cipher.nonce, header, ciphertext, tag) ]
    
    result = json.dumps(dict(zip(jFields, jData)))
    return result    

def decryptMessageChaCha20_Poly1305(key, encMessage):
    # encMessage is in Json format. Example:
    # {"nonce": "mNZxeCG19fvA2TLF", "header": "aGVhZGVy", "ciphertext": "kGB50VqzN2zeAffmj54=", "tag": "UULZU7fupukN0kxQC2PzpQ=="}
    
    message = ''
    aead = ''
    aeadPlain= ''
    errK = ''
    errV = ''
    alright = False
    try:
        jb64 = json.loads(encMessage)
    
        jFields = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jData = {f:b64decode(jb64[f]) for f in jFields}
    
        cipher = ChaCha20_Poly1305.new(key=key, nonce=jData['nonce'])
        byteAead = jData['header']
        cipher.update(byteAead)
        byteText = cipher.decrypt_and_verify(jData['ciphertext'], jData['tag'])
        
        message = byteText.decode('utf-8')
        aead = byteAead.decode('utf-8')
        alright = True
        # print("The message was: " + message)
    except ValueError as verr:
        # print("Incorrect decryption")
        errV = verr
    except KeyError as kerr:
        # print("Incorrect decryption")
        errK = kerr
    
    return message, aead, errK, errV, alright


def uuidGenerate(uuidVersion = 4):
    # make a random UUID
    uuid.uuid4()
    uid = str(uuid.uuid4())
    return uid

def uuidStrToUuidType(strUuid):
    uid = uuid.UUID(strUuid)
    return uid

