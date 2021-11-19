import os

import Crypto.Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA,DSA
from Crypto.Cipher import PKCS1_OAEP
import time

from Crypto.Signature import DSS


def RSAEncrypt(msg,bitlength):
    RSA_start_time = time.time()
    KeyPair = RSA.generate(bitlength)
    privateKey = KeyPair.export_key()
    publicKey  = KeyPair.public_key()
    encryptor = PKCS1_OAEP.new(publicKey)
    encryptedMessage = encryptor.encrypt(msg)
    print("Encrypted Message : ",end="")
    print(encryptedMessage)
    decrypter = PKCS1_OAEP.new(KeyPair)
    decryptedMessage = decrypter.decrypt(encryptedMessage)
    print("Decrypted Message : " + decryptedMessage.decode('utf-8'))
    print("Original Message : " + msg.decode('utf-8'))
    print("RSA execution time : " + str(time.time() - RSA_start_time))

def DLVerify(msg):
    DL_start_time =  time.time()
    key = DSA.generate(2048)
    publickey = key.publickey()
    hash_obj = SHA256.new(msg)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    pkey = DSS.new(publickey, 'fips-186-3')
    try:
        pkey.verify(hash_obj, signature)
        print("The message is authentic")
        print("DL execution time : " + str(time.time() - DL_start_time))
    except:
        print("This message is not authentic")



msg = b'Hello world'
DLVerify(msg)