import os

import Crypto.Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA,DSA
from Crypto.Cipher import PKCS1_OAEP
import time

from Crypto.Signature import DSS, pkcs1_15


def RSAVerify(msg,bitlength):
    RSA_start_time = time.time()
    key = RSA.generate(bitlength)
    publickey = key.publickey()
    hash_obj = SHA256.new(msg)
    signer = pkcs1_15.new(key)
    signature = signer.sign(hash_obj)
    pkey = pkcs1_15.new(publickey)
    try:
        pkey.verify(hash_obj, signature)
        print("The message is authentic")
        print("RSA execution time : " + str(time.time() - RSA_start_time))
    except:
        print("This message is not authentic")

def DLVerify(msg,bitlength):
    DL_start_time =  time.time()
    key = DSA.generate(bitlength)
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
RSAVerify(msg,1024)
DLVerify(msg,1024)