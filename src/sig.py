import hashlib
import os
import secrets

import tinyec.registry as reg
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



CURVE = reg.get_curve("secp256k1")
HASH_F = hashlib.sha3_256()

class Sign:
    def __init__(self, r, s, d):
        self.r = r
        self.s = s
        self.d = d

    def make_sig(self, hash):
        self.d = secrets.randbelow(CURVE.field.n - 1) + 1
        k = secrets.randbelow(CURVE.field.n - 1) + 1
        g = CURVE.g
        R = k*g
        self.r = R.x
        inverse_k = pow(k,-1,CURVE.field.n)
        self.s = inverse_k*(hash + self.r*self.d)



class Person:
    def __init__(self, p_k_ECC = None, G_point = None, mod = None, pub_k_ECC = None, sc_k_ECC = None, k_AES = None, message = "", crypt_message = None, name = "user"):
        self.p_k_ECC = p_k_ECC
        self.G_point = G_point
        self.mod = mod
        self.pub_k_ECC = pub_k_ECC
        self.sc_k_ECC = sc_k_ECC
        self.k_AES = k_AES
        self.message = message
        self.crypt_message = crypt_message
        self.name = name

    def key_gens(self):
        self.G_point = CURVE.g
        self.mod = CURVE.field.p
        self.p_k_ECC = secrets.randbelow(CURVE.field.n - 1) + 1
        self.pub_k_ECC = self.p_k_ECC * self.G_point

    def sh_sec_k(self, pub_k):
        self.sc_k_ECC = self.p_k_ECC * pub_k
        self.k_AES = hashlib.sha256(str(self.sc_k_ECC.x).encode()).digest()

    def encrypt_message(self, text: str):
        self.message = text
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(text.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.k_AES), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        self.crypt_message = iv + ct
        return self.crypt_message

    def decrypt_message(self, blob: bytes = None):
        if blob == None:
            blob = self.crypt_message
        iv = blob[:16]
        ct = blob[16:]
        cipher = Cipher(algorithms.AES(self.k_AES), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()
