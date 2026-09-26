import hashlib
import os
import secrets

import tinyec.registry as reg

CURVE = reg.get_curve("secp256k1")
HASH_F = hashlib.sha3_256


class Sign:
    def __init__(self, r, s, d):
        self.r = r
        self.s = s
        self.d = d
        self.pub = None

    def keygen(self):
        self.d = secrets.randbelow(CURVE.field.n - 1) + 1
        self.pub = self.d * CURVE.g
        return self

    def make_sig(self, hash):
        n = CURVE.field.n
        while True:
            k = secrets.randbelow(n - 1) + 1
            R = k * CURVE.g
            r = R.x % n
            if r == 0:
                continue
            s = (pow(k, -1, n) * (hash + r * self.d)) % n
            if s == 0:
                continue
            self.r = r
            self.s = s
            return self

    def verify(self, hash, r, s):
        if self.pub is None:
            return False
        r = self.r if r is None else r
        s = self.s if s is None else s
        n = CURVE.field.n
        try:
            s_inverse = pow(s, -1, n)
            u1 = (hash * s_inverse) % n
            u2 = (r * s_inverse) % n
            P = u1 * CURVE.g + u2 * self.pub
            if P is None:
                return False
            return P.x % n == r
        except Exception:
            return False
