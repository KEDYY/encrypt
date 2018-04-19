#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from binascii import (hexlify, unhexlify)

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../src/")


def test_fast():
    import pySM4 as sm4
    key = unhexlify("0123456789ABCDEFFEDCBA9876543210")
    clear = key
    cipher = clear
    for i in range(10 ** 6):
        cipher = sm4.encrypt(key, cipher)

    print(hexlify(cipher))
    clear = unhexlify("595298c7c6fd271f0402f804c33d3f66")
    cipher = clear
    for i in range(10 ** 6):
        cipher = sm4.decrypt(key, cipher)

    print(hexlify(cipher))


def test_slow():
    from slowSM4 import SM4
    from time import time
    key = "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10".replace(" ", "")
    obj = SM4(key)
    s1 = time()
    res = unhexlify(key)
    for i in range(10 ** 6):
        res = obj.encrypt(res)
        if i % 1000 == 500:
            print("{} times/s".format(500 / (time() - s1)))
            s1 = time()
            try:
                print(hexlify(res))
            except Exception:
                print(res.encode("base64"))
    print(hexlify(res))
    # 一百万次加密后 X"59 52 98 c7 c6 fd 27 1f 04 02 f8 04 c3 3d 3f 66"


if __name__ == '__main__':
    # test_fast()
    test_slow()
