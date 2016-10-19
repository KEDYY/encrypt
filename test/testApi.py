#! /usr/bin/env python2
def test_fast():
    import pySM4 as sm4
    from binascii import hexlify as hexs,unhexlify as unhexs
    key=unhexs("0123456789ABCDEFFEDCBA9876543210")
    clear= key
    cipher=clear 
    for i in xrange(10**6):
        cipher  = sm4.encrypt(key, cipher)

    print hexs(cipher)
    clear=unhexs("595298c7c6fd271f0402f804c33d3f66")
    cipher=clear 
    for i in xrange(10**6):
        cipher  = sm4.decrypt(key, cipher)

    print hexs(cipher)

def tests_low():
    from slowSM4 import SM4
    from time import time
    KEY = "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10".replace(" ","")
    DATA = unhexs(KEY)
    obj = SM4(KEY)
    s1 = time()
    res = obj.encrypt(DATA)
    for i in xrange(9999):
        res = obj.encrypt(res)
        if i% 1000 ==500:
            print 500 / (time()-s1) , "times/s"
            s1=time()
            print(hexs(res))
    print hexs(res)
    #一百万次加密后 X"59 52 98 c7 c6 fd 27 1f 04 02 f8 04 c3 3d 3f 66"

if __name__ == '__main__':
    test_fast()
    test_slow()
