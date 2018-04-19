# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import struct
from binascii import unhexlify

import six

"""
国密 SM4（无线局域网SMS4）算法
分组算法 长度 128bit即16字节；密钥128bit即16字节
根据标准叙述文件编写，效率极低，作为学习理解之用，一般性算法工具
如果希望用于大数据量加解密，请使用C/C++ 实现并编译python模块
最后修改时间：2018年4月19日
"""
__author__ = '<yifei0727@gmail.com>'
__date__ = '2014/8/13'
__version__ = '0.1.1'
__license__ = 'The MIT License'

__all__ = ["SM4"]

# S 置换盒
SBox = {
    0x00: 0xd6, 0x01: 0x90, 0x02: 0xe9, 0x03: 0xfe, 0x04: 0xcc, 0x05: 0xe1, 0x06: 0x3d, 0x07: 0xb7,
    0x08: 0x16, 0x09: 0xb6, 0x0a: 0x14, 0x0b: 0xc2, 0x0c: 0x28, 0x0d: 0xfb, 0x0e: 0x2c, 0x0f: 0x05,

    0x10: 0x2b, 0x11: 0x67, 0x12: 0x9a, 0x13: 0x76, 0x14: 0x2a, 0x15: 0xbe, 0x16: 0x04, 0x17: 0xc3,
    0x18: 0xaa, 0x19: 0x44, 0x1a: 0x13, 0x1b: 0x26, 0x1c: 0x49, 0x1d: 0x86, 0x1e: 0x06, 0x1f: 0x99,

    0x20: 0x9c, 0x21: 0x42, 0x22: 0x50, 0x23: 0xf4, 0x24: 0x91, 0x25: 0xef, 0x26: 0x98, 0x27: 0x7a,
    0x28: 0x33, 0x29: 0x54, 0x2a: 0x0b, 0x2b: 0x43, 0x2c: 0xed, 0x2d: 0xcf, 0x2e: 0xac, 0x2f: 0x62,

    0x30: 0xe4, 0x31: 0xb3, 0x32: 0x1c, 0x33: 0xa9, 0x34: 0xc9, 0x35: 0x08, 0x36: 0xe8, 0x37: 0x95,
    0x38: 0x80, 0x39: 0xdf, 0x3a: 0x94, 0x3b: 0xfa, 0x3c: 0x75, 0x3d: 0x8f, 0x3e: 0x3f, 0x3f: 0xa6,

    0x40: 0x47, 0x41: 0x07, 0x42: 0xa7, 0x43: 0xfc, 0x44: 0xf3, 0x45: 0x73, 0x46: 0x17, 0x47: 0xba,
    0x48: 0x83, 0x49: 0x59, 0x4a: 0x3c, 0x4b: 0x19, 0x4c: 0xe6, 0x4d: 0x85, 0x4e: 0x4f, 0x4f: 0xa8,

    0x50: 0x68, 0x51: 0x6b, 0x52: 0x81, 0x53: 0xb2, 0x54: 0x71, 0x55: 0x64, 0x56: 0xda, 0x57: 0x8b,
    0x58: 0xf8, 0x59: 0xeb, 0x5a: 0x0f, 0x5b: 0x4b, 0x5c: 0x70, 0x5d: 0x56, 0x5e: 0x9d, 0x5f: 0x35,

    0x60: 0x1e, 0x61: 0x24, 0x62: 0x0e, 0x63: 0x5e, 0x64: 0x63, 0x65: 0x58, 0x66: 0xd1, 0x67: 0xa2,
    0x68: 0x25, 0x69: 0x22, 0x6a: 0x7c, 0x6b: 0x3b, 0x6c: 0x01, 0x6d: 0x21, 0x6e: 0x78, 0x6f: 0x87,

    0x70: 0xd4, 0x71: 0x00, 0x72: 0x46, 0x73: 0x57, 0x74: 0x9f, 0x75: 0xd3, 0x76: 0x27, 0x77: 0x52,
    0x78: 0x4c, 0x79: 0x36, 0x7a: 0x02, 0x7b: 0xe7, 0x7c: 0xa0, 0x7d: 0xc4, 0x7e: 0xc8, 0x7f: 0x9e,

    0x80: 0xea, 0x81: 0xbf, 0x82: 0x8a, 0x83: 0xd2, 0x84: 0x40, 0x85: 0xc7, 0x86: 0x38, 0x87: 0xb5,
    0x88: 0xa3, 0x89: 0xf7, 0x8a: 0xf2, 0x8b: 0xce, 0x8c: 0xf9, 0x8d: 0x61, 0x8e: 0x15, 0x8f: 0xa1,

    0x90: 0xe0, 0x91: 0xae, 0x92: 0x5d, 0x93: 0xa4, 0x94: 0x9b, 0x95: 0x34, 0x96: 0x1a, 0x97: 0x55,
    0x98: 0xad, 0x99: 0x93, 0x9a: 0x32, 0x9b: 0x30, 0x9c: 0xf5, 0x9d: 0x8c, 0x9e: 0xb1, 0x9f: 0xe3,

    0xa0: 0x1d, 0xa1: 0xf6, 0xa2: 0xe2, 0xa3: 0x2e, 0xa4: 0x82, 0xa5: 0x66, 0xa6: 0xca, 0xa7: 0x60,
    0xa8: 0xc0, 0xa9: 0x29, 0xaa: 0x23, 0xab: 0xab, 0xac: 0x0d, 0xad: 0x53, 0xae: 0x4e, 0xaf: 0x6f,

    0xb0: 0xd5, 0xb1: 0xdb, 0xb2: 0x37, 0xb3: 0x45, 0xb4: 0xde, 0xb5: 0xfd, 0xb6: 0x8e, 0xb7: 0x2f,
    0xb8: 0x03, 0xb9: 0xff, 0xba: 0x6a, 0xbb: 0x72, 0xbc: 0x6d, 0xbd: 0x6c, 0xbe: 0x5b, 0xbf: 0x51,

    0xc0: 0x8d, 0xc1: 0x1b, 0xc2: 0xaf, 0xc3: 0x92, 0xc4: 0xbb, 0xc5: 0xdd, 0xc6: 0xbc, 0xc7: 0x7f,
    0xc8: 0x11, 0xc9: 0xd9, 0xca: 0x5c, 0xcb: 0x41, 0xcc: 0x1f, 0xcd: 0x10, 0xce: 0x5a, 0xcf: 0xd8,

    0xd0: 0x0a, 0xd1: 0xc1, 0xd2: 0x31, 0xd3: 0x88, 0xd4: 0xa5, 0xd5: 0xcd, 0xd6: 0x7b, 0xd7: 0xbd,
    0xd8: 0x2d, 0xd9: 0x74, 0xda: 0xd0, 0xdb: 0x12, 0xdc: 0xb8, 0xdd: 0xe5, 0xde: 0xb4, 0xdf: 0xb0,

    0xe0: 0x89, 0xe1: 0x69, 0xe2: 0x97, 0xe3: 0x4a, 0xe4: 0x0c, 0xe5: 0x96, 0xe6: 0x77, 0xe7: 0x7e,
    0xe8: 0x65, 0xe9: 0xb9, 0xea: 0xf1, 0xeb: 0x09, 0xec: 0xc5, 0xed: 0x6e, 0xee: 0xc6, 0xef: 0x84,

    0xf0: 0x18, 0xf1: 0xf0, 0xf2: 0x7d, 0xf3: 0xec, 0xf4: 0x3a, 0xf5: 0xdc, 0xf6: 0x4d, 0xf7: 0x20,
    0xf8: 0x79, 0xf9: 0xee, 0xfa: 0x5f, 0xfb: 0x3e, 0xfc: 0xd7, 0xfd: 0xcb, 0xfe: 0x39, 0xff: 0x48
}


def switch_box(int_src):
    """
       `int_src`  待置换数  1字节数据
    """
    # Python2 chr 0-255; Python3 chr unicode
    # Python2 SBox.get(chr);Python3 SBox.get(int)

    if isinstance(int_src, int):
        k = int_src
    elif isinstance(int_src, str):
        k = ord(int_src)  # Python2
    elif isinstance(int_src, bytes):
        k = bytes[0]
    else:
        raise ValueError("int_src should be one byte")
    return struct.pack("B", SBox.get(k))


def XOR(data1, data2, force_right=False):
    # type: (bytes, bytes, bool) -> bytes
    """字节序异或计算
    @param force_right 不足时是否右侧填充0x00
    """
    if force_right:
        while len(data1) != len(data2):
            data2 = b"\x00" + data2
        rdata = b""
        for i in range(len(data1)):
            if six.PY2:
                rdata += chr(ord(data1[i]) ^ ord(data2[i]))  # += win32 linux(python2) 较快于 ''.join
            elif six.PY3:
                rdata += bytes([data1[i] ^ data2[i]])  # += win32 linux(python2) 较快于 ''.join
            else:
                raise RuntimeError("Python version unknown")
    else:
        if len(data1) != len(data2):
            raise ValueError("Param1's Length != Param2's Length")
        rdata = b""
        for i in range(len(data1)):
            if six.PY2:
                rdata += chr(ord(data1[i]) ^ ord(data2[i]))
            elif six.PY3:
                rdata += bytes([data1[i] ^ data2[i]])
            else:
                raise RuntimeError("Python version unknown")
    return rdata


def segment(data, length, force=False):
    # type: (bytes, int, bool) -> list
    """将数据切割为 指定长度的段"""
    res = []
    assert length > 0
    if force:
        bk = int(len(data) / length)  # python2 int/int -> int; python3 int/int -> float
        for i in range(bk):
            res.append(data[i * length:(i + 1) * length])
    else:
        if len(data) % length != 0:
            raise ValueError("data's length is not an integer multiple of param %d" % length)
        bk = int(len(data) / length)
        for i in range(bk):
            res.append(data[i * length:(i + 1) * length])
    return res


def bi2bt(num):
    """将无符号整数转换为字节序"""
    MSBin = b''
    while num > 0:
        # if six.PY2:
        #     MSBin = chr(num % 256) + MSBin
        # elif six.PY3:
        MSBin = six.int2byte(num % 256) + MSBin
        num >>= 8
    return MSBin


def bt2bi(MSBin):
    # type:(bytes) -> int
    """将字节数转换为无符号整数"""
    num = 0
    for i in range(len(MSBin)):
        if six.PY2:
            num += ord(MSBin[i])
        elif six.PY3:
            num += MSBin[i]
        else:
            raise RuntimeError("Python version unknown")
        if i < (len(MSBin) - 1):  # 最后一次不能偏移
            num <<= 8
    return num


class SM4(object):
    ECB = 0x00
    CBC = 0x01

    FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)

    CK = (0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
          0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
          0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
          0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
          0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
          0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
          0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
          0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279)

    def __init__(self, key, mode=ECB, iv=None, pad=None, padmode='PAD_NORMAL'):
        if len(key) != 32:
            raise ValueError("32H")
        self.rk = self._create_key(unhexlify(key))
        self.rk_enc = self.rk
        self.rk_dec = self.rk[::-1]
        self.mode = mode
        self.iv = iv

    def _create_key(self, sm_key):
        """密钥扩展算法，用于生成轮密钥
            (K0,K1,K2,K3)=(MK0○+FK0,MK1○+FK1,MK2○+FK2,MK3○+FK3)
        """
        # 1
        MK = (sm_key[:4], sm_key[4:8], sm_key[8:12], sm_key[12:])
        # 2
        K = []
        for i in range(4):
            K.append(XOR(MK[i], bi2bt(SM4.FK[i]), True))
            # print("K[%s]" % hexs(K[i]))
        # 3
        rk = []
        for i in range(32):
            tmp = XOR(K[i + 1], K[i + 2])
            tmp = XOR(tmp, K[i + 3])
            tmp = XOR(tmp, bi2bt(SM4.CK[i]), True)

            K.append(XOR(K[i], self._funT1(tmp)))
            rk.append(K[i + 4])
        return rk

    @staticmethod
    def _offset(bit32, off):
        """循环向左偏移位 B<<< 2
        """
        # 将左侧 n位数据保留填充到后面  保持位长度不变
        new_bit32 = bt2bi(bit32)
        while off > 0:
            bit_0 = (new_bit32 >> 31) & 0xff  # 得到当前最高位
            new_bit32 = (new_bit32 << 1) & 0xffffffff  # 得到偏移后的值
            new_bit32 = new_bit32 + bit_0  # 最高位放在最低位
            new_bit32 = new_bit32 & 0xffffffff  # 得到结果
            off -= 1
        return bi2bt(new_bit32)

    def _funW(self, byte4):
        """非线性变换 τ function
            由4个盒子组成
        """
        return switch_box(byte4[0]) + switch_box(byte4[1]) + switch_box(byte4[2]) + switch_box(byte4[3])

    def _funL(self, byte4):
        """线性变换 L function
            B ⊕ (B<<< 2) ⊕ (B<<<10 ) ⊕ (B <<<18) ⊕(B<<<24)
            用于加解密
        """
        tmp = XOR(byte4, self._offset(byte4, 2), True)
        tmp = XOR(tmp, self._offset(byte4, 10), True)
        tmp = XOR(tmp, self._offset(byte4, 18), True)
        tmp = XOR(tmp, self._offset(byte4, 24), True)
        return tmp

    def _funT(self, data):
        """合成置换  T funciton
            T(.) = L(τ(.))
            用于加解密
        """
        return self._funL(self._funW(data))

    def _funL1(self, byte4):
        """线性变换 L' function
            L(B)=B○+(B<<<13)○+(B<<<23)
            用于轮密钥生成
            `byte4` 4字节数据
        """
        tmp = XOR(byte4, self._offset(byte4, 13), True)
        tmp = XOR(tmp, self._offset(byte4, 23), True)
        return tmp

    def _funT1(self, data):
        """合成置换  T' function
            T(.) = L'(τ(.))
            用于轮密钥生成
            `data`  4字节数据
        """
        return self._funL1(self._funW(data))

    def _crypt(self, block, rk):
        """加解密，不同之处在于轮密钥顺序
            `block` 16字节待加密数据块
        """
        sub_block = [block[:4], block[4:8], block[8:12], block[12:]]
        X = [] + sub_block
        for i in range(32):
            tmp = XOR(X[i + 1], X[i + 2])
            tmp = XOR(tmp, X[i + 3])
            tmp = XOR(tmp, rk[i])
            X.append(XOR(X[i], self._funT(tmp)))

        return X[35] + X[34] + X[33] + X[32]

    def encrypt(self, src_data):
        # type:(SM4, bytes) -> bytes
        """ SM4加密
            `src_data`  待加密数据 字节数据，长度如果不是16整数倍，填充\x00
        """
        des_data = b""
        if self.ECB == self.mode:
            for i in segment(src_data, 16):
                des_data += self._crypt(src_data, self.rk_enc)
        elif self.CBC == self.mode:
            for i in segment(src_data, 16):
                tmp = XOR(i, self.iv)
                tmp = self._crypt(tmp, self.rk_enc)
                self.iv = tmp
                des_data += tmp
        else:
            raise ValueError("mode only ECB or CBC support")
        return des_data

    def decrypt(self, src_data):
        # type:(SM4, bytes) -> bytes
        """
            SM4解密，将轮密钥反转，做计算
            `src_data`  待解密数据 字节数据，长度必须是16整数倍
        """
        des_data = b""
        if self.ECB == self.mode:
            for i in segment(src_data, 16):
                des_data += self._crypt(src_data, self.rk_dec)
        elif self.CBC == self.mode:
            for i in segment(src_data, 16):
                tmp = self._crypt(i, self.rk_dec)
                des_data += XOR(tmp, self.iv)
                self.iv = i
        else:
            raise ValueError("mode only ECB or CBC support")
        return des_data
