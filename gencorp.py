#!/usr/bin/python

# tool to generate corpus

import os
import binascii

curves = {
"secp192k1": (18, "FFFFFFFF FFFFFFFF FFFFFFFE 26F2FC17 0F69466A 74DEFD8C") ,
"secp192r1": (19, "FFFFFFFF FFFFFFFF FFFFFFFF 99DEF836 146BC9B1 B4D22830") ,
"secp224k1": (20, "00000000 00000000 00000000 0001DCE8 D2EC6184 CAF0A971 769FB1F6") ,
"secp224r1": (21, "FFFFFFFF FFFFFFFF FFFFFFFF FFFF16A2 E0B8F03E 13DD2945 5C5C2A3C") ,
"secp256k1": (22, "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364140") ,
"secp256r1": (23, "FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632550") ,
"secp384r1": (24, "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7634D81 F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52972") ,
"secp521r1": (25, "01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFA 51868783 BF2F966B 7FCC0148 F709A5D0 3BB5C9B8 899C47AE BB6FB71E 91386408") ,
"brainpoolP256r1": (26, "A9FB57DB A1EEA9BC 3E660A90 9D838D71 8C397AA3 B561A6F7 901E0E82 974856A6") ,
"brainpoolP384r1": (27, "8CB91E82 A3386D28 0F5D6F7E 50E641DF 152F7109 ED5456B3 1F166E6C AC0425A7 CF3AB6AF 6B7FC310 3B883202 E9046564") ,
"brainpoolP512r1": (28, "AADD9DB8 DBE9C48B 3FD4E6AE 33C9FC07 CB308DB3 B3C9D20E D6639CCA 70330870 553E5C41 4CA92619 41866119 7FAC1047 1DB1D381 085DDADD B5879682 9CA90068") ,
}

for c in curves:
    tlsid, order = curves[c]
    order = order.replace(" ","")

    #zero and identity
    f = open("corpus/"+c+"01", "wb")
    f.write(bytes([0, tlsid, 1, 0]))
    f.close()

    #double and triple
    f = open("corpus/"+c+"23", "wb")
    f.write(bytes([0, tlsid, 2, 3]))
    f.close()

    f = open("corpus/"+c+"random", "wb")
    f.write(bytes([0, tlsid]))
    f.write(bytes(os.urandom(len(order))))
    f.close()

    f = open("corpus/"+c+"minus", "wb")
    f.write(bytes([0, tlsid]))
    f.write(bytes((len(order)//2-1)*[0]))
    f.write(bytes([1]))
    f.write(binascii.unhexlify(order))
    f.close()
