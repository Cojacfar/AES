#!/usr/bin/env python



Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3] 

def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def xtime(a,n=1):
    '''
    Described in 4.2.1 of NIST AES spec.
    Equal to multiplying by one 'x', so perform xtime multiple times to get values other than {02}
    such as {04}
    '''
    for i in range(n):
        a = (a << 1) % 256
        if a < 127:
            a = a ^ 27
    return a

def mix_columns(s):
    #NIST FIPS-197 5.1.3
    x = s
    for i in range(4):
        x[i][0] = xtime(s[i][0]) ^ xtime(s[i][1]) ^ s[i][2] ^ s[i][3]
        x[i][1] = s[i][0] ^ xtime(s[i][1]) ^ xtime(s[i][2]) ^ s[i][3]
        x[i][2] = s[i][0] ^ s[i][1] ^ xtime(s[i][2]) ^ xtime(s[i][3])
        x[i][3] = xtime(s[i][0]) ^ s[i][1] ^ s[i][2] ^ xtime(s[i][3])
    return x

def inv_mix_columns(s):
    #NIST FIPS-197 5.3.3
    x = s
    for i in range(4):
        x[i][0] = xtime(s[i][0],7) ^ xtime(s[i][1],5) ^ xtime(s[i][2],6) ^ xtime(s[i][3],4)
        x[i][1] = xtime(s[i][0],4) ^ xtime(s[i][1],7) ^ xtime(s[i][2],5) ^ xtime(s[i][3],6)
        x[i][2] = xtime(s[i][0],6) ^ xtime(s[i][1],4) ^ xtime(s[i][2],7) ^ xtime(s[i][3],5)
        x[i][3] = xtime(s[i][0],5) ^ xtime(s[i][1],6) ^ xtime(s[i][2],4) ^ xtime(s[i][3],7)
    return x

def addRoundKey(s,k):
    #Described in standard at 5.1.4, XOR each column with word from round key
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

def subByte(s):
    #Input is the state, substitutes using Sbox
    for i in range(4):
        for j in range(4):
            s[i][j] = Sbox[s[i][j]]

def inv_subByte(s):
    #Reverse of subByte
    for i in range(4):
        for j in range(4):
            s[i][j] = InvSbox[s[i][j]]

def rot(w):
    #Rotates a word
    w[0],w[1],w[2],w[3] = w[1],w[2],w[3],w[0]
    return w


def text_to_state(text):
    '''
    This function takes a 128-bit key and translates it into 
    a state matrix where each column is a 4-byte word

    Input is [a0,a1,a2,a3...]

    State looks like:
    [ a[0,0] a[0,1] a[0,2] a[0,3] 
      a[1,0] a[1,1] a[1,2] a[1,3]
      a[2,0] a[2,1] a[2,2] a[2,3]
      a[3,0] a[3,1] a[3,2] a[3,3] ]

    Where each a is 8 bits, and each column is a 4 byte word
    '''
    matrix = [ ]
    text = int(text.encode("hex"),16)
    for i in range(16):
        byte = text >> (8 * (15 - i)) & 255 #Shifts the text over to the right in mulitples of 8 bits
                                            #and ANDs with a bit-string of 8 1s(255) to return only the 8
                                            #rightmost bits
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i/4].append(byte)
    return matrix

def state_to_text(state):
    '''
    Reverses text_to_state to output either ciphertext or plain text as a string
    '''
    text = ''
    for column in state:
        for byte in column:
            text = text + hex(byte).decode("hex")
    return text


def KeyExpansion(key,nK = 4):
    '''
    Key expansion from NIST FIPS-197 5.2
    In the original pseudo-code, the key is moved to w, which consists of
    4-byte words. However, in Python binary is a bit of a bear (at least for me)
    so I will simply use the same set-up as the state array for the key. 
    This means each column would be equal to w in the pseudo-code provided
    and each value one byte, which is the smallest unit I need to manipulate
    '''
    nB = 4  #For 128-Bit nB = 4
    nR = 10 #For 128-Bit nR = 10
    w = text_to_state(key) 
    i = nK

    temp = w[i-1]
    while i < nB * (nR + 1):
        if i % nK == 0:
            temp = subByte(rot(temp)) #Rotate bytes, then perform subByte, then xor with Rcon (but only the first byte)
            temp[0] = temp[0] ^ Rcon(i/nK)
        for x in range(4):
            w[i][x] = w[i-nK][x] ^ temp[x]
        i += 1
    return w

def encrypt(text,key,nB = 4, nR = 10):
    '''
    This function takes the plaintext and key
    and encrypts
    '''
    state = text_to_state(text)

    w = KeyExpansion(key)

    addRoundKey(state, w[0, nB - 1])

    for i in range(9):
        subByte(state)
        shift_rows(state)
        mix_columns(state)
        addRoundKey(state, w[i*nB, (i + 1)*nB-1])

    subByte(state)
    shift_rows(state)
    addRoundKey(state,w[nR*nB, (nR+1)*nB-1])

    return state_to_text(state)

def decrypt(text,key,nB = 4, nR = 10):
    '''
    This function takes the ciphertext and key and returns the plaintext
    '''

    state = text_to_state(text)

    w = KeyExpansion(key)

    addRoundKey(state, w[nR * nB, (nR + 1)*nB-1])

    for i in range(1,10,-1):
        inv_shift_rows(state)
        inv_subByte(state)
        addRoundKey(state, w[i*nB, (i+1)*nB-1])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_subByte(state)
    addRoundKey(state,w[0, nB-1])

    return state_to_text(state)


    
#TESTING
plaintext = '00112233445566778899aabbccddeeff'.decode("hex")
KEY = '000102030405060708090a0b0c0d0e0f'.decode("hex")

#key schedule = '000102030405060708090a0b0c0d0e0f'
#state at start: '00102030405060708090a0b0c0d0e0f0'
#after sub_bytes = '63cab7040953d051cd60e0e7ba70e18c'
#after shift rows = '6353e08c0960e104cd70b751bacad0e7'
#after mix columns = '5f72641557f5bc92f7be3b291db9f91a'

