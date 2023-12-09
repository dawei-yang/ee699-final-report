import hmac
from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac, sha1

# Auther: Smith, Nicholas
# https://nicholastsmith.wordpress.com/2016/11/15/wpa2-key-derivation-with-anaconda-python/

# Pseudo-random function for generation of
# the pairwise transient key (PTK)
# key:       The PMK
# A:         b'Pairwise key expansion'
# B:         The apMAC, clientMAC, aNonce, and sNonce concatenated
#           like mac1 mac2 nonce1 nonce2
#           such that mac1 < mac2 and nonce1 < nonce2
# return:    The ptk
def PRF(key, A, B):
    # Number of bytes in the PTK
    nByte = 64
    i = 0
    R = b''
    # Each iteration produces 160-bit value and 512 bits are required
    while(i <= ((nByte * 8 + 159) / 160)):
        hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
        R = R + hmacsha1.digest()
        print(R)
        i += 1
    return R[0:nByte]


def RunTest():
    # passphrase(PSK)
    psk = "guess1"
    # ssid
    ssid = "SKYVIPER_63A4DB"
    # ANonce 64 bytes
    aNonce = a2b_hex('bc96154204fd9ea863e4978768e7e84a2d824cba57e6b2f310b4fd6721feec42')
    # SNonce
    sNonce = a2b_hex("646635e1c66445d6e43d0e89a0846e17eecb1d0998dd30caafec898de3b713a6")
    # Authenticator MAC (AP)
    apMAC = a2b_hex("38014663a4db")
    # Station address: MAC of client
    clientMAC = a2b_hex("4e1a278fa1bc")
    # The first MIC (EAPOL 2)
    mic1 = "4e453e30a60aa8f1e70c48a83883b399"
    # The entire 802.1x frame of the second handshake message with the MIC field set to all zeros
    data2 = a2b_hex("0103007502010a00000000000000000001646635e1c66445d6e43d0e89a0846e17eecb1d0998 \
        dd30caafec898de3b713a60000000000000000000000000000000000000000000000000000000000000000000 \
                    00000000000000000000000000000001630140100000fac040100000fac040100000fac028000")

    # Concat
    A = b"Pairwise key expansion"
    B = min(apMAC, clientMAC) + max(apMAC, clientMAC) + min(aNonce, sNonce) + max(aNonce, sNonce)
    # print(f"B is {b2a_hex(B).decode().upper()[:-8]}")

    # Generate PMK
    pmk = pbkdf2_hmac('sha1', psk.encode('ascii'), ssid.encode('ascii'), 4096, 32)

    # Make the pairwise transient key (PTK)
    ptk = PRF(pmk, A, B)

    # Calculate MIC
    guess_MIC = hmac.new(ptk[0:16], data2, sha1).digest()
    #Take the first 128-bits of the 160-bit SHA1 hash
    micStr = b2a_hex(guess_MIC).decode().upper()[:-8]

    #Display the desired MIC1 and compare to target MIC1
    mic1Str = mic1.upper()
    print("desired mic:\t" + mic1Str)


    print("guessMICFull:\t" + b2a_hex(guess_MIC).decode().upper())
    print("actual mic:\t" + micStr)
    print('MATCH\n' if micStr == mic1Str else 'MISMATCH\n')

    return

RunTest()