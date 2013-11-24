from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from struct import pack
from struct import unpack

SYMMETRIC_KEY_SIZE = 32
ASYMMETRIC_KEY_SIZE = 1024
SHA_SCHEME = SHA

def pad(text, block_size):
    padlen = block_size - len(text) % block_size
    return text + pack('B', 0x80) + (block_size - len(text) % block_size - 1) * pack('B', 0)


def unpad(text):
    index = -1
    while unpack('B', text[index])[0] == 0:
        index -= 1
    return text[:index]


def symmetric_encrypt(text, key):
    if len(key) != SYMMETRIC_KEY_SIZE:
        raise Exception('Cannot symmetrically encrypt with wrong key size: ' + str(len(key)))
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(text, AES.block_size))

def symmetric_decrypt(ciphertext, key):
    if len(key) != SYMMETRIC_KEY_SIZE:
        raise Exception('Cannot symmetrically decrypt with the wrong key size: ' + str(len(key)))
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[AES.block_size:]))

def generate_symmetric_key():
    return Random.new().read(SYMMETRIC_KEY_SIZE)


# returns (N, e, d) where N is the RSA modulus, e is the encryption exponent, and d the decryption exponent
def generate_asymmetric_keypair():
    key = RSA.generate(ASYMMETRIC_KEY_SIZE)
    return key.key.n, key.key.e, key.key.d


# public_key is (N, e)
def asymmetric_encrypt(public_key, msg):
    key = RSA.construct(public_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(msg)

# private key is (N, e, d)
def asymmetric_decrypt(private_key, ciphertext):
    key = RSA.construct(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)


# private key is (N, e, d)
def asymmetric_sign(private_key, msg):
    key = RSA.construct(private_key)
    signature_scheme = PKCS1_PSS.new(key)
    h = SHA_SCHEME.new()
    h.update(msg)
    return signature_scheme.sign(h)

# public key is (N, e)
def asymmetric_verify(public_key, msg, signature):
    key = RSA.construct(public_key)
    signature_scheme = PKCS1_PSS.new(key)
    h = SHA_SCHEME.new()
    h.update(msg)
    return signature_scheme.verify(h, signature)