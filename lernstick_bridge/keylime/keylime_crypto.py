'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
Copyrigyt 2021 Thore Sommer
'''

# Some code is nearly the same as in Keylime which is Apache 2.0
import base64
import hashlib
import hmac
import string
import os

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

from lernstick_bridge.schema.keylime import Payload

AES_BLOCK_SIZE = 16


def generate_payload(input: str):
    k = generate_random_key(32)
    v = generate_random_key(32)
    u = _bitwise_xor(k, v)
    encrypted_data = _encrypt(input, k)
    return Payload(k=k, v=v, u=u, encrypted_data=encrypted_data, plain_data=input)


def get_random_nonce(length=20):
    """
    Returns a random alphanumeric string. Default length is 20.
    :param length: Length of the nonce
    :return: A random string
    """
    valid_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return "".join([valid_chars[int(x) % len(valid_chars)] for x in generate_random_key(length)])


def do_hmac(key: bytes, value: str):
    h = hmac.new(key, msg=None, digestmod=hashlib.sha384)
    h.update(value.encode('utf-8'))
    return h.hexdigest()


def _bitwise_xor(a: bytes, b: bytes):
    assert (len(a) == len(b))
    out = bytearray()
    for i, j in zip(bytearray(a), bytearray(b)):
        out.append(i ^ j)
    return out


def generate_random_key(length: int):
    return os.urandom(length)


def _encrypt(input: str, key: bytes):
    """
    Encrypts the input with the key using AES encryption
    :param input: to encrypt
    :param key: for encryption
    :return: Then encrypted input base64 encoded
    """
    iv = generate_random_key(AES_BLOCK_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(
        iv), backend=default_backend()).encryptor()
    encrypted_input = encryptor.update(input.encode('ascii')) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_input + encryptor.tag)


def rsa_encrypt(key, message):
    """ RSA encrypt message  """
    return key.encrypt(bytes(message),
                       cryptography.hazmat.primitives.asymmetric.padding.OAEP(mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                                                                              algorithm=hashes.SHA1(),
                                                                              label=None))