'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
Copyrigyt 2021 Thore Sommer
'''
# Keylime specific crypto and other utility functions.
# Some code is nearly the same as in Keylime which is Apache 2.0
import base64
import hashlib
import hmac
import os
import string
from typing import Any, Dict, Optional

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from lernstick_bridge.config import config
from lernstick_bridge.schema.keylime import Payload

AES_BLOCK_SIZE = 16


def generate_payload(input: str) -> Payload:
    """
    Generates a payload from given input string
    :param input: input string
    :return: Payload object
    """
    k = generate_random_key(32)
    v = generate_random_key(32)
    u = _bitwise_xor(k, v)
    encrypted_data = _encrypt(input, k)
    return Payload(k=k, v=v, u=u, encrypted_data=encrypted_data, plain_data=input)


def get_random_nonce(length: int = 20) -> str:
    """
    Returns a random alphanumeric string. Default length is 20.
    :param length: Length of the nonce
    :return: A random string
    """
    valid_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return "".join([valid_chars[int(x) % len(valid_chars)] for x in generate_random_key(length)])


def do_hmac(key: bytes, value: str) -> str:
    h = hmac.new(key, msg=None, digestmod=hashlib.sha384)
    h.update(value.encode('utf-8'))
    return h.hexdigest()


def _bitwise_xor(a: bytes, b: bytes) -> bytes:
    assert (len(a) == len(b))
    out = bytearray()
    for i, j in zip(bytearray(a), bytearray(b)):
        out.append(i ^ j)
    return out


def generate_random_key(length: int) -> bytes:
    return os.urandom(length)


def _encrypt(input: str, key: bytes) -> str:
    """
    Encrypts the input with the key using AES encryption
    :param input: to encrypt
    :param key: for encryption
    :return: Then encrypted input base64 encoded
    Note: This function is imported from Keylime
    """
    iv = generate_random_key(AES_BLOCK_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(
        iv, None, None), backend=default_backend()).encryptor()
    encrypted_input = encryptor.update(input.encode('ascii')) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_input + encryptor.tag).decode("utf-8")  # type: ignore


def rsa_encrypt(key: Any, message: bytes) -> bytes:
    """
    Encrypts an message with a RSA key.
    Is used for the payload mechanism.
    :param key: RSA key to encrypt with
    :param message: to encrypt
    :return: encrypted message
    Note: This function is imported from Keylime
    """
    return key.encrypt(bytes(message),
                       cryptography.hazmat.primitives.asymmetric.padding.OAEP(mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                                                                              algorithm=hashes.SHA1(),
                                                                              label=None))


def generate_mask(tpm_policy: Optional[Dict[int, Any]] = None, measured_boot: bool = True, ima: bool = True) -> str:
    """
    Generates the mask needed for all the checked pcrs
    :param tpm_policy: static tpm policy
    :param measured_boot: enable pcrs for measured boot
    :param ima: enable pcr for IMA
    :return: mask for enabling that features
    """
    if tpm_policy is None:
        tpm_policy = {}

    pcrs = list(tpm_policy.keys())
    if measured_boot:
        # TODO enabling this currently breaks something in Keylime
        pcrs += config.tenant.measuredboot_pcrs
    if ima:
        pcrs += config.tenant.ima_pcrs
    out = 0
    for i in set(pcrs):
        out = out | (1 << int(i))
    return hex(out)
