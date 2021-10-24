'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
Copyrigyt 2021 Thore Sommer
'''
# Keylime specific crypto and other utility functions.
# Some code is nearly the same as in Keylime which is Apache 2.0
import base64
import codecs
import hashlib
import hmac
import os
import string
from typing import Any, List, Optional

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from lernstick_bridge.config import config
from lernstick_bridge.schema.keylime import Payload

AES_BLOCK_SIZE = 16


def generate_payload(input_data: str) -> Payload:
    """
    Generates a payload from given input string
    :param input_data: input string
    :return: Payload object
    """
    k = generate_random_key(32)
    v = generate_random_key(32)
    u = _bitwise_xor(k, v)
    encrypted_data = _encrypt(input_data, k)
    return Payload(k=k, v=v, u=u, encrypted_data=encrypted_data, plain_data=input_data)


def get_random_nonce(length: int = 20) -> str:
    """
    Returns a random alphanumeric string. Default length is 20.
    :param length: Length of the nonce
    :return: A random string
    """
    valid_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return "".join([valid_chars[int(x) % len(valid_chars)] for x in generate_random_key(length)])


def do_hmac(key: bytes, value: str) -> str:
    """
    Generate an HMAC that is used by Keylime. It uses SHA384.

    :param key: key for HMAC
    :param value: the value for HMAC (should be a utf-8 encoded string)
    :return: the HMAC as hex string.
    """
    h_digest = hmac.new(key, msg=None, digestmod=hashlib.sha384)
    h_digest.update(value.encode("utf-8"))
    return h_digest.hexdigest()


def _bitwise_xor(a: bytes, b: bytes) -> bytes:
    """
    Bitwise XOR two byte arrays. a and b must be the same length!

    :param a: first byte array
    :param b: second byte array
    :return: bitwise a ^ b
    """
    assert len(a) == len(b)
    out = bytearray()
    for i, j in zip(bytearray(a), bytearray(b)):
        out.append(i ^ j)
    return out


def generate_random_key(length: int) -> bytes:
    """
    Generate random bytes. Uses urandom.

    :param length:  length of the byte array
    :return: random byte array of given length
    """
    return os.urandom(length)


def _encrypt(input_data: str, key: bytes) -> str:
    """
    Encrypts the input with the key using AES encryption.

    Note: This function is imported from Keylime

    :param input_data: to encrypt
    :param key: for encryption
    :return: Then encrypted input base64 encoded
    """
    iv = generate_random_key(AES_BLOCK_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(
        iv, None, None), backend=default_backend()).encryptor()
    encrypted_input = encryptor.update(input_data.encode("ascii")) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_input + encryptor.tag).decode("utf-8")  # type: ignore


def rsa_encrypt(key: Any, message: bytes) -> bytes:
    """
    Encrypts an message with a RSA key.
    Is used for the payload mechanism.

    Note: This function is imported from Keylime

    :param key: RSA key to encrypt with
    :param message: to encrypt
    :return: encrypted message
    """
    return key.encrypt(bytes(message),
                       cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                           mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                           algorithm=hashes.SHA1(),
                           label=None))


def generate_mask(used_pcrs: Optional[List[int]], measured_boot: bool = True, ima: bool = True) -> str:
    """
    Generates the mask needed for all the checked PCRs.

    :param used_pcrs: used PCRs by the static tpm policy
    :param measured_boot: enable PCRs for measured boot
    :param ima: enable PCR for IMA
    :return: mask for enabling that features
    """
    if used_pcrs is None:
        used_pcrs = []

    if measured_boot:
        used_pcrs += config.tenant.measuredboot_pcrs
    if ima:
        used_pcrs += config.tenant.ima_pcrs
    out = 0
    for i in set(used_pcrs):
        out = out | (1 << int(i))
    return hex(out)


def data_extend(data: bytes, hash_alg: Optional[str] = "sha256") \
        -> Optional[str]:
    """
    Calculates the PCR extend from a reset with the hash of data.

    :param data: the data that should used for simulate that PCR extend.
    :param hash_alg: the hash_alg that should be used. Only sha256 is currently implemented.
    :return: The Hash or None if the hash_alg is not implemented
    """
    if hash_alg == "sha256":
        start_hash = b"0" * (256 // 4)
        data_hash = hashlib.sha256(data).digest()
        return hashlib.sha256(codecs.decode(start_hash, "hex_codec") + data_hash).hexdigest()

    return None


def str_to_rsapubkey(key_str: Optional[str]) -> Optional[str]:
    """
    Convert a string to a RSA public key.

    :param key_str: the key as a string (PEM encoded)
    :return: RSA public key object
    """
    if key_str is None:
        return None
    return cryptography.hazmat.primitives.serialization.load_pem_public_key(key_str.encode("utf-8"))
