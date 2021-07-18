'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
Copyright 2021 Thore Sommer
'''
# Some parts of the parsing are very similar to the original Keylime implementation so this module is Apache 2.0 licenced
# and the copyright notice is added.
import json
import zlib

import cryptography.hazmat.primitives.serialization
import requests
import tpm2_pytss
import base64
import subprocess

from tempfile import NamedTemporaryFile

from lernstick_bridge.schema.keylime import Payload
from lernstick_bridge.keylime import keylime_crypto


def do_quote(agent_url: str, aik: str):
    nonce = keylime_crypto.get_random_nonce()  # TODO random 20 char pw
    ret = requests.get(f"{agent_url}/quotes/identity?nonce={nonce}")
    if ret.status_code != 200:
        # TODO
        return False

    results = ret.json()["results"]
    hash_alg = results["hash_alg"]
    quote = results["quote"]

    (tpm2b_pub, _) = tpm2_pytss.TPM2B_PUBLIC().unmarshal(base64.b64decode(aik))
    aik = tpm2b_pub.to_pem()

    if quote[0] != "r":
        raise ValueError("Quote is invalid")

    quote = quote[1:]

    quote_vals = quote.split(":")
    if len(quote_vals) != 3:
        raise ValueError("Quote is invalid!")

    quote_val = zlib.decompress(base64.b64decode(quote_vals[0]))
    sig_val = zlib.decompress(base64.b64decode(quote_vals[1]))
    pcr_val = zlib.decompress(base64.b64decode(quote_vals[2]))

    quote_valid = _check_qoute(aik, quote_val, sig_val, pcr_val, nonce, hash_alg)
    return quote_valid


def _check_qoute(aik: bytes, quote_data: bytes, signature_data: bytes, pcr_data: bytes, nonce: str, hash_alg: str):
    """
    Validates a quote using tpm2_checkqoute.
    :param aik: AIK PEM encoded
    :param quote_data: The TPM quote
    :param signature_data: The signature of the quote
    :param pcr_data:
    :param nonce: Send nonce
    :param hash_alg: Used hashing algorithm
    :return: True if valid
    """
    nonce = nonce.encode("utf-8").hex()
    with NamedTemporaryFile(prefix="lernstick-", ) as quote_file, \
            NamedTemporaryFile(prefix="lernstick-", ) as sig_file, \
            NamedTemporaryFile(prefix="lernstick-", ) as pcr_file, \
            NamedTemporaryFile(prefix="lernstick-", ) as aik_file:
        quote_file.write(quote_data)
        sig_file.write(signature_data)
        pcr_file.write(pcr_data)
        aik_file.write(aik)

        quote_file.seek(0)
        sig_file.seek(0)
        pcr_file.seek(0)
        aik_file.seek(0)

        ret = subprocess.run(
            ["tpm2_checkquote",
             "-u", aik_file.name,
             "-m", quote_file.name,
             "-s", sig_file.name,
             "-f", pcr_file.name,
             "-g", hash_alg,
             "-q", nonce], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return ret.returncode == 0


def get_pubkey(agent_url: str):
    res = requests.get(f"{agent_url}/keys/pubkey")
    if res.status_code != 200:
        return None

    data = res.json()
    if "results" not in data:
        return None
    return cryptography.hazmat.primitives.serialization.load_pem_public_key(data["results"]["pubkey"].encode("utf-8"))


def post_payload_u(agent_id, agent_url, payload: Payload):
    auth_tag = keylime_crypto.do_hmac(payload.k, agent_id)
    key = get_pubkey(agent_url)
    data = {'auth_tag': auth_tag,
            'encrypted_key': base64.b64encode(keylime_crypto.rsa_encrypt(key, payload.u)).decode("utf-8"),
            'payload': payload.encrypted_data}
    print(data)
    res = requests.post(f"{agent_url}/v2/keys/ukey", data=json.dumps(data))
    return res.status_code == 200
