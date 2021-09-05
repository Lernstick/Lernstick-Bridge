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
import tpm2_pytss
import base64
import requests
import subprocess

from tempfile import NamedTemporaryFile
from typing import Any, Tuple, Optional

from lernstick_bridge.schema.keylime import Payload
from lernstick_bridge.keylime import util
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.utils import RetrySession


def do_quote(agent_url: str, aik: str) -> Tuple[bool, Optional[str]]:
    nonce = util.get_random_nonce()

    try:
        ret = RetrySession().get(f"{agent_url}/quotes/identity?nonce={nonce}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Getting the quote from the agent {agent_url} failed: {e}")
        return False, None

    results = ret.json()["results"]
    hash_alg = results["hash_alg"]
    quote = results["quote"]

    (tpm2b_pub, _) = tpm2_pytss.TPM2B_PUBLIC().unmarshal(base64.b64decode(aik))
    pem_aik = tpm2b_pub.to_pem()

    if quote[0] != "r":
        raise ValueError("Quote is invalid")

    quote = quote[1:]

    quote_vals = quote.split(":")
    if len(quote_vals) != 3:
        raise ValueError("Quote is invalid!")

    quote_val = zlib.decompress(base64.b64decode(quote_vals[0]))
    sig_val = zlib.decompress(base64.b64decode(quote_vals[1]))
    pcr_val = zlib.decompress(base64.b64decode(quote_vals[2]))

    quote_valid = _check_qoute(pem_aik, quote_val, sig_val, pcr_val, nonce, hash_alg)
    return quote_valid, results["pubkey"]


def _check_qoute(aik: bytes, quote_data: bytes, signature_data: bytes, pcr_data: bytes, nonce: str, hash_alg: str) -> bool:
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


def get_pubkey(agent_url: str) -> Optional[str]:
    try:
        res = RetrySession().get(f"{agent_url}/keys/pubkey")

        data = res.json()
        if "results" not in data or "pubkey" not in data["results"]:
            logger.error(f"Failed to get public key from agent {agent_url}")
            return None

        return cryptography.hazmat.primitives.serialization.load_pem_public_key(data["results"]["pubkey"].encode("utf-8"))
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to get public key from agent {agent_url}: {e}")
        return None


def post_payload_u(agent_id: str, agent_url: str, payload: Payload, key: Any = None) -> bool:
    """
    Posts the encrypted payload and the u key to the agent
    :param agent_id: The uuid of the agent
    :param agent_url: The url where we can contact the agent
    :param payload: The payload to post
    :param key: Public RSA key for encrypting the u key.
    :return: True if it was successful
    """
    auth_tag = util.do_hmac(payload.k, agent_id)
    if key is None:
        key = get_pubkey(agent_url)
    data = {'auth_tag': auth_tag,
            'encrypted_key': base64.b64encode(util.rsa_encrypt(key, payload.u)).decode("utf-8"),
            'payload': payload.encrypted_data}
    try:
        res = RetrySession().post(f"{agent_url}/keys/ukey", data=json.dumps(data))
    except requests.exceptions.RequestException as e:
        logger.error(f"Could post payload to agent {agent_id}: {e}")
        return False
    return res.status_code == 200
