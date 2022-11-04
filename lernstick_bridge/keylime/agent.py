'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
Copyright 2021 Thore Sommer
'''
import base64
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any, Optional, Tuple

import requests
import tpm2_pytss
import yaml

from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.config import config
from lernstick_bridge.keylime import util
from lernstick_bridge.schema.keylime import Payload
from lernstick_bridge.utils import RetrySession

# Some parts of the parsing are very similar to the original Keylime implementation so this module is Apache 2.0 licenced
# and the copyright notice is added.


def do_quote(agent_url: str, ak: str, mtls_cert: str) -> Tuple[bool, Optional[str]]:  # pylint: disable=too-many-locals
    """
    Does an identity quote of an agent and validates it against the provided AK.

    :param agent_url: the contact URL of the agent
    :param ak: the AK for the agent. We assume that we trust that AK at this point.
    :param mtls_cert: mTLS certificate of the agent
    :return: A tuple (True, Transport Key) if validation was successful and (False, None) if not
    """
    nonce = util.get_random_nonce()

    try:
        with RetrySession(verify_cert=mtls_cert, cert=(config.tenant.agent_mtls_cert, config.tenant.agent_mtls_priv_key),
                          ignore_hostname=True) as session:
            ret = session.get(f"{agent_url}/quotes/identity?nonce={nonce}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Getting the quote from the agent {agent_url} failed: {e}")
        return False, None
    try:
        results = ret.json()["results"]
        hash_alg = results["hash_alg"]
        quote = results["quote"]
        pubkey = results["pubkey"]
    except KeyError as e:
        logger.error(f"Response from agent {agent_url} is missing data: {e}")
        return False, None

    (tpm2b_pub, _) = tpm2_pytss.TPM2B_PUBLIC().unmarshal(base64.b64decode(ak))
    pem_aik = tpm2b_pub.to_pem()

    if quote[0] != "r":
        logger.error(f"Quote form {agent_url} is invalid. Not prefixed with 'r'.")
        return False, None

    quote = quote[1:]

    quote_vals = quote.split(":")
    if len(quote_vals) != 3:
        logger.error(f"Quote form {agent_url} is invalid. Does not contain 3 values.")
        return False, None

    quote_val = base64.b64decode(quote_vals[0])
    sig_val = base64.b64decode(quote_vals[1])
    pcr_val = base64.b64decode(quote_vals[2])

    quote_valid, data_pcr_hash = _check_qoute(pem_aik, quote_val, sig_val, pcr_val, nonce, hash_alg)
    computed = util.data_extend(pubkey.encode("utf-8"), hash_alg)
    # tpm2-tools hash no leading zeros while hashlib has some we remove them from both
    if computed is None or data_pcr_hash is None or computed.lstrip("0") != data_pcr_hash.lstrip("0"):
        logger.error(f"data_pcr does not match hash.\n"
                     f"Got\t: {data_pcr_hash}\n"
                     f"Expected\t: {computed}")
        return False, None
    return quote_valid, pubkey


def _check_qoute(ak: bytes, quote_data: bytes, signature_data: bytes, pcr_data: bytes, nonce: str, hash_alg: str) \
        -> Tuple[bool, Optional[str]]:  # pylint: disable=too-many-arguments
    """
    Validates a quote using tpm2_checkquote.

    :param ak: AK PEM encoded
    :param quote_data: The TPM quote
    :param signature_data: The signature of the quote
    :param pcr_data: The values of the PCRs
    :param nonce: Send nonce
    :param hash_alg: Used hashing algorithm
    :return: True if valid
    """
    nonce = nonce.encode("utf-8").hex()
    with NamedTemporaryFile(prefix="lernstick-", ) as quote_file, \
            NamedTemporaryFile(prefix="lernstick-", ) as sig_file, \
            NamedTemporaryFile(prefix="lernstick-", ) as pcr_file, \
            NamedTemporaryFile(prefix="lernstick-", ) as ak_file:
        quote_file.write(quote_data)
        sig_file.write(signature_data)
        pcr_file.write(pcr_data)
        ak_file.write(ak)

        quote_file.seek(0)
        sig_file.seek(0)
        pcr_file.seek(0)
        ak_file.seek(0)

        ret = subprocess.run(  # pylint: disable=subprocess-run-check
            ["tpm2_checkquote",
             "-u", ak_file.name,
             "-m", quote_file.name,
             "-s", sig_file.name,
             "-f", pcr_file.name,
             "-g", hash_alg,
             "-q", nonce], capture_output=True)
        if ret.returncode != 0:
            logger.error(f"tpm2_checkquote failed with: {ret.stderr.decode('utf-8')}")
            return False, None

        data = yaml.safe_load(ret.stdout.decode())
        if data is None:
            logger.error(f"tpm2_checkquote output couldn't be parsed: {ret.stdout.decode()}")
            return False, None

        try:
            # [2:] removes the 0x prefix from the hex value
            return True, hex(data["pcrs"][hash_alg][config.tenant.data_pcr])[2:]
        except (KeyError, TypeError, ValueError) as e:
            logger.error(f"tpm2_checkquote didn't provided hash for data pcr: {e}")
            return False, None


def get_pubkey(agent_url: str) -> Optional[str]:
    """
    **Use with caution!**
    Get the transport key from the agent without any validation.
    For most cases use do_quote instead.

    :param agent_url: the agent contact URL
    :return: the transport key or None if something went wrong.
    """
    logger.warning(f"Getting public key from agent {agent_url} without quote validation.")
    try:
        res = RetrySession().get(f"{agent_url}/keys/pubkey")

        data = res.json()
        if "results" not in data or "pubkey" not in data["results"]:
            logger.error(f"Failed to get public key from agent {agent_url}")
            return None

        return util.str_to_rsapubkey(data["results"]["pubkey"])
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to get public key from agent {agent_url}: {e}")
        return None


def post_payload_u(agent_id: str, agent_url: str, payload: Payload, mtls_cert: str, key: Any = None) -> bool:
    """
    Posts the encrypted payload and the u key to the agent.

    :param agent_id: The UUID of the agent
    :param agent_url: The url where we can contact the agent
    :param payload: The payload to post
    :param mtls_cert: mTLS certificate of the agent
    :param key: Public RSA key for encrypting the u key.
    :return: True if it was successful
    """
    auth_tag = util.do_hmac(payload.k, agent_id)
    if key is None:
        logger.error(f"Transport key not provided not posting payload for agent: {agent_id}")
        return False
    data = {"auth_tag": auth_tag,
            "encrypted_key": base64.b64encode(util.rsa_encrypt(key, payload.u)).decode("utf-8"),
            "payload": payload.encrypted_data}
    try:
        with RetrySession(verify_cert=mtls_cert,
                          cert=(config.tenant.agent_mtls_cert, config.tenant.agent_mtls_priv_key),
                          ignore_hostname=True) as session:
            res = session.post(f"{agent_url}/keys/ukey", json=data)
    except requests.exceptions.RequestException as e:
        logger.error(f"Could post payload to agent {agent_id}: {e}")
        return False
    return res.status_code == 200
