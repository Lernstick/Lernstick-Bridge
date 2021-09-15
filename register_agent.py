#!/bin/env python3
'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer

Reference implementation for collecting the data from a agent to register them in strict mode
Needs tpm2-tools as a dependency
'''

import os
import subprocess

import base64
import hashlib
import sys
import yaml
import requests

from cryptography import x509
from cryptography.hazmat.primitives import serialization


BRIDGE_URL = "http://localhost:8080"
BOOT_LOG_PATH = "/sys/kernel/security/tpm0/binary_bios_measurements"

def get_ek_cert():
    # Currently we only try to get the EK certificate from NV storage (Keylime also only does that)
    # This might fail on some platforms where the certificate must be obtained via external methods.
    # We also assume currently that the EK certificate is DER encoded.
    out = subprocess.run(["tpm2_nvreadpublic"], capture_output=True)
    entries = yaml.safe_load(out.stdout.decode())

    if 0x1c00002 not in entries:
        exit("Couldn't find EK certificate in TPM NV")

    out = subprocess.run(["tpm2_nvread", "0x1c00002"], capture_output=True)

    return out.stdout


def generate_uuid(ek_cert):
    # With https://github.com/keylime/keylime/pull/743 the uuid is the EK pubkey im PEM hashed with sha256
    cert = x509.load_der_x509_certificate(ek_cert)
    pubkey_pem =cert.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(pubkey_pem).hexdigest()


def get_pcrs():
    out = subprocess.run(["tpm2_pcrread"], capture_output=True)
    pcrs = yaml.safe_load(out.stdout.decode())["sha256"]
    return {
        "pcr_0": hex(pcrs[0]),
        "pcr_1": hex(pcrs[1]),
        "pcr_2": hex(pcrs[2]),
        "pcr_3": hex(pcrs[3]),
        "pcr_4": hex(pcrs[4]),
        "pcr_5": hex(pcrs[5]),
        "pcr_6": hex(pcrs[6]),
        "pcr_7": hex(pcrs[7])
    }


def get_boot_log():
    with open(BOOT_LOG_PATH, 'rb') as log:
        return base64.b64encode(log.read()).decode()


def main():
    url = BRIDGE_URL
    if len(sys.argv) == 2:
        url = sys.argv[1]
    if os.getuid() != 0:
        exit("Script must be run as root!")
    ek_cert = get_ek_cert()
    data = {
        "agent_id": generate_uuid(ek_cert),
        "ek_cert": base64.b64encode(ek_cert),
        "event_log_reference": get_boot_log(),
        **get_pcrs()
    }
    res = requests.post(f"{url}/agents", json=data)
    if res.status_code == 200:
        print("Submitted data successfully")
        print(f'Agent id: {data["agent_id"]}')
    else:
        print(data)
        print(f"Submission failed with status code {res.status_code}")


if __name__ == "__main__":
    main()
