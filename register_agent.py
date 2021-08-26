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
import tempfile

import yaml
import requests


BRIDGE_URL = "http://localhost:8080"
BOOT_LOG_PATH = "/sys/kernel/security/tpm0/binary_bios_measurements"

def get_ek_cert():
    # Currently we only try to get the EK certificate from NV storage (Keylime also only does that)
    # This might fail on some platforms where the certificate must be obtained via external methods.
    out = subprocess.run(["tpm2_nvreadpublic"], capture_output=True)
    entries = yaml.safe_load(out.stdout.decode())

    print(entries)

    if 0x1c00002 not in entries:
        exit("Couldn't find EK certificate in TPM NV")

    out = subprocess.run(["tpm2_nvread", "0x1c00002"], capture_output=True)

    return base64.b64encode(out.stdout)


def generate_uuid():
    # We just persist a ek handle to directly hash the byte structure and then free it again
    # The public key is the same as it is in the ek certificate
    (fd, ek_tpm) = tempfile.mkstemp()
    out = subprocess.run(["tpm2_createek", "-G", "rsa", "-u", ek_tpm, "-c", "-"], capture_output=True)
    handle = yaml.safe_load(out.stdout.decode())["persistent-handle"]
    subprocess.run(["tpm2_evictcontrol", "-c", hex(handle)], capture_output=True)
    with open(ek_tpm, 'rb') as f:
        uuid = hashlib.sha256(base64.b64encode(f.read())).hexdigest()
    return uuid


def get_pcrs():
    out = subprocess.run(["tpm2_pcrread"], capture_output=True)
    pcrs = yaml.safe_load(out.stdout.decode())["sha256"]
    return {
        "pcr_0": pcrs[0],
        "pcr_1": pcrs[1],
        "pcr_2": pcrs[2],
        "pcr_3": pcrs[3],
        "pcr_4": pcrs[4],
        "pcr_5": pcrs[5],
        "pcr_6": pcrs[6],
        "pcr_7": pcrs[7]
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
    data = {
        "agent_id": generate_uuid(),
        "ek_cert": get_ek_cert(),
        "event_log_reference": get_boot_log(),
        **get_pcrs()
    }
    res = requests.post(f"{url}/agents", json=data)
    if res.status_code == 200:
        print("Submitted data successfully")
    else:
        print(data)
        print(f"Submission failed with status code {res.status_code}")


if __name__ == "__main__":
    main()
