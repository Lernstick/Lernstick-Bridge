'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Thore Sommer
'''
# This module is Apache-2.0 licensed to make it easier to integrate this code into Keylime

import glob
import os
from pathlib import Path

from OpenSSL.crypto import X509Store, \
    X509StoreContext, \
    X509StoreContextError, \
    load_certificate, \
    FILETYPE_PEM, FILETYPE_ASN1


def validate_ek(ek_cert: bytes, cert_store: X509Store):
    """
    Validates Edorsment Key Certificate against a Certificate store
    :param ek_cert: The ek certficate DER encoded as bytes
    :param cert_store: X509Store to check against
    :return: True if valid
    """
    cert = load_certificate(FILETYPE_ASN1, ek_cert)
    ctx = X509StoreContext(certificate=cert, store=cert_store)
    try:
        ctx.verify_certificate()
        return True
    except X509StoreContextError:
        return False


def create_ca_store(path: Path) -> X509Store:
    """
    Creates a X509 certificate store from given path.
    Openssl CAfile path only works with PEM certificates so we implement our own loading.
    :param path: string to the CA directory path
    :return: X509Store
    """
    cert_store = X509Store()
    if path is None:
        return cert_store
    for file in glob.glob(os.path.join(path, "**/*.pem"), recursive=True):
        with open(file, 'rb') as f:
            cert = load_certificate(FILETYPE_PEM, f.read())
            cert_store.add_cert(cert)
    for file in glob.glob(os.path.join(path, "**/*.cer"), recursive=True):
        with open(file, 'rb') as f:
            cert = load_certificate(FILETYPE_ASN1, f.read())
            cert_store.add_cert(cert)
    for file in glob.glob(os.path.join(path, "**/*.crt"), recursive=True):
        with open(file, 'rb') as f:
            cert = load_certificate(FILETYPE_ASN1, f.read())
            cert_store.add_cert(cert)

    return cert_store
