'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Thore Sommer
'''
# This module is Apache-2.0 licensed to make it easier to integrate this code into Keylime

import glob
import os
from pathlib import Path
from typing import Optional

from OpenSSL.crypto import (FILETYPE_ASN1, FILETYPE_PEM, Error, X509Store, X509StoreContext,
                            X509StoreContextError, load_certificate)


def validate_ek(ek_cert: bytes, cert_store: X509Store) -> bool:
    """
    Validates Edorsment Key Certificate against a Certificate store.

    :param ek_cert: The ek certficate DER encoded as bytes
    :param cert_store: X509Store to check against
    :return: True if valid
    """
    try:
        cert = load_certificate(FILETYPE_ASN1, ek_cert)
        ctx = X509StoreContext(certificate=cert, store=cert_store)
        ctx.verify_certificate()
        return True
    except (X509StoreContextError, Error):
        return False


def create_ca_store(path: Optional[Path]) -> X509Store:
    """
    Creates a X509 certificate store from given path.
    Openssl CAfile path only works with PEM certificates so we implement our own loading.

    :param path: string to the CA directory path
    :return: X509Store
    """
    cert_store = X509Store()
    if path is None:
        return cert_store
    filetypes = ["pem", "cer", "crt"]
    for ext in filetypes:
        for file in glob.glob(os.path.join(path, f"**/*.{ext}"), recursive=True):
            with open(file, "rb") as cert_file:
                data = cert_file.read()
                cert = None
                try:
                    cert = load_certificate(FILETYPE_PEM, data)
                except Error:
                    pass
                try:
                    cert = load_certificate(FILETYPE_ASN1, data)
                except Error:
                    pass
                if cert is not None:
                    cert_store.add_cert(cert)
    return cert_store
