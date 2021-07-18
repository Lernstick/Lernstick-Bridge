'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

# Static configuration for the bridge
from typing import List
from pathlib import Path
from pydantic import BaseSettings, BaseModel

class Tenant(BaseModel):
    accept_tpm_hash_algs: List[str] = ["sha512","sha384","sha256", "sha1"]
    accept_tpm_encryption_algs: List[str] = ["ecc", "rsa"]
    accept_tpm_signing_algs: List[str] = ["ecschnorr", "rsassa"]

class Verifier(BaseModel):
    tls_cert: str
    tls_priv_key: str

class Registrar(BaseModel):
    tls_cert: str
    tls_priv_key: str

class Config(BaseSettings):
    keylime_api_entrypoint: str = "v2"
    keylime_registrar: str = "https://localhost:8891"
    keylime_verifier: str = "https://localhost:8881"
    tpm_cert_store: Path = None
    tenant: Tenant = Tenant()
    verifier: Verifier
    registrar: Registrar

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'