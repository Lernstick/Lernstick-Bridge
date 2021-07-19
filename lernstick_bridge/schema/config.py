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
    ima_pcrs: List[int] = [10]
    measuredboot_pcrs: List[int] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15] # TODO check if we actually need all

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
    mode: str = "strict"  # TODO replace with Enum
    validate_ek_registration: bool = True  # Validate EK Cert when a device is registered. Only disable for debugging or if some devices dont have an EK cert
    db_url: str = "sqlite:///./sql_app.db"
    tenant: Tenant = Tenant()
    verifier: Verifier
    registrar: Registrar

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'