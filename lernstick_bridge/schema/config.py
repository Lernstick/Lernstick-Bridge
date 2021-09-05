'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

# Static configuration for the bridge
from typing import List, Optional
from pathlib import Path
from pydantic import BaseSettings, BaseModel
from datetime import timedelta
from ipaddress import IPv4Address


class Tenant(BaseModel):
    accept_tpm_hash_algs: List[str] = ["sha512","sha384","sha256", "sha1"]
    accept_tpm_encryption_algs: List[str] = ["ecc", "rsa"]
    accept_tpm_signing_algs: List[str] = ["ecschnorr", "rsassa"]
    ima_pcrs: List[int] = [10]
    measuredboot_pcrs: List[int] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15] # TODO check if we actually need all
    relaxed_timeout: timedelta = timedelta(seconds=60)


class Verifier(BaseModel):
    tls_cert: str  # certificate for client TLS auth
    tls_priv_key: str  # key for for client TLS auth
    tls_cert_server: str  # certificate of the verifier


class Registrar(BaseModel):
    tls_cert: str  # certificate for client TLS auth
    tls_priv_key: str  # key for for client TLS auth
    tls_cert_server: str  # certificate of the registrar


class Config(BaseSettings):
    ip: IPv4Address = IPv4Address("127.0.0.1")
    port: int = 8080
    keylime_api_entrypoint: str = "v1.0"
    keylime_registrar: str = "https://localhost:8891"
    keylime_verifier: str = "https://localhost:8881"
    tpm_cert_store: Optional[Path] = None
    mode: str = "strict"  # TODO replace with Enum
    validate_ek_registration: bool = True  # Validate EK Cert when a agent is registered. Only disable for debugging or if some devices dont have an EK cert
    db_url: str = "sqlite:///./sql_app.db"
    revocation_webhook: Optional[str] = None
    measured_boot_policy: Optional[str] = None  # Make sure that the keylime.conf includes the correct module to parse the policy
    retry_attempts: int = 4
    tenant: Tenant = Tenant()
    verifier: Verifier
    registrar: Registrar

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'