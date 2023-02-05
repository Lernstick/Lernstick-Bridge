'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer

Static configuration for the bridge
'''
# pylint: disable=too-few-public-methods

from datetime import timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, BaseSettings


class Tenant(BaseModel):
    """
    Configuration for the tenant part. (Which we reimplement with the bridge).
    """
    accept_tpm_hash_algs: List[str] = ["sha512", "sha384", "sha256", "sha1"]
    accept_tpm_encryption_algs: List[str] = ["ecc", "rsa"]
    accept_tpm_signing_algs: List[str] = ["ecschnorr", "rsassa"]
    ima_pcrs: List[int] = [10]
    data_pcr: int = 16  # Keylime uses by default the Debug PCR to bin data to a quote
    measuredboot_pcrs: List[int] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15] # TODO check if we actually need all
    relaxed_timeout: timedelta = timedelta(seconds=60)
    agent_mtls_cert: str
    agent_mtls_priv_key: str


class Verifier(BaseModel):
    """
    TLS configuration for the Keylime Verifier.
    """
    tls_cert: str  # certificate for client TLS auth
    tls_priv_key: str  # key for for client TLS auth
    ca_cert: str  # certificate of the verifier CA


class Registrar(BaseModel):
    """
    TLS configuration for the Keylime Registrar.
    """
    tls_cert: str  # certificate for client TLS auth
    tls_priv_key: str  # key for for client TLS auth
    ca_cert: str  # certificate of the registrar CA


class Config(BaseSettings):
    """
    General configuration of the bridge.
    """
    ip: IPv4Address = IPv4Address("127.0.0.1")
    port: int = 8080
    keylime_api_entrypoint: str = "v2.0"
    keylime_registrar: str = "https://localhost:8891"
    keylime_verifier: str = "https://localhost:8881"
    tpm_cert_store: Optional[Path] = None
    mode: str = "strict"  # TODO replace with Enum
    log_level: str = "info"
    # Validate EK Cert when a agent is registered. Only disable for debugging or if some devices dont have an EK cert
    validate_ek_registration: bool = True
    db_url: str = "sqlite:///./sql_app.db"
    revocation_webhook: Optional[str] = None
    revocation_websocket: bool = False
    retry_attempts: int = 4
    cors_origins: List[str] = []
    tenant: Tenant
    verifier: Verifier
    registrar: Registrar

    class Config:  # pylint: disable=missing-class-docstring
        env_file = ".env"
        env_file_encoding = "utf-8"
