# Hardware Vendor CAs for the TPMs
By default, we try to include as many as possible known good CAs for convenience.
Depending on the deployment you shouldn't trust us and retrieve the CAs directly from the TPM manufactures.

We imported our certificates mainly from ibmtss and Microsoft.
## CA sources
* [Microsoft](https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates)
* [Keylime](https://github.com/keylime/keylime/tree/master/tpm_cert_store)
* [ibmtss](https://github.com/kgoldman/ibmtss)
* [tpm2-tss](https://github.com/tpm2-software/tpm2-tss/blob/master/src/tss2-fapi/fapi_certificates.h)