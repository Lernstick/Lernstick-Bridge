# Test Setup
This document describes on howto set up a test environment for the Lernstick Bridge. In this environment no state is 
permanently stored. For setting up Lernstick Bridge for production see  (TODO).

## Requirements
 * A server running recent versions of Docker and docker-compose (tested with Docker 20.10.8 and docker-compose 1.29.2) 
 * A device with a TPM, Secure Boot and Debian 11 installed
 * The device and server should be in the same network

## Setting up the CA
The Lernstick Bridge and Keylime are sharing a CA for authentication. Normally Keylime generates that on first startup,
but this doesn't work in our case. Please run: `./setup_ca.sh`.

This will create an folder `cv_ca` which contains the shared CA.

## Configuring the Bridge and Keylime
For Keylime the project ships with a pre-configured `keylime.conf.d` directory which shouldn't need any changes.
A development configuration for the Bridge can be found under `.docker_env` which works out of the box.

Depending on Bridge usage the following values might need some change:

* mode: Can be `relaxed` or `strict` which configures the Bridge in the according mode
* validate_ek_registration: Set `false` if you use a VM. **Only set to false during development!**
* revocation_webhook: Uncomment and set to the entrypoint where your system wants to receive revocation events.

## Starting the Bridge and Keylime
Just run `docker compose --env-file .env.example -f docker-compose-local.yml up --force-recreate --build`.

## Preparing the device
 * Ensure that the device has a TPM2.0
 * Download Debian 11 from: https://www.debian.org/download
 * Install Debian 11 on the device with Secure Boot enabled 
 * Install rust agent either from the Lernstick repos or using [cargo deb](https://github.com/keylime/rust-keylime/#building-debian-package-with-cargo-deb).
 * Copy `cv_ca/cacert.crt` Keylime CA certificate to the device to `/var/lib/keylime/cacert.crt`.

Changes to `/etc/keylime/agent.conf`:

 * `[agent]` section
   * `ip` change to `0.0.0.0`
   * `contact_ip` change to the devices IP address reachable by the Bridge. E.g. `192.168.0.1`.
   * `registrar_ip` change to IP where the Bridge is running
   * `uuid` change to `hash_ek`
   * `trusted_client_ca` change to `/var/lib/keylime/cacert.crt`
   * `tpm_hash_alg` change to `sha256`

Now restart the agent with `systemctl restart keylime_agent`.
If this fails make sure that the registrar is running and reachable from the device.

## Registering the agent for strict mode
For registering the agent at the Bridge for strict mode can be done with the `register_agent.py` script.
It collects all the necessary information and then submits it to the Bridge.
The script is only a reference implementation and normally the agents shouldn't submit their registration directly to
the Bridge.

Usage: `python3 register_agent.py "http://BRIDGE_IP:BRIDGE_PORT"`
