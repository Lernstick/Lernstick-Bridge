# Test Setup
This document describes on howto set up a test environment for the Lernstick Bridge. In this environment no state is 
permanently stored. For setting up Lernstick Bridge for production see  (TODO).

## Requirements
 * A server running Docker and docker-compose
 * A device with a TPM, Secure Boot and Debian 11 installed
 * The device and server should be in the same network

## Setting up the CA
The Lernstick Bridge and Keylime are sharing a CA for authentication. Normally Keylime generates that on first startup,
but this doesn't work in our case. Please run: `./setup_ca.sh`.

This will create an folder `cv_ca` which contains the shared CA.

## Configuring the Bridge and Keylime
For Keylime the project ships with a pre configured `keylime.conf` which shouldn't need any changes.
A development configuration for the Bridge can be found under `.docker_env` which works out of the box.

Depending on Bridge usage the following values might need some change:

* mode: Can be `relaxed` or `strict` which configures the Bridge in the according mode
* validate_ek_registration: Set `false` if you use a VM. **Only set to false during development!** 

## Starting the Bridge and Keylime
Just run `docker-compose -up`.

## Preparing the device
 * Ensure that the device has a TPM2.0
 * Download Debian 11 from: https://www.debian.org/download
 * Install Debian 11 on the device with Secure Boot enabled 
 * Install Keylime package from TODO

Changes to `/etc/keylime-agent.conf`:

 * `[cloud_agent]` section
   * `cloudagent_ip` change to `0.0.0.0`
   * `agent_contact_ip` change to the devices IP address reachable by the Bridge. E.g. `192.168.0.1`.
   * `registrar_ip` change to IP where the Bridge is running
   * `agent_uuid` change to `hash_ek`

Now restart the agent with `systemctl restart keylime_agent`.
If this fails make sure that the registrar is running and reachable from the device.

## Building the Keylime Debian Package
Note prebuild images can be found here: TODO

We need a current git build because we currently depend on features not included in the latest release.

* Get Debian packaging from: `https://github.com/utkarsh2102/python-keylime`
* Get the latest Keylime version: `https://github.com/keylime/keylime`
* Copy `debian` directory into `keylime` directory
* Install build dependencies TODO
* Create new version TODO
* Build package `dpk-buildpackage -uc -us`
* Upload