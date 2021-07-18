# Lernstick Keylime Bridge
The Lernstick Keylime Bridge provides a unified interface for interacting with the Keylime Registrar and Verifier.
It also provides device management and configuration of default values for Remote Attestation. 

## Modes
The bridge can operate in two different modes, depending on the use case.

### Strict verification
In this mode devices must be in the database and registered at the Keylime Registrar,
before the device is activated for Remote Attestation by the user.
A token is deployed on the device. 
This token can be used to verify that a user actually belongs to a device.

The activated devices need to be manually removed by the bridge user.
### Automatic registration and verification
In this mode devices are automatically added to the Verifier if the TPM EK 
is signed by one of the known hardware vendors. 
Then a token is automatically released on the device. 
This token is then used to identify a device.
The user of the bridge needs to manually activate a device to signal 
interest in that device otherwise it will be removed from the Verifier automatically
after a specified time period.

The activated devices need to be manually removed by the bridge user.

## Design limitations
* We allow only one valid generic Configuration for Keylime at a time. 
  Allowing multiple configurations conflicts with idea of autoconfiguration. 
  