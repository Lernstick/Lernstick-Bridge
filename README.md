# Lernstick Keylime Bridge
The Lernstick Keylime Bridge provides a unified interface for interacting with the Keylime Registrar and Verifier.
It also provides device management and configuration of default values for Remote Attestation. 

## Modes
The bridge can operate in two different modes, depending on the use case.

### strict - Only allow known devices
In this mode devices must be manually activated at the bridge.
During activation the EK certificate of the TPM is checked against a known good one in the database and static PCR 
values are taken into account during verification.
After activation an identification token is deployed on the device. 
This can be optionally used for additional verification. 

Activated devices mus be removed by the exam system.
### relaxed - Verify devices only against TPM vendor EK certificate
In this mode the bridge tries to activate the device automatically. 
The only check that is done for this device is the validation of the TPMs EK against the Hardware Vendor CAs. 
An identification token is automatically deployed on the device which the agent can decrypt once the verifier confirmed
that the device is in a known good state.
If the exam system wants to use a device it must first find the identification token on that device and then retrieve
the device id from bridge. Then exam system activates that device for use at the bridge.

Non manually activated devices that are active in the bridge are automatically removed after a configured time period.
Manually activated devices must be removed by the exam system. 

If a device was deactivated the agent must be restarted in order to register with the registrar again. 
## Deployment
For creating a test environment see: [TEST_SETUP.md](TEST_SETUP.md)

## Configuration
Configuration is done using pydantic settings. The setting schema is specified in `lernstick_bridge/schema/config.py`. 
More information can be found here: https://pydantic-docs.helpmanual.io/usage/settings/

## API documentation
FastAPI automatically generates a Swagger documentation. 
It can be found when the Bridge is running under `IP:PORT/docs`.  

## Known design limitations
* We allow only one valid generic Configuration for Keylime at a time. 
  Allowing multiple configurations conflicts with idea of autoconfiguration.
* More granular reporting of the state of an agent is limited by the current capabilities of Keylime.
* The device id is mapped to the EK cert.
* The registrar, verifier and bridge need a route to conact the agent (Limitation of Keylime).