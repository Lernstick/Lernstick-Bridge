# Measured Boot Support
The Lernstick Bridge supports measured boot by providing a custom test module for Keylime and a tool to extract the 
necessary information.

## Generating the policy
To generate a policy from a lernstick ISO run as root:
```
lernstick2policy.py /path/to/lernstick.iso > /path/to/policy.json
```

To use this policy point the mount in the `docker-compose.yaml` to the generated policy.


## Disabling Measured Boot
For testing on other platforms it can be useful to disable measured boot. 
This can be done by adding using a policy only containing `{}`.

# Known limitations
 * No device specific information is used. We will those collected values in strict mode once enough data is collected
 * Only one Lernstick Version at a time is supported. This is done intentionally to simplify the configuration and make
   the relaxed mode simpler to implement