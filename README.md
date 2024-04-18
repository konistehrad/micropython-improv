# micropython-improv
An implementation of the Bluetooth commissioning standard for Micropython. This encapsulates a whole network management solution, watching for WiFi disconnect, and automatically opening the Bluetooth commissioning path in the event that it is unable to reconnect.

TODO: Save WiFi credentials for reuse on restart.

## Usage
```
from improv import ImprovService
network_manager = ImprovService(["http://duckduckgo.com"], name="Improv")
network_manager.start_network_monitoring()
```

## Dependencies
Currently depends on the following MicroPython libraries:
- aioble
- logging


## Authors
The original implementation was done by [Mimoja
](https://github.com/Mimoja/pyImprov/) for Linux DBus. This implementation was extended and modified to support MicroPython.
