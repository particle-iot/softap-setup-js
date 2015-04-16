# softap-setup-js
Spark SoftAP Setup for JavaScript


## Installation

```
npm install softap-setup
```

## Configuration

Configuration options are specified in the following three ways:

1. Defaults loaded from config/defaults.json
2. SOFTAP_* environment variables specified
3. Options object provided during instantiation


### Configuration File

The file located at `config/defaults.json` contains the most common SoftAP settings.
If you wish to override these settings, please see below for usage information on environment variables and the options object.


### Environment Variables

Defining either of the following environment variables will override defaults.json:

* SOFTAP_HOST (defaults to 192.168.0.1)
* SOFTAP_PORT (defaults to 5609)


###  Options Object

When instantiating a SoftAPSetup object, simply provide an options object with values for the keys you would like to override.

### Defaults

```
{
	"host": "192.168.0.1",
	"port": "5609",
	"keep_alive": true,
	"timeout": 10000,
	"no_delay": true
}
```

## Usage

### Obtaining Device Information

You may often find it necessary to query the ID and claim status of your device. This is accomplished with a single method: `deviceInfo`. This method takes a single argument, which should be a reference to a callback function with the standard Node.js callback signature (example below).

#### Example:
```js
var SoftAPSetup = require('softap-setup');
var sap = new SoftAPSetup();

sap.deviceInfo(callback);
function callback(err, dat) {
	if (err) { throw err; }
	console.log("Device ID: %s, claimed: %s", dat.id, dat.claimed ? "yes" : "no");
};
```
The above code will attempt to retrieve the device information from a device in SoftAP mode (assuming the system running this code is connected to a device in SoftAP mode), with the default configuration (192.168.0.1:5609). When the underlying request is successfully fulfilled, the callback is called with no error parameter (null), and a result object containing the `id` of the device as a string of hex, as well as the `claimed` status as a boolean value, like so:

```json
{ "id": "STRINGOFHEXREPRESENTINGYOURDEVICEIDHERE", "claimed": false }
```

### Connecting to an Access Point

While connected to the device in SoftAP mode, the following code snippet will store the provided details on the device, and cause it to attempt to connect to the AP you specify. If it is unsuccessful, it will return to 'listening' mode so you may reconnect to its SoftAP and try again.

#### Example
```js
var sap = new SoftAPSetup();
sap.connect({
	ssid: "<NETWORK NAME>",
	security: "<SECURITY TYPE (see below)>",
	password: "[PASSWORD]",
	channel: "<CHANNEL>"
}, callback);
```

### Wireless Security Types

Valid security types are as follows:

1. "open" or "none" - no security
2. "wep_psk" - WEP pre-shared key
3. "wep_shared" - Open WEP
4. "wpa_tkip" — WPA with TKIP
5. "wpa_aes" — WPA with AES
6. "wpa2_tkip" - WPA2 with TKIP
7. "wpa2_aes" — WPA2 with AES
8. "wpa2" or "wpa2_mixed" — WPA2 AES & TKIP


## Notes

### AP Password Security

It's worth noting that this library uses the public key of the device to encrypt any AP passwords that are specified when configuring and connecting. 

