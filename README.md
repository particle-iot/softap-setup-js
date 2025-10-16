# softap-setup-js
Particle SoftAP Setup for JavaScript — Perform wireless setup of Particle devices with Node.js or a browser.

See also [softap-setup-ts, a community-created Typescript port of the SoftAP Setup library](https://github.com/markterrill/softap-setup-ts).

## Installation

```
npm install softap-setup
```

## Configuration

When instantiating a SoftAPSetup object, simply provide an options object with values for the keys you would like to override.

### Defaults

```
{
	"host": "192.168.0.1",
	"keepAlive": true,
	"timeout": 2000,
	"noDelay": true,
	"channel": 6,
	"protocol": "tcp",
	"port": 5609 (will default to 80 if protocol = http and no port specified)
}
```

## Usage

### Protocols

This library supports both TCP and HTTP protocols for performing SoftAP setup. TCP is the default protocol. If you would like to use the HTTP protocol instead, simply override the `protocol` configuration parameter.

#### Example:
```js
var SoftAPSetup = require('softap-setup');
var sap = new SoftAPSetup({ protocol: 'http' });

sap.deviceInfo(callback);
function callback(err, dat) {
	if (err) { throw err; }
	console.log("Device ID: %s, claimed: %s", dat.id, dat.claimed ? "yes" : "no");
};
```
The above code will substitute the standard TCP port 5609 for HTTP on port 80. All methods function exactly the same regardless of chosen protocol. TCP is still the recommended protocol unless browser compatibility is specifically required.

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
The above code will attempt to retrieve the device information from the device (assuming the system running this code is connected to the device in SoftAP mode), with the default configuration (192.168.0.1:5609). When the underlying request is successfully fulfilled, the callback is called with no error parameter (null), and a result object containing the `id` of the device as a string of hex, as well as the `claimed` status as a boolean value, like so:

```json
{ "id": "STRINGOFHEXREPRESENTINGYOURDEVICEIDHERE", "claimed": false }
```

### Obtaining the Device's Public Key

The public key must be obtained from the device before it can be successfully configured. This is due to the fact that the public key is used to encrypt the passphrase for any AP that is configured to use security (see below). If you do not already know the public key of the device, you may request it from the device with the following command:

#### Example
```js
var sap = new SoftAPSetup();
sap.publicKey(callback);
function callback(err, dat) {
	if (err) { throw err; }
	console.log(dat);
};
```

### Setting the Device's Claim Code

The device must be provided with a claim code before it can be registered to a user's account. This is a string that is typically provided by a call to the [Particle API](https://docs.particle.io/reference/api/#create-a-claim-code). Once such a claim code has been obtained, it can be provided to the device like so:

#### Example
```js
var code = "somekindaclaimcode";
var sap = newSoftAPSetup();
sap.setClaimCode(code, callback);
function callback(err, dat) {
	if(err) { throw err; }
	console.log(dat);
};
```

### Scanning for Nearby Access Points

While connected to the device in SoftAP mode, it is possible to request a list of access points that have been detected in the area. This is done by way of the `scan` command. This command is one of the few commands that will typically take more than a few hundred milliseconds to complete. When executed, the device will listen for access points which are broadcasting their SSID. Important to note here is that it's not possible to detect networks which don't broadcast their SSID. You can still configure a non-broadcast network manually (see below).

#### Example

```js
var sap = new SoftAPSetup();
sap.scan(callback);
function callback(err, dat) {
	if(err) { throw err; }
	console.log("Networks Identified:");
	console.log(dat);
};
```

### Configuring the Device for a Selected Access Point

The following code snippet will store the provided details on the device, and cause it to attempt to connect to the AP you specify. If it is unsuccessful; it will return to SoftAP mode shortly thereafter, so you may reconnect to it and try again.

#### Example
```js
var sap = new SoftAPSetup();
sap.configure({
	ssid: "<NETWORK NAME>",
	security: "<SECURITY TYPE (see below)>",
	password: "[PASSWORD]",
	channel: "<CHANNEL>"
}, callback);
```

#### Example: WPA Enterprise with PEAP/MSCHAPv2 authentication
```js
var sap = new SoftAPSetup();
sap.configure({
    ssid: "<NETWORK NAME>",
    security: "<SECURITY TYPE (see below)>",
    username: "[USERNAME]",
    password: "[PASSWORD]",
    outer_identity: "[OUTER IDENTITY (optional)]",
    ca: "[CA CERTIFICATE (in PEM format, optional)]",
    channel: "<CHANNEL>"
}, callback);
```

#### Example: WPA Enterprise with EAP-TLS authentication
```js
var sap = new SoftAPSetup();
sap.configure({
    ssid: "<NETWORK NAME>",
    security: "<SECURITY TYPE (see below)>",
    client_certificate: "[CLIENT CERTIFICATE (in PEM format)]",
    private_key: "[PRIVATE KEY (in PEM format)]",
    outer_identity: "[OUTER IDENTITY (optional)]",
    ca: "[CA CERTIFICATE (in PEM format, optional)]",
    channel: "<CHANNEL>"
}, callback);
```

### Connecting to a Previously Configured Access Point

Once you have successfully issued a `configure` command, it's now only a matter of giving the device the go-ahead to actually connect. As you may have guessed, this is done via the `connect` command. It takes only a callback parameter, and will always execute "successfully". Since there is no way to verify that the provided configuration is correct until a connection attempt is made; you will need to verify that the device is able to successfully connect to the cloud (most likely via an API request to the cloud to check for the presence of the device ID that was just configured).

#### Example
```js
var sap = new SoftAPSetup();
sap.connect(callback);
function callback(err, dat) {
	console.log("Device is attempting to connect to the AP...");
};
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
8. "wpa2_mixed" — WPA2 AES & TKIP
9. "wpa_enterprise_aes" — WPA Enterprise with AES
10. "wpa_enterprise_tkip" — WPA Enterprise with TKIP
11. "wpa2_enterprise_aes" — WPA2 Enterprise with AES
12. "wpa2_enterprise_tkip" — WPA2 Enterprise with TKIP
13. "wpa2_enterprise_mixed" — WPA2 Enterprise with AES/TKIP
14. "wpa2_enterprise" — WPA2 Enterprise with AES/TKIP

## Notes

### AP Password Security

It's worth noting that this library uses the public key of the device to encrypt any AP passwords that are sent when configuring and connecting your device.

### EAP-TLS Private Key Security

This library also uses the public key of the device and a random AES encryption key to encrypt the Private Key when configuring your device to connect to WPA Enterprise access point with EAP-TLS authentication.

## Running in the Browser

It's possible to do SoftAP configuration from within a web browser. However, you must first convert the SoftAP code (and all of it's dependencies) from a Node.js module into a single javascript file.

### Browserify

Install browserify:
```js
npm install -g browserify
```
From the softap-setup-js code directory, run:
```js
browserify lib/browser.js -s SoftAPSetup -o softap-browser.js
```
This will create a browser-friendly ```softap-browser.js``` file that exports the ```SoftAPSetup``` object. The only difference with the browser version of this object is that it does *NOT* support reading the configuration from a file. All other methods described above will work.

**NOTE:** *Only the "http" protocol works in the browser. "tcp" will fail because the browser does not allow direct access to sockets.*

#### Example:
```js
<!doctype html>
<html lang="en">
<head></head>
<body>
  <script src="softap-browser.js"></script>
  <script> 
    var sap = new SoftAPSetup();

    sap.deviceInfo(callback);
    function callback(err, dat) {
	    if (err) { throw err; }
	    console.log("Device ID: %s, claimed: %s", dat.id, dat.claimed ? "yes" : "no");
    };
  </script>
 </body>
 </html>
```
The above code will print the device info to the javascript console of the browser.
