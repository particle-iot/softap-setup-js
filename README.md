# softap-setup-js
Spark SoftAP Setup for JavaScript


## Installation

```
npm install softap-setup-js
```

## Configuration

Configuration options are specified in the following two ways:

1. Edit config/defaults.json
2. Provide environment variables
3. Options object in instantiation

### Configuration file

The file located at `config/defaults.json` contains the most common SoftAP settings.
If you wish to override these settings you can do so by editing this file directly,
or by using the environment variables listed below.

### Environment Variables

Defining either of the following environment variables will override defaults.json:

* SOFTAP_HOST (defaults to 192.168.0.1)
* SOFTAP_PORT (defaults to 5609)


###  Options object

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

### Connecting to an Access Point

Tell your device to connect to a given access point:

```
var sap = new SoftAPSetup();
sap.connect({
	ssid: "NAME-OF-NETWORK",
	security: "<TYPE OF SECURITY>"
})
```

### Security types

Valid security types are as follows:

1. "open" or "none" - no security
2. "wep_psk" - WEP pre-shared key
3. "wep_shared" - Open WEP
4. "wpa_tkip" — WPA with TKIP
5. "wpa_aes" — WPA with AES
6. "wpa2_tkip" - WPA2 with TKIP
7. "wpa2_aes" — WPA2 with AES
8. "wpa2" or "wpa2_mixed" — WPA2 AES & TKIP

