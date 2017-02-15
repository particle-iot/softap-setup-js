'use strict';

var SoftAPSetup = require('../index');
var config = require('./config');
var path = require('path');

var sap = new SoftAPSetup({ protocol: 'http', port: 80 });

if (!config.get('ssid')) {

	console.log('* Please specify the ssid of the AP with which you wish to connect your device...');
	console.log('Example: %s %s --ssid BestWiFiNetworkEver --password SuperSecretPassword --security wpa2_mixed', process.argv[0], path.relative(process.cwd(), __filename));
	process.exit(1);
}

console.log('Obtaining device information...');

sap.deviceInfo(claim);

function claim(err, dat) {
	if (err) {
		console.error('Error getting claim code', err);
		return;
	}
	console.log(dat);
	console.log('-------');
	console.log('Obtained device information. Setting claim code...');
	sap.setClaimCode('wat', key);
}

function key(err, dat) {

	if (err) {
		throw err;
	}
	console.log(dat);
	console.log('-------');
	console.log('Requesting public key...');
	sap.publicKey(scan);
}

function scan(err, dat) {

	if (err) {
		throw err;
	}
	console.log(dat);
	console.log('-------');
	console.log('Received public key. Scanning for APs...');
	sap.scan(configure);
}

function configure(err, dat) {

	if (err) {
		throw err;
	}
	console.log(dat);
	console.log('-------');
	console.log('Scanned APs. Configuring device...');

	sap.configure({
		ssid: config.get('ssid')
		, channel: config.get('channel') || 11
		, password: config.get('password') || undefined
		, security: config.get('security') || undefined
	}, connect);

}

function connect(err, dat) {

	if (err) {
		throw err;
	}
	console.log('Configured device. Issuing connect request...');

	sap.connect(done);
}

function done(err, dat) {

	if (err) {
		throw err;
	}
	console.log('Successfully sent connect request. Now wait for breathing cyan!');

}
