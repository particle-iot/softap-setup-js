var SoftAPSetup = require('../index');
var sap = new SoftAPSetup();

console.log("Requesting public key...");
sap.publicKey(scan);

function scan(err, dat) {

	if(err) { throw err; }
	console.log("Received public key. Scanning for APs...");
	sap.scan(configure);
}

function configure(err, dat) {

	if(err) { throw err; }
	console.log("Scanned APs. Configuring device...");
	console.log(dat);

	sap.configure({
		ssid: 'test'
		, channel: 11
		, password: 'testtest'
		, security: 'wpa2_mixed'
	}, connect);

};

function connect(err, dat) {

	if(err) { throw err; }
	console.log("Configured device. Issuing connect request...");

	sap.connect(done);
};

function done(err, dat) {

	if(err) { throw err; }
	console.log("Successfully sent connect request. Now wait for breathing cyan!");

};
