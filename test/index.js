'use strict';

var SoftAPSetup = require('../index');
var SoftAPEmulator = require('softap-emulator-js');
var assert = require('assert');
// var domain = require('domain');
var RSA = require('node-rsa');
var net = require('net');

// function noop() { };
var TEST_KEY = '30818902818100a633b9fdee23da72b0d40c4669eaf8101f0157cb971d8d16a5f1a91379a0d59b48acc887b9d15dd103225a583461abfe8c6008bb03d74d58c3d50fecd89244cf4c42269808fe5646a2eaca7a8ee14ba0d1921bd4e3ebd47d7c9552b07fc93ad31d4543b927956b170a4c53f34886f45c48dcfbce18003cc99370bf61def099e90203010001';

var testConfig = { host: '127.0.0.1', port: 5609, timeout: 3000 };
var server;

describe('SoftAPSetup', function () {
	before(function (done) {
		var emu = new SoftAPEmulator();
		server = net.createServer(emu.server());
		server.listen(
			testConfig.port,
			testConfig.host, function () {
				done();
		});
	});

	describe('#deviceInfo', function() {
		it('Successfully retrieves device info', function(done) {
			var sap = new SoftAPSetup(testConfig);
			sap.deviceInfo(done);
		});

		it('Throws an error when given an invalid callback', function() {
			try {
				var sap = new SoftAPSetup(testConfig);
				sap.deviceInfo('callback');
			} catch (e) {
				assert.equal('Invalid callback function provided.', e.message);
			}
		});
	});

	describe('#scan', function() {
		it('Successfully retrieves AP list', function (done) {
			var sap = new SoftAPSetup(testConfig);
			sap.scan(done);
		});
	});

	describe('#publicKey', function() {
		it('Successfully retrieves what looks like a public key', function (done) {
			var sap = new SoftAPSetup(testConfig);
			sap.publicKey(done);
		});
	});

	describe('#configure', function() {
		var conf = {
			ssid : 'hi',
			security: 'wpa2',
			password: 'hi'
		};

		it('Throws an error when called before publicKey is obtained', function (done) {
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });
			try {
				sap.configure(conf, cb);
			} catch (e) {
				assert.equal('Must retrieve public key of device prior to AP configuration', e.message);
				done();
			}

			function cb() {
				done(new Error('Configure did not throw an error'));
			}
		});

		it('Successfully sends configuration details', function (done) {
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });

			sap.__publicKey = new RSA(new Buffer(TEST_KEY, 'hex'), 'pkcs1-public-der', {
				encryptionScheme: 'pkcs1'
			});

			sap.configure(conf, done);
		});
	});

	describe('#connect', function() {
		it('Successfully sends command to connect', function (done) {
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });
			sap.connect(done);
		});
	});
});
