'use strict';

require('should');
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
			sap.deviceInfo(function(err, dat) {
				if (err) {
					return done(err);
				}
				try {
					dat.should.have.property('id').be.a.String;
					dat.should.have.property('claimed').be.Boolean;
					done();
				} catch (e) {
					done(e);
				}
			});
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
			sap.scan(function(err, dat) {
				if (err) {
					return done(err);
				}
				try {
					dat.should.be.Array;
					dat.should.matchAny(function(scan) {
						scan.should.have.property('ssid').be.a.String;
						scan.should.have.property('sec').be.a.Number;
					});
					done();
				} catch (e) {
					done(e);
				}
			});
		});
	});

	describe('#publicKey', function() {
		it('Successfully retrieves what looks like a public key', function (done) {
			var sap = new SoftAPSetup(testConfig);
			sap.publicKey(function(err, key) {
				if (err) {
					return done(err);
				}
				try {
					key.should.be.a.String;
					key.should.startWith('-----BEGIN PUBLIC KEY-----\n');
					done();
				} catch (e) {
					done(e);
				}
			});
		});
	});

	describe('#setClaimCode', function() {
		it('Successfully sets a claim code', function (done) {
			var sap = new SoftAPSetup(testConfig);
			sap.setClaimCode('asdfasdf', done);
		});
	});

	describe('#configure', function() {
		var conf = {
			ssid : 'hi',
			security: 'wpa2',
			password: 'hi'
		};

		var confEnterprise = {
			ssid: 'ent',
			security: 'wpa2_enterprise'
		}

		it('Throws an error when called before publicKey is obtained', function (done) {
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });
			try {
				sap.configure(conf, function cb() {
					done(new Error('Configure did not throw an error'));
				});
			} catch (e) {
				assert.equal('Must retrieve public key of device prior to AP configuration', e.message);
				done();
			}
		});

		it('Successfully sends configuration details', function (done) {
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });

			sap.__publicKey = new RSA(new Buffer(TEST_KEY, 'hex'), 'pkcs1-public-der', {
				encryptionScheme: 'pkcs1'
			});

			sap.configure(conf, done);
		});

		it('Throws an error when security is set to Enterprise but no EAP type or wrong EAP type is provided', function(done) {
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });

			sap.__publicKey = new RSA(new Buffer(TEST_KEY, 'hex'), 'pkcs1-public-der', {
				encryptionScheme: 'pkcs1'
			});

			try {
				sap.configure(confEnterprise, function cb() {
					done(new Error('Configure did not throw an error'));
				});
			} catch (e) {
				assert.equal('Security is set to Enterprise, but no EAP type provided', e.message);
			}

			try {
				var c = Object.assign({}, confEnterprise);
				c.eap = 'leap';
				sap.configure(c, function cb() {
					done(new Error('Configure did not throw an error'));
				});
			} catch (e) {
				assert.equal('Unknown EAP type provided', e.message);
			}

			done();
		});

		it('Throws an error when EAP is set to PEAP and no PEAP credentials are provided', function(done) {
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });

			sap.__publicKey = new RSA(new Buffer(TEST_KEY, 'hex'), 'pkcs1-public-der', {
				encryptionScheme: 'pkcs1'
			});

			try {
				var c = Object.assign({}, confEnterprise);
				c.eap = 'peap';
				sap.configure(c, function cb() {
					done(new Error('Configure did not throw an error'));
				});
			} catch (e) {
				assert.equal('PEAP credentials missing', e.message);
			}

			done();
		});

		it('Throws an error when EAP is set to EAP-TLS and no EAP-TLS credentials are provided', function(done) {
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });

			sap.__publicKey = new RSA(new Buffer(TEST_KEY, 'hex'), 'pkcs1-public-der', {
				encryptionScheme: 'pkcs1'
			});

			try {
				var c = Object.assign({}, confEnterprise);
				c.eap = 'eap-tls';
				sap.configure(c, function cb() {
					done(new Error('Configure did not throw an error'));
				});
			} catch (e) {
				assert.equal('EAP-TLS credentials missing', e.message);
			}

			done();
		});

		it('Successfully sends PEAP configuration details', function(done){
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });

			sap.__publicKey = new RSA(new Buffer(TEST_KEY, 'hex'), 'pkcs1-public-der', {
				encryptionScheme: 'pkcs1'
			});

			var c = Object.assign({}, confEnterprise);
			c.eap = 'peap';
			c.username = 'username';
			c.password = 'password';
			c.outer_identity = 'anonymous';
			c.ca = 'TESTCACERTIFICATE';

			sap.configure(c, done);
		});

		it('Successfully sends EAP-TLS configuration details', function(done){
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });

			sap.__publicKey = new RSA(new Buffer(TEST_KEY, 'hex'), 'pkcs1-public-der', {
				encryptionScheme: 'pkcs1'
			});

			var c = Object.assign({}, confEnterprise);
			c.eap = 'eap-tls';
			c.private_key = 'TESTPRIVATEKEY';
			c.client_certificate = 'TESTCLIENTCERTIFICATE';
			c.outer_identity = 'anonymous';
			c.ca = 'TESTCACERTIFICATE';

			sap.configure(c, done);
		});
	});

	describe('#connect', function() {
		it('Successfully sends command to connect', function (done) {
			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });
			sap.connect(done);
		});
	});
});
