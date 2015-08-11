var SoftAPSetup = require('../index');
var emulator = require('softap-emulator-js');
var assert = require('assert');
var domain = require('domain');
var mocha = require('mocha');
var rsa = require('node-rsa');
var net = require('net');

function noop() { };
const TEST_KEY = '30818902818100a633b9fdee23da72b0d40c4669eaf8101f0157cb971d8d16a5f1a91379a0d59b48acc887b9d15dd103225a583461abfe8c6008bb03d74d58c3d50fecd89244cf4c42269808fe5646a2eaca7a8ee14ba0d1921bd4e3ebd47d7c9552b07fc93ad31d4543b927956b170a4c53f34886f45c48dcfbce18003cc99370bf61def099e90203010001';

var testConfig = { host: '127.0.0.1', port: 5609 };
var server;
var test;

describe('SoftAPSetup', function () {

	before(function (done) {

		server = new emulator();
		test = net.createServer(server.server()).listen(
			testConfig.port,
			testConfig.host, function () {
				done();
		});
	});

	describe('#__getSocket', function () {

		it('Returns a net.Socket when called with parameters', function () {

			var sap = new SoftAPSetup(testConfig);
			var sock = sap.__getSocket(noop, noop, noop);

			assert(true, sock instanceof net.Socket);
			// sock.destroy();

		});

		it('Throws an invalid handler error with bad connect function', function() {

			try {

				var sap = new SoftAPSetup(testConfig);
				var sock = sap.__getSocket("connect", noop, noop);

			}
			catch(e) {

				assert.equal("Invalid connect function specified.", e.message);
			}

		});

		it('Throws an invalid handler error with bad data function', function() {

			try {

				var sap = new SoftAPSetup(testConfig);
				var sock = sap.__getSocket(noop, "data", noop);

			}
			catch(e) {

				assert.equal("Invalid data function specified.", e.message);
			}

		});

		it('Throws an invalid handler error with bad error function', function() {

			try {

				var sap = new SoftAPSetup(testConfig);
				var sock = sap.__getSocket(noop, noop, "error");

			}
			catch(e) {

				assert.equal("Provided error handler is not a function.", e.message);
			}

		});

		it('Throws an error when the default error handler is used', function (done) {

			var port = Math.floor(Math.random() * 64511 + 1024);
			var sap = new SoftAPSetup({
				host : '127.0.0.1',
				port: port,
				timeout: 1
			});
			var d = domain.create();
			var sock;
			d.run(function () {

				sock = sap.__getSocket(noop, noop);
			});
			d.on('error', function (err) {

				done();
				sock.destroy();
				d.dispose();
			});
		});
	});

	describe('#deviceInfo', function () {

		it('Successfully retrieves device info', function (done) {

			var sap = new SoftAPSetup(testConfig);
			var req = sap.deviceInfo(done);

		});

		it('Throws an error when given an invalid callback', function () {

			try {

				var sap = new SoftAPSetup(testConfig);
				var req = sap.deviceInfo("callback");
			}
			catch(e) {

				assert.equal('Invalid callback function provided.', e.message);
			}
		});
	});

	describe('#scan', function() {

		it('Successfully retrieves AP list', function (done) {

			var sap = new SoftAPSetup();
			sap.scan(list);
			function list(aps) {
				done();
			};

		});
	});

	describe('#_set', function() {

		it('Successfully sets a property', function (done) {

			var sap = new SoftAPSetup();
			sap._set();
			done();

		});
	});

	describe('#publicKey', function() {

		it('Successfully retrieves what looks like a public key', function (done) {

			var sap = new SoftAPSetup();
			sap.publicKey(function (err, dat) {
				done();
			});

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
			}
			catch (e) {

				assert.equal('Must retrieve public key of device prior to AP configuration', e.message);
				done();
			}
			function cb(err, dat) {

				done(new Error('Configure did not throw an error'));
			}
		});

		it('Successfully sends configuration details', function (done) {

			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });

			sap.__publicKey = new rsa(new Buffer(TEST_KEY, 'hex'), 'pkcs1-public-der', {
				encryptionScheme: 'pkcs1'
			});

			sap.configure(conf, function(err, dat) {
				done();
			});

		});
	});

	describe('#connect', function() {

		it('Successfully sends command to connect', function (done) {

			var sap = new SoftAPSetup({ host: '127.0.0.1', port: 5609 });
			sap.connect(function (err, dat) {

			});
			done();

		});
	});
});