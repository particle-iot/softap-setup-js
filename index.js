module.exports = SoftAPSetup;

var net = require('net');
var util = require('util');
var config = require('./config');
var rsa = require('node-rsa');

// hashtag lazyJS
function is(cb) {

	if (cb && typeof cb == 'function') { return true }
	throw new Error('Invalid callback function provided.');
};

function SoftAPSetup(opts) {

	if(opts && typeof opts == 'object') {
		Object.keys(opts).forEach(function _loadOpts(key) {
			config.set(key, opts[key]);
		});
	}

	this.keepAlive = config.get('keep_alive');
	this.noDelay = config.get('no_delay');
	this.timeout = config.get('timeout');

	this.port = config.get('port');
	this.host = config.get('host');

	this.__publicKey = undefined;

};

SoftAPSetup.prototype.scan = function scan(cb) {

	is(cb);
	var sock = this.__sendCommand('scan-ap', cb);
	return sock;
};

SoftAPSetup.prototype.connect = function connect(cb) {

	is(cb);
	var sock = this.__sendCommand('connect-ap', cb);
	return sock;
};

SoftAPSetup.prototype.deviceInfo = function deviceInfo(cb) {

	is(cb);
	var sock = this.__sendCommand('device-id', response.bind(this));
	function response(err, dat) {

		if(err) { return cb(err); }

		var claimed = dat.c === '1' ? true : false;
		this.__deviceID = dat.id;

		cb(null, {
			id : dat.id,
			claimed : claimed
		});
	};
	return sock;
};

SoftAPSetup.prototype.publicKey = function publicKey(cb) {

	is(cb);
	var sock = this.__sendCommand('public-key', response.bind(this));
	function response(err, dat) {

		if(err) { return cb(err); }
		if(!dat) { return cb(new Error('No data received')); }
		if(dat.r !== 0) {
			return cb(new Error('Received non-zero response code'));
		}
		var buff = new Buffer(dat.b, 'hex');
		this.__publicKey = new rsa(buff.slice(22), 'pkcs1-public-der', {
			encryptionScheme: 'pkcs1'
		})
		cb(null, this.__publicKey.exportKey('pkcs8-public'));
	};
	return sock;
};

SoftAPSetup.prototype.setClaimCode = function(code, cb) {

	is(cb);
	if(!code || typeof code !== "string") {
		throw new Error('Must provide claim code string as first parameter');
	}

};

SoftAPSetup.prototype.configure = function configure(opts, cb) {

	is(cb);
	var securityTable = {
		"open": 0,
		"none": 0,
		"wep_psk": 1,
		"wep_shared": 0x8001,
		"wpa_tkip": 0x00200002,
		"wpa_aes": 0x00200004,
		"wpa2_aes": 0x00400004,
		"wpa2_tkip": 0x00400002,
		"wpa2_mixed": 0x00400006,
		"wpa2": 0x00400006
	};
	var securePass = undefined;

	if(!this.__publicKey) {
		throw new Error('Must retrieve public key of device prior to AP configuration');
	}
	if(!opts || typeof opts !== 'object') {
		throw new Error('Missing configuration options object as first parameter');
	}
	if(!opts.ssid) {
		if(!opts.name) {
			throw new Error('Configuration options contain no ssid property');
		}
		opts.ssid = opts.name;
	}

	if((opts.enc || opts.sec) && !opts.security) {
		opts.security = opts.sec || opts.enc;
	}
	if(!opts.security) {
		opts.security = "open";
		opts.password = null;
	}
	if(opts.password || opts.pass) {
		if(!opts.security) {
			throw new Error('Password provided but no security type specified');
		}
		if(opts.pass && !opts.password) {
			opts.password = opts.pass;
		}
		securePass = this.__publicKey.encrypt(opts.password, 'hex');
	}
	var apConfig = {
		idx: 0,
		ssid: opts.ssid,
		sec: securityTable[opts.security],
		ch: parseInt(opts.channel)
	};

	if(securePass) { apConfig.pwd = securePass; }

	var sock = this.__sendCommand({ name: 'configure-ap', body: apConfig }, cb);

	return sock;
};

SoftAPSetup.prototype.__getSocket = function __getSocket(connect, data, error) {

	var errorMessage = undefined;
	if(typeof connect !== 'function') {
		errorMessage = "Invalid connect function specified.";
	}
	if(typeof data !== 'function') {
		errorMessage = "Invalid data function specified.";
	}
	if(error && typeof error !== 'function') {
		errorMessage = "Provided error handler is not a function.";
	}
	if(errorMessage) { throw new Error(errorMessage); }

	var sock = net.createConnection(this.port, this.host);
	if(!error) { error = function(err) { console.log(err); } }

	sock.setTimeout(this.timeout);

	sock.on('data', data);
	if(error) { sock.on('error', error); }
	sock.on('connect', connect);

	return sock;
};

SoftAPSetup.prototype.__sendCommand = function(cmd, cb) {

	if(typeof cmd == 'string') {
		cmd = { name : cmd, body : undefined };
	}
	else if (typeof cmd == 'object') {
		if(!cmd.name) { throw new Error('Command object has no name property'); }
	}
	else { throw new Error('Invalid command'); }
	is(cb);

	var sock = this.__getSocket(connected, onData);
	function connected() {

		var send;
		if((cmd.body) && typeof cmd.body === 'object') {

			var body = JSON.stringify(cmd.body);
			var length = body.length;
			send = util.format("%s\n%s\n\n%s", cmd.name, length, body);
		}
		else {
			send = util.format("%s\n0\n\n", cmd.name);
		}
		console.log(send);
		sock.write(send);
	};
	function onData(dat) {

		try {
			var json = JSON.parse(dat.toString());
		}
		catch (e) {

			return cb(new Error('Invalid JSON received from device.'));
		}

		//TODO: Parse the return data, which really only needs to send the results, or error.
		cb(null, json);
	};

	return sock;
};

SoftAPSetup.prototype.version = function(cb) {

	is(cb);
	var sock = this.__sendCommand('version', cb);
	return sock;
};
