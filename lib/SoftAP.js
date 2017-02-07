'use strict';

var RSA = require('node-rsa');

var securityTable = {
	open: 0,
	none: 0,
	wep_psk: 1,
	wep_shared: 0x8001,
	wpa_tkip: 0x00200002,
	wpa_aes: 0x00200004,
	wpa2_aes: 0x00400004,
	wpa2_tkip: 0x00400002,
	wpa2_mixed: 0x00400006,
	wpa2: 0x00400006
};

function is(cb) {
	if (cb && typeof cb == 'function') {
		return true;
	}
	throw new Error('Invalid callback function provided.');
}

function SoftAP(options) {
	var opts = SoftAP.defaultOptions();
	SoftAP.assign(opts, options);

	this.keepAlive = opts.keepAlive;
	this.noDelay = opts.noDelay;
	this.timeout = opts.timeout;
	this.host = opts.host;
	this.port = opts.port;

	this.__publicKey = undefined;

	return this;
}

SoftAP.defaultOptions = function() {
	var opts = {
		host: '192.168.0.1',
		keepAlive: true,
		timeout: 8000,
		noDelay: true,
		channel: 6
	};

	return opts;
};

SoftAP.assign = function(opts, options) {
	if (options && typeof options == 'object') {
		Object.keys(options).forEach(function _loadOpts(key) {
			opts[key] = options[key];
		});
	}
};

function checkResponse(err, dat, cb) {
	if (err) {
		return cb(err);
	}
	if (!dat) {
		return cb(new Error('No data received'));
	}
	if (dat.r !== 0) {
		return cb(new Error('Received non-zero response code'));
	}
}

SoftAP.prototype.scan = function scan(cb) {
	is(cb);
	this.__sendCommand({ name: 'scan-ap' }, function response(err, json) {
		if (err) {
			return cb(err);
		}
		cb(null, json.scans);
	});
};

SoftAP.prototype.connect = function connect(index, cb) {
	if (!cb) {
		cb = index;
		index = 0;
	}
	is(cb);
	this.__sendCommand({ name: 'connect-ap', body: { idx: index } }, function response(err, dat) {
		checkResponse(err, dat, cb);
		cb();
	});
};

SoftAP.prototype.deviceInfo = function deviceInfo(cb) {
	is(cb);
	this.__sendCommand({ name: 'device-id' }, function response(err, dat) {
		if (err) {
			return cb(err);
		}

		var claimed = dat.c === '1';
		var id = dat.id && dat.id.toLowerCase();
		this.__deviceID = id;

		cb(null, {
			id : id,
			claimed : claimed
		});
	}.bind(this));
};

SoftAP.prototype.publicKey = function publicKey(cb) {
	is(cb);
	this.__sendCommand({ name: 'public-key' }, function response(err, dat) {
		checkResponse(err, dat, cb);
		var buff = new Buffer(dat.b, 'hex');
		this.__publicKey = new RSA(buff.slice(22), 'pkcs1-public-der', {
			encryptionScheme: 'pkcs1'
		});
		cb(null, this.__publicKey.exportKey('pkcs8-public'));
	}.bind(this));
};

SoftAP.prototype.setClaimCode = function setClaimCode(code, cb) {
	is(cb);
	if (!code || typeof code !== 'string') {
		throw new Error('Must provide claim code string as first parameter');
	}
	var claim = {
		k: 'cc',
		v: code
	};
	this.set(claim, cb);
};

SoftAP.prototype.set = function set(data, cb) {
	is(cb);
	this.__sendCommand({ name: 'set', body: data }, function response(err, dat) {
		checkResponse(err, dat, cb);
		cb();
	});
};

SoftAP.prototype.configure = function configure(opts, cb) {
	is(cb);

	var securePass = undefined;

	if (!this.__publicKey) {
		throw new Error('Must retrieve public key of device prior to AP configuration');
	}
	if (!opts || typeof opts !== 'object') {
		throw new Error('Missing configuration options object as first parameter');
	}
	if (!opts.ssid) {
		if (!opts.name) {
			throw new Error('Configuration options contain no ssid property');
		}
		opts.ssid = opts.name;
	}

	if ((opts.enc || opts.sec) && !opts.security) {
		opts.security = opts.sec || opts.enc;
	}
	if (!opts.security) {
		opts.security = 'open';
		opts.password = null;
	}
	if (opts.password || opts.pass) {
		if (!opts.security) {
			throw new Error('Password provided but no security type specified');
		}
		if (opts.pass && !opts.password) {
			opts.password = opts.pass;
		}
		securePass = this.__publicKey.encrypt(opts.password, 'hex');
	}
	if (typeof opts.security === 'string') {
		opts.security = securityTable[opts.security];
	}

	var apConfig = {
		idx: opts.index || 0,
		ssid: opts.ssid,
		sec: opts.security,
		ch: parseInt(opts.channel)
	};

	if (securePass) {
		apConfig.pwd = securePass;
	}

	this.__sendCommand({ name: 'configure-ap', body: apConfig }, cb);
};

SoftAP.prototype.__sendCommand = function __sendCommand(cmd, cb) {
	is(cb);
	if (typeof cmd == 'object') {
		if (!cmd.name) {
			throw new Error('Command object has no name property');
		}
	} else {
		throw new Error('Invalid command');
	}

	return this._sendProtocolCommand(cmd, cb);
};

SoftAP.prototype._sendProtocolCommand = function _sendProtocolCommand() {
	throw new Error('Implemented in protocol specific class');
};

SoftAP.prototype.version = function version(cb) {
	is(cb);
	this.__sendCommand({ name: 'version' }, cb);
};

SoftAP.prototype.securityLookup = function securityLookup(dec) {
	var match = null;
	Object.keys(securityTable).forEach(function securityType(key) {
		if (parseInt(dec) === securityTable[key]) {
			match = key;
		}
	});
	return match;
};

module.exports = SoftAP;
