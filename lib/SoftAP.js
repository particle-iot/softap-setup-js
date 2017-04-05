'use strict';

var RSA = require('node-rsa');
var crypto = require('crypto');

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
	wpa2: 0x00400006,
	wpa_enterprise_aes: 0x02200004,
	wpa_enterprise_tkip: 0x02200002,
	wpa2_enterprise_aes: 0x02400004,
	wpa2_enterprise_tkip: 0x02400002,
	wpa2_enterprise_mixed: 0x02400006,
	wpa2_enterprise: 0x02400006,
	enterprise: 0x02000000
};

var eapTypeTable = {
	peap: 25,
	'peap/mschapv2': 25,
	'eap-tls': 13,
	tls: 13
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

SoftAP.defaultOptions = function defaultOptions() {
	var opts = {
		host: '192.168.0.1',
		keepAlive: true,
		timeout: 8000,
		noDelay: true,
		channel: 6
	};

	return opts;
};

SoftAP.assign = function assign(opts, options) {
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

SoftAP.prototype.aesEncrypt = function(data, kiv) {
	if (!kiv) {
		kiv = crypto.randomBytes(32);
	}
	var kivEncrypted = this.__publicKey.encrypt(kiv, 'hex');
	var cipher = crypto.createCipheriv('aes-128-cbc', kiv.slice(0, 16), kiv.slice(16, 32));
	var encrypted = cipher.update(data, 'utf8', 'hex');
	encrypted += cipher.final('hex');

	return {
		kiv: kivEncrypted,
		encrypted: encrypted
	};
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

	if (opts.security & securityTable.enterprise) {
		if (!opts.eap)
			throw new Error('Security is set to Enterprise, but no EAP type provided');
		if (typeof opts.eap === 'string') {
			opts.eap = eapTypeTable[opts.eap.toLowerCase()];
		}
		if (opts.eap === undefined) {
			throw new Error('Unknown EAP type provided');
		}
		if (opts.eap == eapTypeTable.peap) {
			// inner identity and password are mandatory
			opts.inner_identity = opts.inner_identity || opts.username;
			if (!opts.inner_identity || !opts.password) {
				throw new Error('PEAP credentials missing');
			}
			apConfig.ii = opts.inner_identity;
			// Password is set later on
		} else if (opts.eap == eapTypeTable.tls) {
			// client certificate and private key are mandatory
			if (!opts.private_key || !opts.client_certificate) {
				throw new Error('EAP-TLS credentials missing');
			}
			apConfig.crt = opts.client_certificate.trim() + '\r\n';
			var enc = this.aesEncrypt(opts.private_key.trim() + '\r\n');
			apConfig.key = enc.encrypted;
			apConfig.ek = enc.kiv;
		}
		apConfig.eap = opts.eap;
		if (opts.outer_identity) {
			apConfig.oi = opts.outer_identity;
		}
		opts.ca = opts.ca || opts.root_ca;
		if (opts.ca) {
			apConfig.ca = opts.ca.trim() + '\r\n';
		}
	}

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

SoftAP.prototype.securityValue = function(name) {
	return securityTable[name];
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

SoftAP.prototype.eapTypeValue = function(name) {
	return eapTypeTable[name];
};

module.exports = SoftAP;
