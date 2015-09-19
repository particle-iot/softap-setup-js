module.exports = SoftAP;

var net = require('net');
var util = require('util');
var http = require('http');
var rsa = require('node-rsa');

var defaults = {
	host: "192.168.0.1",
	keep_alive: true,
	timeout: 2000,
	no_delay: true,
	default_channel: 6,
	default_protocol: "http",
	available_protocols: {
		tcp: {
			port: "5609"
		},
		http: {
			port: "80"
		}
	}
};	
var config = defaults;


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

// hashtag lazyJS
function is(cb) {

	if (cb && typeof cb == 'function') { return true }
	throw new Error('Invalid callback function provided.');
};

function SoftAP(opts) {

	if(opts && typeof opts == 'object') {
		Object.keys(opts).forEach(function _loadOpts(key) {
			config[key] = opts[key];
		});
	}

	this.protocol = config['protocol'];
	this.keepAlive = config['keep_alive'];
	this.noDelay = config['no_delay'];
	this.timeout = config['timeout'];

	this.host = config['host'];
	this.port = config['port'];

	if(!this.protocol) {
		this.protocol = config['default_protocol'];
	}
	if(!this.port) {
		this.port = defaults.available_protocols[this.protocol].port;
	}

	this.__publicKey = undefined;

	return this;
};

SoftAP.prototype.scan = function scan(cb) {

	is(cb);
	var sock = this.__sendCommand('scan-ap', cb);
	return sock;
};

SoftAP.prototype.connect = function connect(cb) {

	is(cb);
	var sock = this.__sendCommand({ name: 'connect-ap', body: { idx: 0 } }, cb);
	return sock;
};

SoftAP.prototype.deviceInfo = function deviceInfo(cb) {

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

SoftAP.prototype.publicKey = function publicKey(cb) {

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

SoftAP.prototype.setClaimCode = function(code, cb) {

	is(cb);
	if(!code || typeof code !== "string") {
		throw new Error('Must provide claim code string as first parameter');
	}
	var claim = {
		k: "cc"
		, v: code
	};
	var sock = this.__sendCommand({ name: 'set', body: claim }, cb);

	return sock;
};

SoftAP.prototype.configure = function configure(opts, cb) {

	is(cb);

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
	if(typeof opts.security === "string") {
		opts.security = securityTable[opts.security];
	}

	var apConfig = {
		idx: 0,
		ssid: opts.ssid,
		sec: opts.security,
		ch: parseInt(opts.channel)
	};

	if(securePass) { apConfig.pwd = securePass; }

	var sock = this.__sendCommand({ name: 'configure-ap', body: apConfig }, cb);

	return sock;
};

SoftAP.prototype.__getSocket = function __getSocket(connect, data, error) {

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

	sock.setTimeout(this.timeout);

	sock.on('data', data);
	if(error) { sock.on('error', error); }
	sock.on('connect', connect);

	return sock;
};

SoftAP.prototype.__httpRequest = function __httpRequest(cmd, data, error) {

	var sock;
	var payload;
	var errorMessage = undefined;

	if(!cmd || typeof cmd !== "object") {
		errorMessage = "Invalid command object specified.";
	}
	if(errorMessage) { throw new Error(errorMessage); }

	var opts = {
		method: 'GET',
		path: '/' + cmd.name,
		hostname: this.host,
		port: this.port
	};

	if((cmd.body) && typeof cmd.body === 'object') {
		payload = JSON.stringify(cmd.body);
		opts.headers = { 'Content-Length': payload.length };
		opts.method = 'POST';
	}

	sock = http.request(opts, function responseHandler(res) {
		var results = '';
		res.on('data', function dataHandler(chunk) {
			if(chunk) { results += chunk.toString(); }
		});
		res.on('end', function () {
			data(results);
		});
	});

	sock.on('error', error);
	payload && sock.write(payload);
	sock.end();

	return sock;
};

SoftAP.prototype.__sendCommand = function(cmd, cb) {

	var sock;
	var protocol = this.protocol;

	if(typeof cmd == 'string') {
		cmd = { name : cmd, body : undefined };
	}
	else if (typeof cmd == 'object') {
		if(!cmd.name) { throw new Error('Command object has no name property'); }
	}
	else { throw new Error('Invalid command'); }
	is(cb);

	if(protocol == "http") {
		sock = this.__httpRequest(cmd, onData, cb);
	}
	else {
		sock = this.__getSocket(tcpConnected, onData);
	}

	function tcpConnected() {

		if((cmd.body) && typeof cmd.body === 'object') {

			var body = JSON.stringify(cmd.body);
			var length = body.length;
			send = util.format("%s\n%s\n\n%s", cmd.name, length, body);
		}
		else {

			send = util.format("%s\n0\n\n", cmd.name);
		}

		sock.write(send);
	};

	function onData(dat) {
		if(dat instanceof Buffer || typeof dat === 'string') {
			try {
				var json = JSON.parse(dat.toString());
			}
			catch (e) {
				return cb(new Error('Invalid JSON received from device.'));
			}
		}
		else if(typeof dat === 'object') {
			var json = dat;
		}

		cb(null, json);
	};
	return sock;
};

SoftAP.prototype.version = function(cb) {

	is(cb);
	var sock = this.__sendCommand('version', cb);
	return sock;
};

SoftAP.prototype.securityLookup = function(dec) {

	var match = null;
	Object.keys(securityTable).forEach(function(key) {
		if(parseInt(dec) == securityTable[key]) {
			match = key;
		}
	});
	return match;
};
