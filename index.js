'use strict';

var HttpSoftAP = require('./lib/HttpSoftAP');
var TcpSoftAP = require('./lib/TcpSoftAP');

var defaultPortMapping = {
	tcp: 5609,
	http: 80
};

function SoftAPSetup(options) {
	var opts = {
		host: '192.168.0.1',
		keepAlive: true,
		timeout: 2000,
		noDelay: true,
		channel: 6,
		protocol: 'tcp'
	};
	if (options && typeof options == 'object') {
		Object.keys(options).forEach(function _loadOpts(key) {
			opts[key] = options[key];
		});
	}

	if (!opts.port) {
		opts.port = defaultPortMapping[opts.protocol];
	}

	if (opts.protocol === 'tcp') {
		return new TcpSoftAP(opts);
	} else if (opts.protocol === 'http') {
		return new HttpSoftAP(opts);
	} else {
		throw new Error('unknown protocol');
	}
};

module.exports = SoftAPSetup;
