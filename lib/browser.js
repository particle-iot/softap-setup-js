'use strict';
const HttpSoftAP = require('./HttpSoftAP');
const TcpSoftAP = require('./TcpSoftAP');
const SoftAP = require('./SoftAP.js');

const defaultPortMapping = {
	tcp: 5609,
	http: 80
};

function SoftAPSetup(options) {
	const opts = SoftAP.defaultOptions();
	opts.protocol = 'tcp';

	SoftAP.assign(opts, options);

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
}

module.exports = SoftAPSetup;
