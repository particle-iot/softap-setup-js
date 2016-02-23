'use strict';

var SoftAP = require('./SoftAP');
var util = require('util');
var http = require('http');

function HttpSoftAP(options) {
	SoftAP.call(this, options);
}
util.inherits(HttpSoftAP, SoftAP);

HttpSoftAP.prototype._sendProtocolCommand = function _sendProtocolCommand(cmd, cb) {
	var payload;

	if (!cmd || typeof cmd !== 'object') {
		throw new Error('Invalid command object specified.');
	}

	var opts = {
		method: 'GET',
		path: '/' + cmd.name,
		hostname: this.host,
		port: this.port,
		protocol: 'http:'
	};

	if ((cmd.body) && typeof cmd.body === 'object') {
		payload = JSON.stringify(cmd.body);
		// NOTE: 'Content-Type' is set here to make this a "simple" cross-site
		// request, as per the HTTP CORS docs:
		//   https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Simple_requests
		// According to the spec, this means that POST can be made directly
		// without an OPTIONS request being made first.
		opts.headers = {
			'Content-Length': payload.length,
			'Content-Type': 'application/x-www-form-urlencoded'
		};
		opts.method = 'POST';
	}

	var req = http.request(opts);
	req.setTimeout(this.timeout);

	var to = setTimeout(function socketTimedOut() {
		req.abort();
		cb(new Error('HTTP timed out'));
	}, this.timeout);

	req.on('response', function responseHandler(res) {
		var results = '';
		res.on('data', function dataHandler(chunk) {
			if (chunk) {
				results += chunk.toString();
			}
		});
		res.once('end', function httpEnd() {
			clearTimeout(to);

			var json;
			try {
				json = JSON.parse(results.toString());
			} catch (e) {
				return cb(new Error('Invalid JSON received from device.'));
			}
			cb(null, json);
		});
	});

	req.once('error', function httpError(err) {
		clearTimeout(to);
		cb(err);
	});

	if (payload) {
		req.write(payload);
	}
	req.end();
};

module.exports = HttpSoftAP;
